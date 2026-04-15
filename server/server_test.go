package server_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"testing"
	"time"

	netconf "github.com/GabrielNunesIT/netconf"
	"github.com/GabrielNunesIT/netconf/client"
	"github.com/GabrielNunesIT/netconf/server"
	"github.com/GabrielNunesIT/netconf/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── test helpers ──────────────────────────────────────────────────────────────

// testCaps is a minimal base:1.0-only capability set.
var testCaps = netconf.NewCapabilitySet([]string{netconf.BaseCap10})

// newTestPair establishes a NETCONF session pair over an in-process loopback
// and returns the client-side and server-side sessions.
func newTestPair(t *testing.T) (clientSess *netconf.Session, serverSess *netconf.Session) {
	t.Helper()

	clientT, serverT := transport.NewLoopback()
	t.Cleanup(func() {
		clientT.Close()
		serverT.Close()
	})

	type sessResult struct {
		sess *netconf.Session
		err  error
	}
	cliCh := make(chan sessResult, 1)
	srvCh := make(chan sessResult, 1)

	go func() {
		s, err := netconf.ClientSession(clientT, testCaps)
		cliCh <- sessResult{s, err}
	}()
	go func() {
		s, err := netconf.ServerSession(serverT, testCaps, 1)
		srvCh <- sessResult{s, err}
	}()

	cliRes := <-cliCh
	srvRes := <-srvCh
	require.NoError(t, cliRes.err, "ClientSession must succeed")
	require.NoError(t, srvRes.err, "ServerSession must succeed")

	return cliRes.sess, srvRes.sess
}

// sendRPC marshals and sends an RPC with the given message-id and operation body.
func sendRPC(t *testing.T, sess *netconf.Session, msgID string, opBody []byte) {
	t.Helper()
	rpc := &netconf.RPC{
		MessageID: msgID,
		Body:      opBody,
	}
	data, err := xml.Marshal(rpc)
	require.NoError(t, err, "marshal RPC")
	require.NoError(t, sess.Send(data), "send RPC")
}

// recvReply receives and unmarshals one RPCReply from sess.
func recvReply(t *testing.T, sess *netconf.Session) *netconf.RPCReply {
	t.Helper()
	raw, err := sess.Recv()
	require.NoError(t, err, "recv reply")
	var reply netconf.RPCReply
	require.NoError(t, xml.Unmarshal(raw, &reply), "unmarshal RPCReply")
	return &reply
}

// runServe starts srv.Serve in a goroutine and returns a channel that receives
// the Serve return value when it exits.
func runServe(t *testing.T, srv *server.Server, sess *netconf.Session) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(context.Background(), sess)
	}()
	return done
}

// sendCloseSession sends a close-session RPC, reads the ok reply, and waits
// for Serve to return. The loopback pipes are synchronous: Serve's Send for
// the ok reply blocks until the client reads, so we must read before waiting
// on serveDone.
func sendCloseSession(t *testing.T, clientSess *netconf.Session, serveDone chan error) {
	t.Helper()
	sendRPC(t, clientSess, "close", []byte(`<close-session xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))
	// Must read the <ok/> reply before waiting for Serve — otherwise Serve's
	// sess.Send blocks indefinitely on the synchronous pipe.
	closeReply := recvReply(t, clientSess)
	assert.NotNil(t, closeReply.Ok, "close-session reply must be <ok/>")
	select {
	case err := <-serveDone:
		require.NoError(t, err, "Serve must return nil after close-session")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after close-session")
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestServer_DispatchesToRegisteredHandler verifies that an RPC for a
// registered operation is routed to the correct handler and its body is
// returned in the reply.
func TestServer_DispatchesToRegisteredHandler(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	const responseBody = `<data><config/></data>`
	srv.RegisterHandler("get-config", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return []byte(responseBody), nil
		},
	))

	serveDone := runServe(t, srv, serverSess)

	// Client sends a get-config RPC.
	sendRPC(t, clientSess, "42", []byte(`<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><source><running/></source></get-config>`))

	reply := recvReply(t, clientSess)
	assert.Equal(t, "42", reply.MessageID, "message-id must echo back")
	assert.Contains(t, string(reply.Body), "<data>", "reply body must contain <data>")
	assert.Contains(t, string(reply.Body), "<config/>", "reply body must contain <config/>")
	assert.Nil(t, reply.Ok, "ok must not be set when body is non-nil")

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_UnknownOperation_ReturnsError verifies that an RPC for an
// unregistered operation name produces an operation-not-supported rpc-error.
func TestServer_UnknownOperation_ReturnsError(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	// No handlers registered.
	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "1", []byte(`<frobnicate xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))

	reply := recvReply(t, clientSess)
	assert.Equal(t, "1", reply.MessageID)
	assert.Nil(t, reply.Ok, "must not be ok for unknown operation")

	errs, err := netconf.ParseRPCErrors(reply)
	require.NoError(t, err, "ParseRPCErrors must succeed")
	require.Len(t, errs, 1, "exactly one rpc-error expected")
	assert.Equal(t, "operation-not-supported", errs[0].Tag)
	assert.Equal(t, "protocol", errs[0].Type)
	assert.Contains(t, errs[0].Message, "frobnicate",
		"error message must name the unrecognised operation")

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_HandlerRPCError_PropagatesAsReply verifies that a handler
// returning an RPCError produces a well-formed <rpc-error> reply with the
// same fields.
func TestServer_HandlerRPCError_PropagatesAsReply(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	handlerErr := netconf.RPCError{
		Type:     "application",
		Tag:      "invalid-value",
		Severity: "error",
		Message:  "the value 'x' is not valid",
	}
	srv.RegisterHandler("edit-config", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return nil, handlerErr
		},
	))

	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "7", []byte(`<edit-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><target><running/></target><config/></edit-config>`))

	reply := recvReply(t, clientSess)
	assert.Equal(t, "7", reply.MessageID)
	assert.Nil(t, reply.Ok, "must not be ok on error")

	errs, err := netconf.ParseRPCErrors(reply)
	require.NoError(t, err)
	require.Len(t, errs, 1)
	assert.Equal(t, "application", errs[0].Type)
	assert.Equal(t, "invalid-value", errs[0].Tag)
	assert.Equal(t, "error", errs[0].Severity)
	assert.Equal(t, "the value 'x' is not valid", errs[0].Message)

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_CloseSession_TerminatesServeLoop verifies that a <close-session>
// RPC causes Serve to return nil after sending an <ok/> reply.
func TestServer_CloseSession_TerminatesServeLoop(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "5", []byte(`<close-session xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))

	// Client must receive an <ok/> reply — read it before waiting on Serve
	// (synchronous pipe: Serve's Send blocks until client reads).
	reply := recvReply(t, clientSess)
	assert.Equal(t, "5", reply.MessageID, "message-id must echo back")
	assert.NotNil(t, reply.Ok, "close-session reply must be <ok/>")

	// Serve must return nil.
	select {
	case err := <-serveDone:
		require.NoError(t, err, "Serve must return nil after close-session")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after close-session")
	}
}

// TestServer_HandlerReturnsOk verifies that a handler returning (nil, nil)
// causes the server to send an <ok/> reply.
func TestServer_HandlerReturnsOk(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	srv.RegisterHandler("commit", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return nil, nil
		},
	))

	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "3", []byte(`<commit xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))

	reply := recvReply(t, clientSess)
	assert.Equal(t, "3", reply.MessageID)
	assert.NotNil(t, reply.Ok, "handler returning (nil, nil) must produce <ok/>")

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_HandlerNonRPCError_ProducesOperationFailed verifies that a
// handler returning a plain error produces an operation-failed rpc-error.
func TestServer_HandlerNonRPCError_ProducesOperationFailed(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	srv.RegisterHandler("get", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return nil, plainError("something went wrong internally")
		},
	))

	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "8", []byte(`<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))

	reply := recvReply(t, clientSess)
	assert.Equal(t, "8", reply.MessageID)
	assert.Nil(t, reply.Ok)

	errs, err := netconf.ParseRPCErrors(reply)
	require.NoError(t, err)
	require.Len(t, errs, 1)
	assert.Equal(t, "operation-failed", errs[0].Tag)
	assert.Equal(t, "application", errs[0].Type)
	assert.Contains(t, errs[0].Message, "something went wrong internally")

	sendCloseSession(t, clientSess, serveDone)
}

// ── observability diagnostic ──────────────────────────────────────────────────

// TestServer_UnknownOperation_ErrorMessageNamesOperation is the observability
// diagnostic check: the operation name must appear in the rpc-error message.
func TestServer_UnknownOperation_ErrorMessageNamesOperation(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := runServe(t, srv, serverSess)

	const opName = "no-such-operation"
	sendRPC(t, clientSess, "11", wrapOp(opName))

	reply := recvReply(t, clientSess)
	errs, err := netconf.ParseRPCErrors(reply)
	require.NoError(t, err)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, opName,
		"error-message must contain the unrecognised operation name %q", opName)

	sendCloseSession(t, clientSess, serveDone)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// plainError is a minimal error type for non-RPCError handler error tests.
type plainError string

func (e plainError) Error() string { return string(e) }

// wrapOp wraps an operation name as a minimal NETCONF element for use in
// sendRPC. The resulting body is `<opName xmlns="…"/>`.
func wrapOp(opName string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<`)
	buf.WriteString(opName)
	buf.WriteString(` xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`)
	return buf.Bytes()
}

// ── SendNotification tests ────────────────────────────────────────────────────

// TestSendNotification verifies that SendNotification marshals a Notification
// and delivers it over the session transport. The client side receives the raw
// bytes, unmarshals them as a netconf.Notification, and asserts the EventTime
// and Body fields match.
//
// The send runs in a goroutine because the loopback transport is synchronous:
// sess.Send blocks until the other end reads, so client Recv and server Send
// must happen concurrently.
func TestSendNotification(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	const eventTime = "2026-01-01T00:00:00Z"
	notif := &netconf.Notification{
		EventTime: eventTime,
		Body:      []byte(`<test-event/>`),
	}

	// Send from a goroutine — synchronous pipe: Send blocks until client reads.
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- server.SendNotification(serverSess, notif)
	}()

	// Receive and unmarshal on the client side.
	raw, err := clientSess.Recv()
	require.NoError(t, err, "client Recv must succeed")

	// Wait for send to complete.
	require.NoError(t, <-sendErr, "SendNotification must succeed")

	var got netconf.Notification
	require.NoError(t, xml.Unmarshal(raw, &got), "unmarshal Notification must succeed")

	assert.Equal(t, eventTime, got.EventTime, "EventTime must round-trip")
	assert.Contains(t, string(got.Body), "test-event", "Body must contain the event element")
}

// TestSendNotification_SendError verifies that SendNotification wraps transport
// errors with the expected "server: SendNotification: send:" prefix.
func TestSendNotification_SendError(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	// Close both sides so the next Send fails.
	require.NoError(t, clientSess.Close())
	require.NoError(t, serverSess.Close())

	notif := &netconf.Notification{
		EventTime: "2026-01-01T00:00:00Z",
		Body:      []byte(`<test-event/>`),
	}

	err := server.SendNotification(serverSess, notif)
	require.Error(t, err, "SendNotification must return an error when transport is closed")
	assert.Contains(t, err.Error(), "server: SendNotification: send:",
		"error must include the expected prefix")
}

// ── client↔server integration tests ──────────────────────────────────────────

// newClientServerPair establishes a NETCONF loopback session pair, wraps the
// client side in a *client.Client, and returns it together with the raw
// server-side Session.  The caller is responsible for running server.Serve on
// serverSess and for calling cli.Close() when done.
//
// Concurrently establishing both sessions is required because the loopback
// io.Pipe is synchronous and each side must send its hello before the other
// can complete the hello exchange.
func newClientServerPair(t *testing.T) (cli *client.Client, serverSess *netconf.Session) {
	t.Helper()

	clientT, serverT := transport.NewLoopback()
	t.Cleanup(func() {
		clientT.Close()
		serverT.Close()
	})

	type sessResult struct {
		sess *netconf.Session
		err  error
	}
	cliCh := make(chan sessResult, 1)
	srvCh := make(chan sessResult, 1)

	go func() {
		s, err := netconf.ClientSession(clientT, testCaps)
		cliCh <- sessResult{s, err}
	}()
	go func() {
		s, err := netconf.ServerSession(serverT, testCaps, 1)
		srvCh <- sessResult{s, err}
	}()

	cliRes := <-cliCh
	srvRes := <-srvCh
	require.NoError(t, cliRes.err, "ClientSession must succeed")
	require.NoError(t, srvRes.err, "ServerSession must succeed")

	// NewClient starts the background recvLoop goroutine which drains replies
	// automatically — no loopback deadlock risk for the client side.
	cli = client.NewClient(cliRes.sess)
	return cli, srvRes.sess
}

// TestServer_WithClient is the integration closure for R005: typed
// client.Client methods drive real NETCONF RPCs against a Server with mock
// handlers over an in-process loopback transport.
//
// Sequence:
//  1. GetConfig → handler returns <data><config/></data> body → DataReply non-nil
//  2. EditConfig → handler returns (nil, nil) → ok reply → no error
//  3. CloseSession → server built-in intercepts → <ok/> → Serve returns nil
func TestServer_WithClient(t *testing.T) {
	t.Parallel()
	cli, serverSess := newClientServerPair(t)

	srv := server.NewServer()

	// get-config handler: returns a minimal <data> body.
	const getConfigBody = `<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><config/></data>`
	srv.RegisterHandler("get-config", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return []byte(getConfigBody), nil
		},
	))

	// edit-config handler: returns (nil, nil) → <ok/> reply.
	srv.RegisterHandler("edit-config", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return nil, nil
		},
	))

	// Serve runs in a goroutine; we collect its return value.
	ctx := context.Background()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(ctx, serverSess)
	}()

	// 1. GetConfig — DataReply must be non-nil and contain <config/>.
	running := netconf.Datastore{Running: &struct{}{}}
	dr, err := cli.GetConfig(ctx, running, nil)
	require.NoError(t, err, "GetConfig must succeed")
	require.NotNil(t, dr, "GetConfig must return a DataReply")
	assert.Contains(t, string(dr.Content), "config",
		"DataReply content must include the handler-supplied config element")

	// 2. EditConfig — plain <ok/> expected.
	editCfg := netconf.EditConfig{
		Target: netconf.Datastore{Running: &struct{}{}},
		Config: []byte(`<config/>`),
	}
	require.NoError(t, cli.EditConfig(ctx, editCfg), "EditConfig must succeed")

	// 3. CloseSession — built-in intercept sends <ok/>, Serve returns nil.
	// client.Client's recvLoop drains the reply, so no manual read is needed
	// before waiting on serveDone.
	require.NoError(t, cli.CloseSession(ctx), "CloseSession must succeed")

	select {
	case err := <-serveDone:
		assert.NoError(t, err, "Serve must return nil after CloseSession")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after CloseSession")
	}

	// Close the client — this shuts down the recvLoop goroutine cleanly.
	_ = cli.Close()
}

// TestServer_WithClient_RPCError proves the full error propagation chain:
// server handler → RPCError → marshal → transport → client dispatcher →
// ParseRPCErrors → checkDataReply → errors.As.
//
// A handler registered for "get-config" returns an RPCError.  The typed
// client method GetConfig must surface it as a netconf.RPCError that
// errors.As can extract with matching fields.
func TestServer_WithClient_RPCError(t *testing.T) {
	t.Parallel()
	cli, serverSess := newClientServerPair(t)

	srv := server.NewServer()

	// get-config handler that returns an application-layer RPCError.
	handlerErr := netconf.RPCError{
		Type:     "application",
		Tag:      "invalid-value",
		Severity: "error",
		Message:  "test error from server",
	}
	srv.RegisterHandler("get-config", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return nil, handlerErr
		},
	))

	ctx := context.Background()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(ctx, serverSess)
	}()

	running := netconf.Datastore{Running: &struct{}{}}
	_, err := cli.GetConfig(ctx, running, nil)
	require.Error(t, err, "GetConfig must return an error when the handler fails")

	// errors.As must be able to extract the structured RPCError.
	var rpcErr netconf.RPCError
	require.True(t, errors.As(err, &rpcErr),
		"error must be (or wrap) a netconf.RPCError; got: %v", err)
	assert.Equal(t, "application", rpcErr.Type)
	assert.Equal(t, "invalid-value", rpcErr.Tag)
	assert.Equal(t, "error", rpcErr.Severity)
	assert.Equal(t, "test error from server", rpcErr.Message)

	// Terminate the server cleanly so the test goroutine exits.
	require.NoError(t, cli.CloseSession(ctx), "CloseSession must succeed after error reply")
	select {
	case err := <-serveDone:
		assert.NoError(t, err, "Serve must return nil after CloseSession")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after CloseSession")
	}
	_ = cli.Close()
}

// TestServer_ContextCancel proves that cancelling the context passed to
// server.Serve causes Serve to return promptly.
func TestServer_ContextCancel(t *testing.T) {
	t.Parallel()
	cli, serverSess := newClientServerPair(t)

	srv := server.NewServer()

	ctx, cancel := context.WithCancel(context.Background())

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(ctx, serverSess)
	}()

	// Cancel the context. Serve should close the session transport internally
	// to unblock any in-flight receive.
	cancel()

	select {
	case err := <-serveDone:
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}

	_ = cli.Close()
}

// ── StreamHandler tests ───────────────────────────────────────────────────────

// echoStreamHandler implements both Handler and StreamHandler.
// HandleStream decodes the operation element via DecodeElement and
// captures the inner bytes for test assertions.
type echoStreamHandler struct {
	decodedOp chan []byte
	replyBody []byte
}

func (h *echoStreamHandler) Handle(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
	return h.replyBody, nil
}

func (h *echoStreamHandler) HandleStream(_ context.Context, _ *netconf.Session, _ *netconf.RPC, dec *xml.Decoder, opStart xml.StartElement) ([]byte, error) {
	type opCapture struct {
		Inner []byte `xml:",innerxml"`
	}
	var cap opCapture
	if err := dec.DecodeElement(&cap, &opStart); err != nil {
		return nil, err
	}
	select {
	case h.decodedOp <- cap.Inner:
	default:
	}
	return h.replyBody, nil
}

// skipStreamHandler implements StreamHandler using dec.Skip() — the zero-copy
// path for handlers that don't need the op body.
type skipStreamHandler struct {
	called chan struct{}
	reply  []byte
}

func (h *skipStreamHandler) Handle(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
	return h.reply, nil
}

func (h *skipStreamHandler) HandleStream(_ context.Context, _ *netconf.Session, _ *netconf.RPC, dec *xml.Decoder, opStart xml.StartElement) ([]byte, error) {
	if err := dec.Skip(); err != nil {
		return nil, err
	}
	select {
	case h.called <- struct{}{}:
	default:
	}
	return h.reply, nil
}

// TestServer_StreamHandler_DecodeElement proves that a handler implementing
// StreamHandler receives the decoder positioned at the operation start element
// and can decode the body via DecodeElement. The rpc.Body field is nil (no
// materialisation); the reply body is returned unchanged.
func TestServer_StreamHandler_DecodeElement(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	const replyBody = `<data><ok/></data>`
	h := &echoStreamHandler{
		decodedOp: make(chan []byte, 1),
		replyBody: []byte(replyBody),
	}

	srv := server.NewServer()
	srv.RegisterHandler("get-config", h)
	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "10", []byte(`<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><source><running/></source></get-config>`))

	reply := recvReply(t, clientSess)
	assert.Equal(t, "10", reply.MessageID, "message-id must echo back")
	assert.Contains(t, string(reply.Body), replyBody, "reply body must be the handler-supplied body")
	assert.Nil(t, reply.Ok, "ok must not be set when body is provided")

	// HandleStream must have captured the inner content of <get-config>.
	select {
	case inner := <-h.decodedOp:
		assert.Contains(t, string(inner), "running",
			"decoded op inner must contain the <source><running/></source> content")
	default:
		t.Fatal("HandleStream was not called — handler was not dispatched via StreamHandler interface")
	}

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_StreamHandler_Skip proves that a StreamHandler that calls
// dec.Skip() (the zero-copy path) works correctly and does not corrupt
// subsequent messages on the same session.
func TestServer_StreamHandler_Skip(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	const replyBody = `<data><skipped/></data>`
	h := &skipStreamHandler{
		called: make(chan struct{}, 1),
		reply:  []byte(replyBody),
	}

	srv := server.NewServer()
	srv.RegisterHandler("get-config", h)
	srv.RegisterHandler("lock", server.HandlerFunc(func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
		return nil, nil
	}))
	serveDone := runServe(t, srv, serverSess)

	// First RPC — handled via StreamHandler + dec.Skip().
	sendRPC(t, clientSess, "11", []byte(`<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><source><running/></source></get-config>`))
	reply := recvReply(t, clientSess)
	assert.Equal(t, "11", reply.MessageID)
	assert.Contains(t, string(reply.Body), "skipped", "reply must contain handler body")

	select {
	case <-h.called:
		// HandleStream + dec.Skip was invoked.
	default:
		t.Fatal("HandleStream with dec.Skip was not called")
	}

	// Second RPC — proves the session is not corrupted after Skip.
	sendRPC(t, clientSess, "12", []byte(`<lock xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><target><running/></target></lock>`))
	reply2 := recvReply(t, clientSess)
	assert.Equal(t, "12", reply2.MessageID, "second RPC after Skip must be dispatched correctly")
	assert.NotNil(t, reply2.Ok, "lock reply must be ok")

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_StreamHandler_MessageID proves that the message-id extracted by
// parseRPCHeader is correctly echoed in the reply for a StreamHandler dispatch.
func TestServer_StreamHandler_MessageID(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	h := &skipStreamHandler{called: make(chan struct{}, 1), reply: []byte(`<data/>`)}
	srv := server.NewServer()
	srv.RegisterHandler("get-config", h)
	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "msg-99", []byte(`<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><source><running/></source></get-config>`))
	reply := recvReply(t, clientSess)
	assert.Equal(t, "msg-99", reply.MessageID,
		"parseRPCHeader must extract the correct message-id for StreamHandler dispatch")

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_StreamHandler_FallsBackToHandler proves that a plain Handler
// (not implementing StreamHandler) still receives a populated rpc.Body after
// the Serve() streaming refactor. marshalOpElement must reconstruct the full
// operation element including namespace.
func TestServer_StreamHandler_FallsBackToHandler(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	var capturedBody []byte
	srv := server.NewServer()
	srv.RegisterHandler("get-config", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, rpc *netconf.RPC) ([]byte, error) {
			capturedBody = append([]byte{}, rpc.Body...)
			return []byte(`<data><config/></data>`), nil
		},
	))
	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "20", []byte(`<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><source><running/></source></get-config>`))
	reply := recvReply(t, clientSess)
	assert.Equal(t, "20", reply.MessageID)
	assert.Contains(t, string(reply.Body), "<config/>")

	// rpc.Body must be populated by marshalOpElement — full element with namespace.
	require.NotEmpty(t, capturedBody, "conventional Handler must receive non-empty rpc.Body")
	assert.Contains(t, string(capturedBody), "get-config",
		"rpc.Body must contain the reconstructed operation element name")
	assert.Contains(t, string(capturedBody), "running",
		"rpc.Body must contain the operation body content")
	assert.Contains(t, string(capturedBody), "urn:ietf:params:xml:ns:netconf:base:1.0",
		"rpc.Body must carry the NETCONF namespace from the operation element")

	sendCloseSession(t, clientSess, serveDone)
}

// ── additional coverage tests ─────────────────────────────────────────────────

// TestServer_ContextCancellation creates a session pair, starts Serve with a
// cancellable context, cancels the context and verifies Serve returns an error
// containing "context".
func TestServer_ContextCancellation(t *testing.T) {
	t.Parallel()
	_, serverSess := newTestPair(t)

	srv := server.NewServer()
	ctx, cancel := context.WithCancel(context.Background())

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(ctx, serverSess)
	}()

	cancel()

	select {
	case err := <-serveDone:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

// TestServer_MalformedRPC_SkippedSilently sends a message that is NOT a valid
// RPC (<not-an-rpc/> without message-id). The server should skip it and
// continue. A subsequent close-session proves Serve continues and returns nil.
func TestServer_MalformedRPC_SkippedSilently(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := runServe(t, srv, serverSess)

	// Not a valid RPC — missing message-id, skipped by parseRPCHeader.
	require.NoError(t, clientSess.Send([]byte(`<not-an-rpc/>`)))

	// Serve should continue after skipping the malformed message.
	sendCloseSession(t, clientSess, serveDone)
}

// streamHandlerFunc implements both Handler and StreamHandler via a function.
type streamHandlerFunc struct {
	fn func(ctx context.Context, sess *netconf.Session, rpc *netconf.RPC, dec *xml.Decoder, opStart xml.StartElement) ([]byte, error)
}

func (s *streamHandlerFunc) Handle(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
	return nil, errors.New("should not be called")
}

func (s *streamHandlerFunc) HandleStream(ctx context.Context, sess *netconf.Session, rpc *netconf.RPC, dec *xml.Decoder, opStart xml.StartElement) ([]byte, error) {
	return s.fn(ctx, sess, rpc, dec, opStart)
}

// TestServer_StreamHandler registers a handler that implements StreamHandler.
// Verifies that HandleStream (not Handle) is called with the decoder positioned
// at the operation start element.
func TestServer_StreamHandler(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	const replyBody = `<data><result/></data>`
	h := &streamHandlerFunc{
		fn: func(_ context.Context, _ *netconf.Session, _ *netconf.RPC, dec *xml.Decoder, opStart xml.StartElement) ([]byte, error) {
			type opCapture struct {
				Inner []byte `xml:",innerxml"`
			}
			var cap opCapture
			if err := dec.DecodeElement(&cap, &opStart); err != nil {
				return nil, err
			}
			return []byte(replyBody), nil
		},
	}

	srv := server.NewServer()
	srv.RegisterHandler("get", h)
	serveDone := runServe(t, srv, serverSess)

	sendRPC(t, clientSess, "50", []byte(`<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><filter/></get>`))

	reply := recvReply(t, clientSess)
	assert.Equal(t, "50", reply.MessageID)
	assert.Contains(t, string(reply.Body), replyBody)

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_RPCMissingMessageID sends <rpc><get/></rpc> (missing message-id
// attribute). The server should skip it and continue.
func TestServer_RPCMissingMessageID(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := runServe(t, srv, serverSess)

	// <rpc> without message-id — parseRPCHeader returns !ok.
	require.NoError(t, clientSess.Send([]byte(`<rpc><get/></rpc>`)))

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_RPCNoOperationElement sends <rpc message-id="1"></rpc> (message-id
// present but no child operation element). The server should skip it.
func TestServer_RPCNoOperationElement(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := runServe(t, srv, serverSess)

	// message-id present but no child element — child loop hits EOF.
	require.NoError(t, clientSess.Send([]byte(`<rpc message-id="1"></rpc>`)))

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_EmptyMessage_SkippedSilently sends a whitespace-only message.
// The XML decoder's first Token call returns CharData, then EOF on the second
// call, triggering the parseRPCHeader error path for the initial token loop.
func TestServer_EmptyMessage_SkippedSilently(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := runServe(t, srv, serverSess)

	// Whitespace-only message — Token returns CharData then EOF.
	require.NoError(t, clientSess.Send([]byte(`   `)))

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_MarshalOpElementError sends a message with a valid RPC header but
// a truncated operation body so that marshalOpElement's DecodeElement fails.
// The server should skip the malformed body and continue.
func TestServer_MarshalOpElementError(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	// Register a plain Handler (not StreamHandler) so the marshalOpElement
	// code path is taken.
	srv.RegisterHandler("get", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			return nil, nil
		},
	))
	serveDone := runServe(t, srv, serverSess)

	// Truncated body: <get> has no closing tag → DecodeElement fails.
	require.NoError(t, clientSess.Send([]byte(`<rpc message-id="1"><get>`)))

	sendCloseSession(t, clientSess, serveDone)
}

// TestServer_SendReplyError verifies that Serve returns an error when
// sendReply fails because the handler closed the transport.
func TestServer_SendReplyError(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	srv.RegisterHandler("get", server.HandlerFunc(
		func(_ context.Context, _ *netconf.Session, _ *netconf.RPC) ([]byte, error) {
			// Close the server transport so the subsequent sendReply fails.
			serverSess.Close()
			return []byte(`<data/>`), nil
		},
	))

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(context.Background(), serverSess)
	}()

	sendRPC(t, clientSess, "1", []byte(`<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))

	select {
	case err := <-serveDone:
		require.Error(t, err, "Serve must return an error when sendReply fails")
		assert.Contains(t, err.Error(), "send reply")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestServer_RecvError verifies that Serve returns a recv error (not context)
// when the transport is closed externally.
func TestServer_RecvError(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(context.Background(), serverSess)
	}()

	// Close the client transport — server recv fails with a pipe error.
	require.NoError(t, clientSess.Close())

	select {
	case err := <-serveDone:
		require.Error(t, err, "Serve must return an error on transport failure")
		assert.Contains(t, err.Error(), "recv")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestServer_CloseSession_SendReplyError verifies that Serve returns an error
// when the ok reply for close-session cannot be sent because the client
// transport was closed.
func TestServer_CloseSession_SendReplyError(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(context.Background(), serverSess)
	}()

	// Send close-session. sendRPC blocks until server reads the message.
	sendRPC(t, clientSess, "close", []byte(`<close-session xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))

	// Close the client transport immediately. The server's reply write to
	// serverW blocks (synchronous pipe) or fails because clientR is closed.
	require.NoError(t, clientSess.Close())

	select {
	case err := <-serveDone:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send close-session reply")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestServer_OperationNotSupported_SendReplyError verifies that Serve returns
// an error when the operation-not-supported reply cannot be sent because the
// client transport was closed.
func TestServer_OperationNotSupported_SendReplyError(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := newTestPair(t)

	srv := server.NewServer()
	// No handlers registered → any operation gets operation-not-supported.
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(context.Background(), serverSess)
	}()

	// Send an unknown operation. sendRPC blocks until server reads.
	sendRPC(t, clientSess, "1", []byte(`<frobnicate xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`))

	// Close client transport — server's error reply send will fail.
	require.NoError(t, clientSess.Close())

	select {
	case err := <-serveDone:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
}
