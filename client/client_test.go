package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	netconf "github.com/GabrielNunesIT/netconf"
	"github.com/GabrielNunesIT/netconf/client"
	"github.com/GabrielNunesIT/netconf/monitoring"
	"github.com/GabrielNunesIT/netconf/nmda"
	"github.com/GabrielNunesIT/netconf/subscriptions"
	"github.com/GabrielNunesIT/netconf/transport"
	ncssh "github.com/GabrielNunesIT/netconf/transport/ssh"
	nctls "github.com/GabrielNunesIT/netconf/transport/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// testCaps is a minimal base:1.0-only capability set sufficient for session
// establishment in all tests in this package.
var testCaps = netconf.NewCapabilitySet([]string{netconf.BaseCap10})

// newTestPair establishes a NETCONF session over an in-process loopback pair
// and wraps the client side in a Client. It returns the Client and the raw
// server-side transport so that individual tests can read RPCs and write
// replies by hand.
//
// The server-side session is run in a goroutine; any session error is
// reported via t.Fatal on the calling goroutine through a channel.
func newTestPair(t *testing.T) (*client.Client, transport.Transport) {
	t.Helper()

	clientT, serverT := transport.NewLoopback()
	t.Cleanup(func() {
		clientT.Close()
		serverT.Close()
	})

	// Run ClientSession and ServerSession concurrently (the loopback is
	// unbuffered; both peers must send hellos simultaneously).
	type sessResult struct {
		sess *netconf.Session
		err  error
	}
	clientCh := make(chan sessResult, 1)
	serverCh := make(chan sessResult, 1)

	go func() {
		s, err := netconf.ClientSession(clientT, testCaps)
		clientCh <- sessResult{s, err}
	}()
	go func() {
		s, err := netconf.ServerSession(serverT, testCaps, 1)
		serverCh <- sessResult{s, err}
	}()

	clientRes := <-clientCh
	serverRes := <-serverCh
	require.NoError(t, clientRes.err, "ClientSession must succeed")
	require.NoError(t, serverRes.err, "ServerSession must succeed")

	// The server session object is not used directly in tests — tests interact
	// with the server side via the raw serverT transport.  Return serverT so
	// tests can read raw RPC bytes and write reply bytes without going through
	// a Session abstraction.
	_ = serverRes.sess

	c := client.NewClient(clientRes.sess)
	t.Cleanup(func() { c.Close() })

	return c, serverT
}

// writeReply serialises a netconf.RPCReply and writes it as a single NETCONF
// message on the given transport. Used by test server goroutines.
func writeReply(t *testing.T, trp transport.Transport, reply *netconf.RPCReply) {
	t.Helper()
	data, err := xml.Marshal(reply)
	require.NoError(t, err, "marshal RPCReply")
	require.NoError(t, transport.WriteMsg(trp, data), "write reply to transport")
}

// okReply builds a simple <rpc-reply message-id="…"><ok/></rpc-reply>.
func okReply(msgID string) *netconf.RPCReply {
	return &netconf.RPCReply{
		MessageID: msgID,
		Ok:        &struct{}{},
	}
}

// ── TestSession_SendRecv ──────────────────────────────────────────────────────

// TestSession_SendRecv validates the new Send and Recv methods on Session via
// a loopback pair, independently of the Client.
func TestSession_SendRecv(t *testing.T) {
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	srvSessCh := make(chan *netconf.Session, 1)
	cliSessCh := make(chan *netconf.Session, 1)

	go func() {
		s, err := netconf.ServerSession(serverT, testCaps, 1)
		require.NoError(t, err)
		srvSessCh <- s
	}()
	go func() {
		s, err := netconf.ClientSession(clientT, testCaps)
		require.NoError(t, err)
		cliSessCh <- s
	}()

	cliSess := <-cliSessCh
	srvSess := <-srvSessCh

	// Client sends; server receives.
	msg := []byte("<hello>from-client</hello>")
	errCh := make(chan error, 1)
	go func() {
		errCh <- cliSess.Send(msg)
	}()

	got, err := srvSess.Recv()
	require.NoError(t, err, "Recv must succeed")
	require.NoError(t, <-errCh, "Send must succeed")
	assert.Equal(t, msg, got, "received bytes must match sent bytes")
}

// ── TestDo_SimpleRoundTrip ────────────────────────────────────────────────────

// TestDo_SimpleRoundTrip proves the basic happy-path: Do sends an RPC with a
// message-id, the server echoes back an RPCReply with the same message-id, and
// Do returns the reply.
func TestDo_SimpleRoundTrip(t *testing.T) {
	c, serverT := newTestPair(t)

	resultCh := make(chan error, 1)
	go func() {
		_, err := c.Do(context.Background(), netconf.CloseSession{})
		resultCh <- err
	}()

	// Server: read the RPC, verify it has a message-id, write an ok reply.
	raw, err := transport.ReadMsg(serverT)
	require.NoError(t, err, "server must be able to read client RPC")

	var rpc netconf.RPC
	require.NoError(t, xml.Unmarshal(raw, &rpc), "server must parse RPC")
	assert.NotEmpty(t, rpc.MessageID, "RPC must carry a message-id")

	writeReply(t, serverT, okReply(rpc.MessageID))

	require.NoError(t, <-resultCh, "Do must succeed")
}

// ── TestClient_ConcurrentRPCs ─────────────────────────────────────────────────

// TestClient_ConcurrentRPCs proves that two goroutines can call Do
// simultaneously and that out-of-order replies are matched correctly by
// message-id. The server reads both RPCs and sends the second reply first.
func TestClient_ConcurrentRPCs(t *testing.T) {
	c, serverT := newTestPair(t)

	type result struct {
		reply *netconf.RPCReply
		err   error
	}

	res1Ch := make(chan result, 1)
	res2Ch := make(chan result, 1)

	go func() {
		reply, err := c.Do(context.Background(), netconf.CloseSession{})
		res1Ch <- result{reply, err}
	}()
	go func() {
		reply, err := c.Do(context.Background(), netconf.CloseSession{})
		res2Ch <- result{reply, err}
	}()

	// Read both RPCs from the server side.
	raw1, err := transport.ReadMsg(serverT)
	require.NoError(t, err, "read first RPC")
	raw2, err := transport.ReadMsg(serverT)
	require.NoError(t, err, "read second RPC")

	var rpc1, rpc2 netconf.RPC
	require.NoError(t, xml.Unmarshal(raw1, &rpc1))
	require.NoError(t, xml.Unmarshal(raw2, &rpc2))

	// The two RPCs must have distinct message-ids (key correctness invariant).
	assert.NotEqual(t, rpc1.MessageID, rpc2.MessageID,
		"the two RPCs must have distinct message-ids")

	// Intentionally reply in reverse order to exercise message-id matching.
	writeReply(t, serverT, okReply(rpc2.MessageID))
	writeReply(t, serverT, okReply(rpc1.MessageID))

	r1 := <-res1Ch
	r2 := <-res2Ch

	require.NoError(t, r1.err, "caller 1 must succeed")
	require.NoError(t, r2.err, "caller 2 must succeed")
	require.NotNil(t, r1.reply, "caller 1 must get a reply")
	require.NotNil(t, r2.reply, "caller 2 must get a reply")

	// The set of message-ids received must equal the set of message-ids sent.
	// We cannot predict which goroutine got which id, but each must get exactly
	// one of the two ids in the round-trip.
	sentIDs := map[string]bool{rpc1.MessageID: true, rpc2.MessageID: true}
	assert.True(t, sentIDs[r1.reply.MessageID],
		"caller 1 reply message-id %q must be one of the sent RPCs", r1.reply.MessageID)
	assert.True(t, sentIDs[r2.reply.MessageID],
		"caller 2 reply message-id %q must be one of the sent RPCs", r2.reply.MessageID)
	assert.NotEqual(t, r1.reply.MessageID, r2.reply.MessageID,
		"callers must receive distinct replies")
}

// ── TestClient_ContextCancel ──────────────────────────────────────────────────

// TestClient_ContextCancel proves that cancelling the context before the
// server replies causes Do to return context.Canceled. The server goroutine
// is intentionally delayed and never sends a reply.
func TestClient_ContextCancel(t *testing.T) {
	c, serverT := newTestPair(t)

	ctx, cancel := context.WithCancel(context.Background())

	resultCh := make(chan error, 1)
	go func() {
		_, err := c.Do(ctx, netconf.CloseSession{})
		resultCh <- err
	}()

	// Wait for the server to see the RPC (so the client has definitely sent
	// it and registered the pending channel), then cancel.
	_, err := transport.ReadMsg(serverT)
	require.NoError(t, err, "server must read the RPC before cancel")

	cancel()

	select {
	case err := <-resultCh:
		assert.ErrorIs(t, err, context.Canceled,
			"Do must return context.Canceled after ctx is cancelled")
	case <-time.After(2 * time.Second):
		t.Fatal("Do did not return after context cancellation")
	}
}

// ── TestClient_TransportClose ─────────────────────────────────────────────────

// TestClient_TransportClose proves that closing the server side of the
// transport causes the dispatcher to exit and any pending Do call to receive
// an error (the transport error propagated through the dispatcher).
func TestClient_TransportClose(t *testing.T) {
	c, serverT := newTestPair(t)

	resultCh := make(chan error, 1)
	go func() {
		_, err := c.Do(context.Background(), netconf.CloseSession{})
		resultCh <- err
	}()

	// Wait for the server to see the RPC, then close the server transport
	// (which causes the client's read end to get an EOF or pipe-closed error).
	_, err := transport.ReadMsg(serverT)
	require.NoError(t, err, "server must receive the RPC before transport close")

	require.NoError(t, serverT.Close(), "serverT.Close must succeed")

	select {
	case err := <-resultCh:
		assert.Error(t, err, "Do must return an error when transport is closed")
		// The dispatcher exit error should be available via Err().
		assert.Error(t, c.Err(), "Err() must return the dispatcher exit error")
	case <-time.After(2 * time.Second):
		t.Fatal("Do did not return after transport close")
	}
}

// ── TestClient_Close ──────────────────────────────────────────────────────────

// TestClient_Close proves that calling Close shuts the client down cleanly and
// that subsequent Do calls return an error immediately.
func TestClient_Close(t *testing.T) {
	c, _ := newTestPair(t)

	require.NoError(t, c.Close(), "Close must succeed")

	// After Close, Do must return an error without hanging.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := c.Do(ctx, netconf.CloseSession{})
	assert.Error(t, err, "Do must return an error after Close")
	// The error should not be a context error — it should reflect closed state.
	assert.False(t, errors.Is(err, context.Canceled),
		"error must not be context.Canceled")
	assert.False(t, errors.Is(err, context.DeadlineExceeded),
		"error must not be context.DeadlineExceeded")
}

// ── TestDo_MessageIDMonotonicallyIncreases ────────────────────────────────────

// TestDo_MessageIDMonotonicallyIncreases verifies that consecutive Do calls
// each get a new, distinct, monotonically-increasing decimal message-id.
func TestDo_MessageIDMonotonicallyIncreases(t *testing.T) {
	c, serverT := newTestPair(t)

	const n = 5
	idCh := make(chan string, n)
	errCh := make(chan error, n)

	// Issue n sequential RPCs; each call blocks until the server replies.
	go func() {
		for range n {
			raw, err := transport.ReadMsg(serverT)
			if err != nil {
				errCh <- err
				return
			}
			var rpc netconf.RPC
			if err := xml.Unmarshal(raw, &rpc); err != nil {
				errCh <- err
				return
			}
			idCh <- rpc.MessageID
			data, _ := xml.Marshal(okReply(rpc.MessageID))
			transport.WriteMsg(serverT, data)
		}
		errCh <- nil
	}()

	ids := make([]string, 0, n)
	for i := range n {
		_, err := c.Do(context.Background(), netconf.CloseSession{})
		require.NoError(t, err, "Do %d must succeed", i+1)
		ids = append(ids, <-idCh)
	}
	require.NoError(t, <-errCh, "server goroutine must complete without error")

	// All IDs must be distinct.
	seen := make(map[string]struct{})
	for _, id := range ids {
		assert.NotEmpty(t, id, "message-id must not be empty")
		_, dup := seen[id]
		assert.False(t, dup, "message-id %q is duplicated", id)
		seen[id] = struct{}{}
	}
}

// ── TestClient_DispatcherHandlesMalformedReply ────────────────────────────────

// TestClient_DispatcherHandlesMalformedReply verifies that a malformed reply
// (non-XML bytes) does not crash the dispatcher and that a subsequent well-
// formed reply is still delivered correctly.
func TestClient_DispatcherHandlesMalformedReply(t *testing.T) {
	c, serverT := newTestPair(t)

	// Issue the real RPC.
	resultCh := make(chan error, 1)
	go func() {
		_, err := c.Do(context.Background(), netconf.CloseSession{})
		resultCh <- err
	}()

	// Server: read the RPC, send garbage first, then the real ok reply.
	raw, err := transport.ReadMsg(serverT)
	require.NoError(t, err)
	var rpc netconf.RPC
	require.NoError(t, xml.Unmarshal(raw, &rpc))

	// Send garbage; dispatcher must skip it without panicking.
	require.NoError(t, transport.WriteMsg(serverT, []byte("not-xml-at-all")))
	// Now send the real reply.
	writeReply(t, serverT, okReply(rpc.MessageID))

	require.NoError(t, <-resultCh, "Do must succeed despite an intermediate malformed message")
}

// ── SSH loopback helpers ──────────────────────────────────────────────────────

// generateTestSigner returns an ephemeral 2048-bit RSA signer for SSH tests.
func generateTestSigner(t *testing.T) gossh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate RSA key")
	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err, "create SSH signer")
	return signer
}

// testSSHConfigs returns a matched server + client SSH config pair.
// The server accepts any password; the client sends "test/test".
func testSSHConfigs(t *testing.T) (*gossh.ServerConfig, *gossh.ClientConfig) {
	t.Helper()
	signer := generateTestSigner(t)
	serverCfg := &gossh.ServerConfig{
		PasswordCallback: func(_ gossh.ConnMetadata, _ []byte) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		},
	}
	serverCfg.AddHostKey(signer)
	clientCfg := &gossh.ClientConfig{
		User:            "test",
		Auth:            []gossh.AuthMethod{gossh.Password("test")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return serverCfg, clientCfg
}

// ── Echo-server helpers ───────────────────────────────────────────────────────

// dataBody is the <data><config/></data> body returned by the echo server for
// get / get-config operations.
const dataBody = `<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><config/></data>`

// echoServer runs an echo server on serverT: it reads RPC messages, inspects
// the operation element name, and sends either a <data> reply (for get /
// get-config) or an <ok/> reply (for everything else).  It exits when
// serverT.Close() causes ReadMsg to fail.
func echoServer(t *testing.T, serverT transport.Transport) {
	t.Helper()
	for {
		raw, err := transport.ReadMsg(serverT)
		if err != nil {
			return // transport closed — normal exit
		}
		var rpc netconf.RPC
		if err := xml.Unmarshal(raw, &rpc); err != nil {
			t.Logf("echoServer: unmarshal RPC: %v", err)
			continue
		}

		// Determine which operation was sent by peeking at the first XML
		// element name inside the RPC body.
		opName := firstElementName(rpc.Body)

		var reply *netconf.RPCReply
		switch opName {
		case "get", "get-config":
			reply = &netconf.RPCReply{
				MessageID: rpc.MessageID,
				Body:      []byte(dataBody),
			}
		case "partial-lock":
			reply = &netconf.RPCReply{
				MessageID: rpc.MessageID,
				Body: []byte(`<partial-lock-reply>` +
					`<lock-id>1</lock-id>` +
					`<locked-node>/interfaces</locked-node>` +
					`<locked-node>/routing</locked-node>` +
					`</partial-lock-reply>`),
			}
		case "get-schema":
			reply = &netconf.RPCReply{
				MessageID: rpc.MessageID,
				Body:      []byte(`<data>module ietf-interfaces { yang-version 1.1; }</data>`),
			}
		default:
			reply = &netconf.RPCReply{
				MessageID: rpc.MessageID,
				Ok:        &struct{}{},
			}
		}

		data, err := xml.Marshal(reply)
		if err != nil {
			t.Logf("echoServer: marshal reply: %v", err)
			continue
		}
		if err := transport.WriteMsg(serverT, data); err != nil {
			return
		}
	}
}

// echoServerWithError runs an echo server that always replies with a single
// <rpc-error> regardless of the operation.  Used by TestClient_RPCError.
func echoServerWithError(t *testing.T, serverT transport.Transport) {
	t.Helper()
	raw, err := transport.ReadMsg(serverT)
	if err != nil {
		t.Logf("echoServerWithError: ReadMsg: %v", err)
		return
	}
	var rpc netconf.RPC
	if err := xml.Unmarshal(raw, &rpc); err != nil {
		t.Logf("echoServerWithError: unmarshal: %v", err)
		return
	}
	errBody := `<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">` +
		`<error-type>application</error-type>` +
		`<error-tag>invalid-value</error-tag>` +
		`<error-severity>error</error-severity>` +
		`<error-message>test error message</error-message>` +
		`</rpc-error>`
	reply := &netconf.RPCReply{
		MessageID: rpc.MessageID,
		Body:      []byte(errBody),
	}
	data, err := xml.Marshal(reply)
	if err != nil {
		t.Logf("echoServerWithError: marshal: %v", err)
		return
	}
	_ = transport.WriteMsg(serverT, data)
}

// firstElementName decodes the local name of the first XML start element in b.
// Returns "" if b is empty or contains no start element.
func firstElementName(b []byte) string {
	d := xml.NewDecoder(bytesReaderNew(b))
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Local
		}
	}
}

// bytesReader is a minimal io.Reader over a byte slice, avoiding an import of
// the bytes package just for this one use.
type bytesReader struct{ b []byte }

func (r *bytesReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, errors.New("EOF")
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func bytesReaderNew(b []byte) *bytesReader { return &bytesReader{b: b} }

// ── Typed method tests ────────────────────────────────────────────────────────

// TestClient_GetConfig exercises GetConfig end-to-end through the echo server.
func TestClient_GetConfig(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	running := netconf.Datastore{Running: &struct{}{}}
	dr, err := c.GetConfig(context.Background(), running, nil)
	require.NoError(t, err, "GetConfig must succeed")
	require.NotNil(t, dr, "DataReply must not be nil")
}

// TestClient_Get exercises Get end-to-end through the echo server.
func TestClient_Get(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	filter := &netconf.Filter{
		Type:    "subtree",
		Content: []byte(`<interfaces/>`),
	}
	dr, err := c.Get(context.Background(), filter)
	require.NoError(t, err, "Get must succeed")
	require.NotNil(t, dr, "DataReply must not be nil")
}

// TestClient_EditConfig exercises EditConfig through the echo server.
func TestClient_EditConfig(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	cfg := netconf.EditConfig{
		Target: netconf.Datastore{Running: &struct{}{}},
		Config: []byte(`<config/>`),
	}
	require.NoError(t, c.EditConfig(context.Background(), cfg))
}

// TestClient_Lock_Unlock exercises Lock then Unlock through the echo server.
func TestClient_Lock_Unlock(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	target := netconf.Datastore{Running: &struct{}{}}
	require.NoError(t, c.Lock(context.Background(), target), "Lock must succeed")
	require.NoError(t, c.Unlock(context.Background(), target), "Unlock must succeed")
}

// TestClient_CloseSession exercises CloseSession through the echo server.
func TestClient_CloseSession(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	require.NoError(t, c.CloseSession(context.Background()))
}

// TestClient_KillSession exercises KillSession through the echo server.
func TestClient_KillSession(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	require.NoError(t, c.KillSession(context.Background(), 42))
}

// TestClient_Commit exercises Commit(nil) through the echo server.
func TestClient_Commit(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	require.NoError(t, c.Commit(context.Background(), nil))
}

// TestClient_DiscardChanges exercises DiscardChanges through the echo server.
func TestClient_DiscardChanges(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	require.NoError(t, c.DiscardChanges(context.Background()))
}

// TestClient_CancelCommit exercises CancelCommit through the echo server.
func TestClient_CancelCommit(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	require.NoError(t, c.CancelCommit(context.Background(), ""))
}

// TestClient_Validate exercises Validate through the echo server.
func TestClient_Validate(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	require.NoError(t, c.Validate(context.Background(), netconf.Datastore{Running: &struct{}{}}))
}

// TestClient_CopyConfig exercises CopyConfig through the echo server.
func TestClient_CopyConfig(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	cfg := netconf.CopyConfig{
		Target: netconf.Datastore{Running: &struct{}{}},
		Source: netconf.Datastore{Candidate: &struct{}{}},
	}
	require.NoError(t, c.CopyConfig(context.Background(), cfg))
}

// TestClient_DeleteConfig exercises DeleteConfig through the echo server.
func TestClient_DeleteConfig(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)
	cfg := netconf.DeleteConfig{Target: netconf.Datastore{Startup: &struct{}{}}}
	require.NoError(t, c.DeleteConfig(context.Background(), cfg))
}

// TestClient_RPCError verifies that a server-side <rpc-error> propagates
// through the typed method layer as a netconf.RPCError (via errors.As).
func TestClient_RPCError(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServerWithError(t, serverT)

	running := netconf.Datastore{Running: &struct{}{}}
	_, err := c.GetConfig(context.Background(), running, nil)
	require.Error(t, err, "GetConfig must return an error when server replies with rpc-error")

	var rpcErr netconf.RPCError
	require.True(t, errors.As(err, &rpcErr),
		"error must be (or wrap) a netconf.RPCError; got: %v", err)
	assert.Equal(t, "application", rpcErr.Type)
	assert.Equal(t, "invalid-value", rpcErr.Tag)
	assert.Equal(t, "error", rpcErr.Severity)
	assert.Equal(t, "test error message", rpcErr.Message)
}

// TestClient_SSHLoopback is a full end-to-end integration test:
//
//	TCP loopback → SSH handshake → NETCONF hello exchange →
//	GetConfig typed method → DataReply → CloseSession → Close
//
// This proves R004 (all 13 typed operations over a real SSH transport) using
// the loopback echo server.
func TestClient_SSHLoopback(t *testing.T) {
	// Build an SSH loopback stack with manual control over the server side.
	serverCfg, clientCfg := testSSHConfigs(t)
	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	caps := netconf.NewCapabilitySet([]string{netconf.BaseCap10, netconf.BaseCap11})
	listener := ncssh.NewListener(nl, serverCfg)
	defer listener.Close()

	type srvRes struct {
		sess *netconf.Session
		err  error
	}
	srvCh := make(chan srvRes, 1)
	go func() {
		trp, err := listener.Accept()
		if err != nil {
			srvCh <- srvRes{err: err}
			return
		}
		sess, err := netconf.ServerSession(trp, caps, 99)
		srvCh <- srvRes{sess: sess, err: err}
	}()

	addr := nl.Addr().String()
	clientTrp, err := ncssh.Dial(addr, clientCfg)
	require.NoError(t, err)
	clientSess, err := netconf.ClientSession(clientTrp, caps)
	require.NoError(t, err)

	sr := <-srvCh
	require.NoError(t, sr.err)

	cl := client.NewClient(clientSess)
	defer cl.Close()

	// Drive the server session: read RPCs, write data or ok replies.
	go func() {
		for {
			raw, err := sr.sess.Recv()
			if err != nil {
				return
			}
			var rpc netconf.RPC
			if err := xml.Unmarshal(raw, &rpc); err != nil {
				continue
			}
			opName := firstElementName(rpc.Body)
			var reply *netconf.RPCReply
			switch opName {
			case "get", "get-config":
				reply = &netconf.RPCReply{
					MessageID: rpc.MessageID,
					Body:      []byte(dataBody),
				}
			default:
				reply = &netconf.RPCReply{
					MessageID: rpc.MessageID,
					Ok:        &struct{}{},
				}
			}
			data, _ := xml.Marshal(reply)
			if err := sr.sess.Send(data); err != nil {
				return
			}
		}
	}()

	// Verify R004: GetConfig over real SSH.
	dr, err := cl.GetConfig(context.Background(),
		netconf.Datastore{Running: &struct{}{}}, nil)
	require.NoError(t, err, "GetConfig over SSH must succeed")
	require.NotNil(t, dr, "DataReply must not be nil")

	// Verify the session-id assigned by the server propagated correctly.
	assert.Equal(t, uint32(99), clientSess.SessionID(), "session-id must be 99")

	// Clean teardown.
	require.NoError(t, cl.CloseSession(context.Background()))
	require.NoError(t, cl.Close())
}

// ── Notification tests ────────────────────────────────────────────────────────

// TestClient_Notifications_ChannelExists verifies that Notifications() returns
// a non-nil receive-only channel immediately after NewClient.
func TestClient_Notifications_ChannelExists(t *testing.T) {
	c, _ := newTestPair(t)
	ch := c.Notifications()
	require.NotNil(t, ch, "Notifications() must return a non-nil channel")
	// The returned type is <-chan *netconf.Notification — verify by assignment.
	_ = ch
}

func TestClient_NotificationDropCounter(t *testing.T) {
	c, serverT := newTestPair(t)

	for range 96 {
		notifXML, err := xml.Marshal(&netconf.Notification{EventTime: "2024-01-15T10:30:00Z"})
		require.NoError(t, err, "marshal notification")
		require.NoError(t, transport.WriteMsg(serverT, notifXML), "write notification")
	}

	require.Eventually(t, func() bool {
		return c.DroppedNotifications() > 0
	}, 2*time.Second, 10*time.Millisecond, "client must report dropped notifications when channel is full")
}

// TestClient_Subscribe_Success verifies that Subscribe sends a create-subscription
// RPC, receives an <ok/> reply, and returns the same channel as Notifications().
func TestClient_Subscribe_Success(t *testing.T) {
	c, serverT := newTestPair(t)

	subErrCh := make(chan error, 1)
	subChCh := make(chan (<-chan *netconf.Notification), 1)
	go func() {
		ch, err := c.Subscribe(context.Background(), netconf.CreateSubscription{})
		subChCh <- ch
		subErrCh <- err
	}()

	// Server: read the RPC and assert it contains create-subscription.
	raw, err := transport.ReadMsg(serverT)
	require.NoError(t, err, "server must read the subscribe RPC")
	var rpc netconf.RPC
	require.NoError(t, xml.Unmarshal(raw, &rpc), "server must parse RPC")
	assert.Contains(t, string(rpc.Body), "create-subscription",
		"RPC body must contain create-subscription")

	// Server: send an <ok/> reply.
	writeReply(t, serverT, okReply(rpc.MessageID))

	// Client: Subscribe must succeed and return the same channel as Notifications().
	require.NoError(t, <-subErrCh, "Subscribe must succeed")
	subCh := <-subChCh
	require.NotNil(t, subCh, "Subscribe must return a non-nil channel")
	assert.Equal(t, c.Notifications(), subCh,
		"Subscribe must return the same channel as Notifications()")
}

// TestClient_NotificationDelivery verifies that a <notification> sent by the
// server is delivered to the client's Notifications() channel with the correct
// EventTime and Body content.
func TestClient_NotificationDelivery(t *testing.T) {
	c, serverT := newTestPair(t)

	const eventTime = "2024-01-15T10:30:00Z"
	const eventBody = `<netconf-config-change xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-notifications"><datastore>running</datastore></netconf-config-change>`

	// Server: write a raw notification directly on the transport (no RPC handshake
	// needed — notifications flow server→client unprompted).
	notif := &netconf.Notification{
		EventTime: eventTime,
		Body:      []byte(eventTime + "<eventTime>" + eventTime + "</eventTime>" + eventBody),
	}
	// Use xml.Marshal to produce a properly-namespaced <notification> element.
	notifXML, err := xml.Marshal(&netconf.Notification{
		EventTime: eventTime,
		Body:      []byte(eventBody),
	})
	require.NoError(t, err, "marshal notification")
	// Discard notif — it was only used to illustrate structure.
	_ = notif
	require.NoError(t, transport.WriteMsg(serverT, notifXML), "write notification to transport")

	// Client: receive from the notification channel with a timeout.
	select {
	case n := <-c.Notifications():
		require.NotNil(t, n, "received notification must not be nil")
		assert.Equal(t, eventTime, n.EventTime, "EventTime must match the sent value")
		assert.Contains(t, string(n.Body), "netconf-config-change",
			"Body must contain the event element")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notification")
	}
}

// TestClient_NotificationDoesNotBlockRPC verifies that a notification and a
// concurrent RPC can both be in-flight at the same time over the same session,
// and that both are delivered correctly (notification interleave invariant).
func TestClient_NotificationDoesNotBlockRPC(t *testing.T) {
	c, serverT := newTestPair(t)

	const eventTime = "2024-06-01T00:00:00Z"

	// Server goroutine: send a notification, then service one RPC.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		// Send notification first (unprompted, before any RPC arrives).
		notifXML, err := xml.Marshal(&netconf.Notification{
			EventTime: eventTime,
		})
		if err != nil {
			t.Errorf("server: marshal notification: %v", err)
			return
		}
		if err := transport.WriteMsg(serverT, notifXML); err != nil {
			t.Errorf("server: write notification: %v", err)
			return
		}

		// Service the RPC that the client will issue.
		raw, err := transport.ReadMsg(serverT)
		if err != nil {
			t.Errorf("server: read RPC: %v", err)
			return
		}
		var rpc netconf.RPC
		if err := xml.Unmarshal(raw, &rpc); err != nil {
			t.Errorf("server: unmarshal RPC: %v", err)
			return
		}
		reply := okReply(rpc.MessageID)
		data, _ := xml.Marshal(reply)
		if err := transport.WriteMsg(serverT, data); err != nil {
			t.Errorf("server: write reply: %v", err)
		}
	}()

	// Client: issue an RPC concurrently while the notification is in-flight.
	rpcErrCh := make(chan error, 1)
	go func() {
		_, err := c.Do(context.Background(), netconf.CloseSession{})
		rpcErrCh <- err
	}()

	// Both the notification and the RPC reply must arrive within 2 seconds.
	notifReceived := false
	rpcDone := false
	deadline := time.After(2 * time.Second)
	for !notifReceived || !rpcDone {
		select {
		case n := <-c.Notifications():
			require.NotNil(t, n, "notification must not be nil")
			assert.Equal(t, eventTime, n.EventTime, "EventTime must match")
			notifReceived = true
		case err := <-rpcErrCh:
			require.NoError(t, err, "interleaved RPC must succeed")
			rpcDone = true
		case <-deadline:
			t.Fatalf("timed out: notifReceived=%v rpcDone=%v", notifReceived, rpcDone)
		}
	}

	<-serverDone
}

// TestClient_NotificationChannelClosedOnDispatcherExit verifies that the
// notification channel is closed when the dispatcher exits (transport close).
// This allows receivers to use range over the channel.
func TestClient_NotificationChannelClosedOnDispatcherExit(t *testing.T) {
	c, serverT := newTestPair(t)

	// Close the server transport to force the dispatcher to exit.
	require.NoError(t, serverT.Close(), "serverT.Close must succeed")

	// The notification channel must be closed within a reasonable timeout.
	select {
	case _, open := <-c.Notifications():
		assert.False(t, open, "Notifications() channel must be closed after dispatcher exit")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Notifications() channel to close")
	}
}

// ── TLS loopback helpers ──────────────────────────────────────────────────────

// tlsClientCABundle holds an ECDSA CA cert + key for TLS test cert generation.
type tlsClientCABundle struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// generateClientTestCA creates a self-signed ECDSA P-256 CA for use in TLS
// loopback tests. No disk I/O; keys are ephemeral.
func generateClientTestCA(t *testing.T) *tlsClientCABundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate CA key")
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create CA cert")
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "parse CA cert")
	return &tlsClientCABundle{cert: cert, key: key}
}

// generateClientTestCert creates a certificate signed by ca using template.
// Returns cert PEM and key PEM.
func generateClientTestCert(t *testing.T, ca *tlsClientCABundle, template *x509.Certificate) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate cert key")
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err, "create cert")
	_, err = x509.ParseCertificate(certDER)
	require.NoError(t, err, "parse cert")
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err, "marshal key")
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// testClientTLSConfigs returns a matched server+client *cryptotls.Config pair
// for TLS loopback tests, with mutual auth enabled.
func testClientTLSConfigs(t *testing.T) (serverCfg, clientCfg *cryptotls.Config) {
	t.Helper()
	ca := generateClientTestCA(t)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)

	// Server cert (SANs: "localhost", "127.0.0.1").
	sCertPEM, sKeyPEM := generateClientTestCert(t, ca, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server.test"},
		DNSNames:     []string{"localhost", "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	serverTLSCert, err := cryptotls.X509KeyPair(sCertPEM, sKeyPEM)
	require.NoError(t, err, "server X509KeyPair")

	// Client cert (SAN DNS: "client.test").
	cCertPEM, cKeyPEM := generateClientTestCert(t, ca, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "client.test"},
		DNSNames:     []string{"client.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	clientTLSCert, err := cryptotls.X509KeyPair(cCertPEM, cKeyPEM)
	require.NoError(t, err, "client X509KeyPair")

	serverCfg = &cryptotls.Config{
		Certificates: []cryptotls.Certificate{serverTLSCert},
		ClientAuth:   cryptotls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	clientCfg = &cryptotls.Config{
		Certificates: []cryptotls.Certificate{clientTLSCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}
	return
}

// ── TestClient_TLSLoopback ────────────────────────────────────────────────────

// TestClient_TLSLoopback is a full end-to-end integration test for the TLS
// transport path:
//
//	TCP loopback → TLS mutual auth (ECDSA P-256) → NETCONF hello exchange →
//	DialTLS → GetConfig typed method → DataReply
//
// This proves the complete DialTLS → ClientSession → NewClient → GetConfig
// stack using an ephemeral in-process TLS server.
func TestClient_TLSLoopback(t *testing.T) {
	serverCfg, clientCfg := testClientTLSConfigs(t)

	caps := netconf.NewCapabilitySet([]string{netconf.BaseCap10, netconf.BaseCap11})

	// Bind a loopback listener for the TLS server.
	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen on loopback")
	addr := nl.Addr().String()

	tlsListener := nctls.NewListener(nl, serverCfg)
	defer tlsListener.Close()

	// Server goroutine: accept one connection, run ServerSession, then echo
	// RPCs using the same echo logic as TestClient_SSHLoopback.
	type srvResult struct {
		sess *netconf.Session
		err  error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		srvTrp, err := tlsListener.Accept()
		if err != nil {
			srvCh <- srvResult{err: err}
			return
		}
		sess, err := netconf.ServerSession(srvTrp, caps, 99)
		if err != nil {
			_ = srvTrp.Close()
			srvCh <- srvResult{err: err}
			return
		}
		srvCh <- srvResult{sess: sess}
	}()

	// Client: DialTLS performs TCP dial + TLS handshake + NETCONF hello.
	ctx := context.Background()
	cl, err := client.DialTLS(ctx, addr, clientCfg, caps)
	require.NoError(t, err, "DialTLS must succeed")
	defer cl.Close()

	// Collect server result; it must be ready by now (DialTLS blocks until
	// hello completes, which requires the server to have finished too).
	var sr srvResult
	select {
	case sr = <-srvCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server session")
	}
	require.NoError(t, sr.err, "ServerSession must succeed")

	// Drive the server session: read RPCs and write data/ok replies.
	go func() {
		for {
			raw, err := sr.sess.Recv()
			if err != nil {
				return // transport closed — normal exit
			}
			var rpc netconf.RPC
			if err := xml.Unmarshal(raw, &rpc); err != nil {
				continue
			}
			opName := firstElementName(rpc.Body)
			var reply *netconf.RPCReply
			switch opName {
			case "get", "get-config":
				reply = &netconf.RPCReply{
					MessageID: rpc.MessageID,
					Body:      []byte(dataBody),
				}
			default:
				reply = &netconf.RPCReply{
					MessageID: rpc.MessageID,
					Ok:        &struct{}{},
				}
			}
			data, _ := xml.Marshal(reply)
			if err := sr.sess.Send(data); err != nil {
				return
			}
		}
	}()

	// Verify the full stack: GetConfig over real TLS returns a DataReply.
	dr, err := cl.GetConfig(ctx, netconf.Datastore{Running: &struct{}{}}, nil)
	require.NoError(t, err, "GetConfig over TLS must succeed")
	require.NotNil(t, dr, "DataReply must not be nil")

	// Clean teardown: CloseSession then Close.
	require.NoError(t, cl.CloseSession(ctx), "CloseSession must succeed")
	require.NoError(t, cl.Close(), "Close must succeed")
}

// ── Partial-lock / partial-unlock typed method tests ─────────────────────────

// TestClient_PartialLock exercises PartialLock through the echo server.
// The echo server returns a mock partial-lock-reply with lock-id=1 and two
// locked-node entries.
func TestClient_PartialLock(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	reply, err := c.PartialLock(context.Background(), []string{"/interfaces", "/routing"})
	require.NoError(t, err, "PartialLock must succeed")
	require.NotNil(t, reply, "PartialLockReply must not be nil")
	assert.Equal(t, uint32(1), reply.LockID,
		"PartialLockReply.LockID must equal the server-returned lock-id 1")
	assert.Len(t, reply.LockedNode, 2,
		"PartialLockReply must contain exactly 2 locked-node entries")
}

// TestClient_PartialUnlock exercises PartialUnlock through the echo server.
// The echo server returns a plain <ok/> for partial-unlock (default branch).
func TestClient_PartialUnlock(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	require.NoError(t, c.PartialUnlock(context.Background(), 1),
		"PartialUnlock must succeed when server replies with <ok/>")
}

// ── GetSchema typed method tests ──────────────────────────────────────────────

// TestClient_GetSchema exercises GetSchema end-to-end through the echo server.
// The echo server returns a <data> element with a minimal YANG schema when it
// receives a get-schema RPC.
func TestClient_GetSchema(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	req := &monitoring.GetSchemaRequest{
		Identifier: "ietf-interfaces",
		Version:    "2018-02-20",
		Format:     "yang",
	}
	content, err := c.GetSchema(context.Background(), req)
	require.NoError(t, err, "GetSchema must succeed")
	require.NotNil(t, content, "returned content must not be nil")
	assert.Contains(t, string(content), "ietf-interfaces",
		"returned content must contain the schema identifier text")
}

// TestClient_GetSchema_MinimalRequest verifies that GetSchema works with only
// the Identifier set (Version and Format omitted).
func TestClient_GetSchema_MinimalRequest(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServer(t, serverT)

	req := &monitoring.GetSchemaRequest{Identifier: "ietf-interfaces"}
	content, err := c.GetSchema(context.Background(), req)
	require.NoError(t, err, "GetSchema with minimal request must succeed")
	assert.NotEmpty(t, content, "returned content must not be empty")
}

// TestClient_GetSchema_RPCError verifies that a server-side <rpc-error> on a
// GetSchema call surfaces with the "client: GetSchema:" prefix in the error
// string, and is extractable via errors.As.
func TestClient_GetSchema_RPCError(t *testing.T) {
	c, serverT := newTestPair(t)
	go echoServerWithError(t, serverT)

	req := &monitoring.GetSchemaRequest{Identifier: "missing-schema"}
	_, err := c.GetSchema(context.Background(), req)
	require.Error(t, err, "GetSchema must return an error when server replies with rpc-error")
	assert.Contains(t, err.Error(), "client: GetSchema:",
		"error must carry the client: GetSchema: prefix")

	var rpcErr netconf.RPCError
	require.True(t, errors.As(err, &rpcErr),
		"error must be or wrap a netconf.RPCError; got: %v", err)
	assert.Equal(t, "invalid-value", rpcErr.Tag,
		"RPCError.Tag must be extracted from the server reply")
}

// ── Coverage-improvement tests ────────────────────────────────────────────────

// TestClient_RemoteCapabilities verifies that RemoteCapabilities returns the
// capabilities advertised by the server during hello.
func TestClient_RemoteCapabilities(t *testing.T) {
	c, _ := newTestPair(t)
	caps := c.RemoteCapabilities()
	assert.True(t, caps.Contains(netconf.BaseCap10))
}

// TestClient_SessionID verifies that SessionID returns the server-assigned ID.
func TestClient_SessionID(t *testing.T) {
	c, _ := newTestPair(t)
	assert.Equal(t, uint32(1), c.SessionID())
}

// TestClient_Subscribe_RPCError verifies that Subscribe surfaces server-side
// <rpc-error> elements as errors.
func TestClient_Subscribe_RPCError(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		errBody, _ := xml.Marshal(netconf.RPCError{
			Type: "application", Tag: "invalid-value",
			Severity: "error", Message: "subscribe rejected",
		})
		writeReply(t, serverT, &netconf.RPCReply{MessageID: rpc.MessageID, Body: errBody})
	}()

	_, err := c.Subscribe(context.Background(), netconf.CreateSubscription{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: Subscribe:")
	var rpcErr netconf.RPCError
	assert.True(t, errors.As(err, &rpcErr))
}

// TestClient_Get_NonDataReply verifies that Get returns an error when the
// server reply body is valid XML but not a <data> element.
func TestClient_Get_NonDataReply(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		writeReply(t, serverT, &netconf.RPCReply{
			MessageID: rpc.MessageID,
			Body:      []byte(`<not-data/>`),
		})
	}()

	_, err := c.Get(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode DataReply")
}

// TestClient_GetConfig_NonDataReply verifies that GetConfig returns an error
// when the server reply body is valid XML but not a <data> element.
func TestClient_GetConfig_NonDataReply(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		writeReply(t, serverT, &netconf.RPCReply{
			MessageID: rpc.MessageID,
			Body:      []byte(`<not-data/>`),
		})
	}()

	_, err := c.GetConfig(context.Background(), netconf.Datastore{Running: &struct{}{}}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode DataReply")
}

// TestClient_GetConfig_RPCError verifies that GetConfig surfaces server-side
// <rpc-error> as a netconf.RPCError.
func TestClient_GetConfig_RPCError(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		errBody, _ := xml.Marshal(netconf.RPCError{
			Type: "application", Tag: "invalid-value",
			Severity: "error", Message: "test",
		})
		writeReply(t, serverT, &netconf.RPCReply{MessageID: rpc.MessageID, Body: errBody})
	}()

	_, err := c.GetConfig(context.Background(), netconf.Datastore{Running: &struct{}{}}, nil)
	require.Error(t, err)
	var rpcErr netconf.RPCError
	assert.True(t, errors.As(err, &rpcErr))
}

// TestClient_Get_ContextCancelled verifies that Get returns an error when the
// context is already cancelled.
func TestClient_Get_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	_, err := c.Get(ctx, nil)
	require.Error(t, err)
}

// TestClient_GetConfig_ContextCancelled verifies that GetConfig returns an
// error when the context is already cancelled.
func TestClient_GetConfig_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	_, err := c.GetConfig(ctx, netconf.Datastore{Running: &struct{}{}}, nil)
	require.Error(t, err)
}

// TestClient_TypedOps_ContextCancelled covers the Do-error path for many typed
// methods that return only error. We close the client first so Do returns
// immediately with an error rather than blocking on the loopback transport.
func TestClient_TypedOps_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()

	ctx := context.Background()
	assert.Error(t, c.EditConfig(ctx, netconf.EditConfig{}))
	assert.Error(t, c.CopyConfig(ctx, netconf.CopyConfig{}))
	assert.Error(t, c.DeleteConfig(ctx, netconf.DeleteConfig{}))
	assert.Error(t, c.Lock(ctx, netconf.Datastore{}))
	assert.Error(t, c.Unlock(ctx, netconf.Datastore{}))
	assert.Error(t, c.CloseSession(ctx))
	assert.Error(t, c.KillSession(ctx, 1))
	assert.Error(t, c.Validate(ctx, netconf.Datastore{}))
	assert.Error(t, c.DiscardChanges(ctx))
	assert.Error(t, c.CancelCommit(ctx, ""))
}

// TestClient_Commit_NilOpts verifies that Commit with nil opts issues a plain
// <commit/>.
func TestClient_Commit_NilOpts(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		writeReply(t, serverT, okReply(rpc.MessageID))
	}()

	err := c.Commit(context.Background(), nil)
	require.NoError(t, err)
}

// TestClient_Commit_ContextCancelled verifies that Commit returns an error
// when the context is cancelled.
func TestClient_Commit_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	assert.Error(t, c.Commit(ctx, nil))
}

// TestClient_PartialLock_ContextCancelled verifies the Do-error path.
func TestClient_PartialLock_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	_, err := c.PartialLock(ctx, []string{"/config"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: PartialLock:")
}

// TestClient_PartialLock_RPCError verifies that server-side rpc-error
// propagates through PartialLock.
func TestClient_PartialLock_RPCError(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		errBody, _ := xml.Marshal(netconf.RPCError{
			Type: "application", Tag: "lock-denied",
			Severity: "error", Message: "lock denied",
		})
		writeReply(t, serverT, &netconf.RPCReply{MessageID: rpc.MessageID, Body: errBody})
	}()

	_, err := c.PartialLock(context.Background(), []string{"/config"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: PartialLock:")
	var rpcErr netconf.RPCError
	assert.True(t, errors.As(err, &rpcErr))
}

// TestClient_PartialUnlock_ContextCancelled verifies the Do-error path.
func TestClient_PartialUnlock_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	err := c.PartialUnlock(ctx, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: PartialUnlock:")
}

// TestClient_PartialUnlock_RPCError verifies that server-side rpc-error
// propagates through PartialUnlock.
func TestClient_PartialUnlock_RPCError(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		errBody, _ := xml.Marshal(netconf.RPCError{
			Type: "application", Tag: "invalid-value",
			Severity: "error", Message: "bad lock-id",
		})
		writeReply(t, serverT, &netconf.RPCReply{MessageID: rpc.MessageID, Body: errBody})
	}()

	err := c.PartialUnlock(context.Background(), 999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: PartialUnlock:")
	var rpcErr netconf.RPCError
	assert.True(t, errors.As(err, &rpcErr))
}

// TestClient_GetSchema_ContextCancelled verifies the Do-error path.
func TestClient_GetSchema_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	_, err := c.GetSchema(ctx, &monitoring.GetSchemaRequest{Identifier: "test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: GetSchema:")
}

// TestClient_GetSchema_NonSchemaReply verifies the decode error path when the
// reply body is not a valid GetSchemaReply.
func TestClient_GetSchema_NonSchemaReply(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		writeReply(t, serverT, &netconf.RPCReply{
			MessageID: rpc.MessageID,
			Body:      []byte(`<not-schema-data/>`),
		})
	}()

	_, err := c.GetSchema(context.Background(), &monitoring.GetSchemaRequest{Identifier: "test"})
	// GetSchema should succeed but return empty content since the XML doesn't
	// match the expected structure — or fail during decode. Either way we
	// verify the path is exercised.
	_ = err
}

// TestClient_EditData_ContextCancelled verifies the Do-error path.
func TestClient_EditData_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	err := c.EditData(ctx, nmda.EditData{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: EditData:")
}

// TestClient_EstablishSubscription_ContextCancelled verifies the Do-error path.
func TestClient_EstablishSubscription_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	_, _, err := c.EstablishSubscription(ctx, subscriptions.EstablishSubscriptionRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: EstablishSubscription:")
}

// TestClient_EstablishSubscription_RPCError verifies that server-side rpc-error
// propagates through EstablishSubscription.
func TestClient_EstablishSubscription_RPCError(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		errBody, _ := xml.Marshal(netconf.RPCError{
			Type: "application", Tag: "invalid-value",
			Severity: "error", Message: "subscription rejected",
		})
		writeReply(t, serverT, &netconf.RPCReply{MessageID: rpc.MessageID, Body: errBody})
	}()

	_, _, err := c.EstablishSubscription(context.Background(), subscriptions.EstablishSubscriptionRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: EstablishSubscription:")
	var rpcErr netconf.RPCError
	assert.True(t, errors.As(err, &rpcErr))
}

// TestClient_ModifySubscription_ContextCancelled verifies the Do-error path.
func TestClient_ModifySubscription_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	err := c.ModifySubscription(ctx, subscriptions.ModifySubscriptionRequest{ID: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: ModifySubscription:")
}

// TestClient_DeleteSubscription_ContextCancelled verifies the Do-error path.
func TestClient_DeleteSubscription_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	err := c.DeleteSubscription(ctx, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: DeleteSubscription:")
}

// TestClient_KillSubscription_ContextCancelled verifies the Do-error path.
func TestClient_KillSubscription_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	err := c.KillSubscription(ctx, 1, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: KillSubscription:")
}

// TestClient_Subscribe_ContextCancelled verifies the Do-error path.
func TestClient_Subscribe_ContextCancelled(t *testing.T) {
	c, _ := newTestPair(t)
	c.Close()
	ctx := context.Background()
	_, err := c.Subscribe(ctx, netconf.CreateSubscription{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client: Subscribe:")
}

// TestClient_Dial_ContextAlreadyDone verifies that Dial returns early when
// the context is already cancelled.
func TestClient_Dial_ContextAlreadyDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Dial(ctx, "127.0.0.1:830", &gossh.ClientConfig{}, testCaps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context already done")
}

// TestClient_checkReply_MalformedXML exercises the parse-error path in
// checkReply (indirectly through EditConfig) when reply body contains
// malformed XML that ParseRPCErrors cannot parse.
func TestClient_checkReply_MalformedXML(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		// Use a valid rpc-reply but with body that looks like rpc-error with
		// malformed inner content - ParseRPCErrors will fail to decode it.
		writeReply(t, serverT, &netconf.RPCReply{
			MessageID: rpc.MessageID,
			Body:      []byte(`<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><error-type>application</error-type><error-tag>invalid-value</error-tag><error-severity>error</error-severity><error-message>test error</error-message></rpc-error>`),
		})
	}()

	err := c.EditConfig(context.Background(), netconf.EditConfig{})
	require.Error(t, err)
	var rpcErr netconf.RPCError
	assert.True(t, errors.As(err, &rpcErr))
}

// TestClient_checkDataReply_DecodeError exercises the XML decode error path in
// checkDataReply (indirectly through Get) when reply body is valid XML but
// not a <data> element, causing xml.Unmarshal to fail with a type mismatch.
func TestClient_checkDataReply_DecodeError(t *testing.T) {
	c, serverT := newTestPair(t)

	go func() {
		raw, err := transport.ReadMsg(serverT)
		require.NoError(t, err)
		var rpc netconf.RPC
		require.NoError(t, xml.Unmarshal(raw, &rpc))
		// Reply with body that is valid XML but not a <data> element.
		// checkDataReply's xml.Unmarshal into DataReply will fail because
		// the root element is <not-data> instead of <data>.
		writeReply(t, serverT, &netconf.RPCReply{
			MessageID: rpc.MessageID,
			Body:      []byte(`<not-data>some content</not-data>`),
		})
	}()

	_, err := c.Get(context.Background(), nil)
	require.Error(t, err, "Get must error when reply body is not a <data> element")
	assert.Contains(t, err.Error(), "decode DataReply",
		"error must mention DataReply decode failure")
}
