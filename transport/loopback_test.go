package transport_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/GabrielNunesIT/netconf/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Basic loopback round-trip ─────────────────────────────────────────────────

func TestLoopback_ClientWritesServerReads(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	defer client.Close()
	defer server.Close()

	msg := []byte("<hello><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>")

	// Write from client in a goroutine (pipe would block otherwise).
	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.WriteMsg(client, msg)
	}()

	got, err := transport.ReadMsg(server)
	require.NoError(t, err, "server must read client message without error")
	require.NoError(t, <-errCh, "client write must succeed")

	assert.Equal(t, msg, got, "server must receive exactly what client sent")
}

func TestLoopback_ServerWritesClientReads(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	defer client.Close()
	defer server.Close()

	msg := []byte("<rpc-reply message-id=\"1\"><ok/></rpc-reply>")

	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.WriteMsg(server, msg)
	}()

	got, err := transport.ReadMsg(client)
	require.NoError(t, err)
	require.NoError(t, <-errCh)

	assert.Equal(t, msg, got)
}

// ── Full request/response round-trip ─────────────────────────────────────────

func TestLoopback_RoundTrip_RequestResponse(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	defer client.Close()
	defer server.Close()

	request := []byte("<rpc message-id=\"42\"><get/></rpc>")
	response := []byte("<rpc-reply message-id=\"42\"><ok/></rpc-reply>")

	done := make(chan error, 2)

	// Client: send request, then receive response.
	go func() {
		if err := transport.WriteMsg(client, request); err != nil {
			done <- err
			return
		}
		got, err := transport.ReadMsg(client)
		if err != nil {
			done <- err
			return
		}
		if string(got) != string(response) {
			done <- fmt.Errorf("client: expected %q, got %q", response, got)
			return
		}
		done <- nil
	}()

	// Server: receive request, send response.
	go func() {
		got, err := transport.ReadMsg(server)
		if err != nil {
			done <- err
			return
		}
		if string(got) != string(request) {
			done <- fmt.Errorf("server: expected %q, got %q", request, got)
			return
		}
		done <- transport.WriteMsg(server, response)
	}()

	for i := range 2 {
		require.NoError(t, <-done, "goroutine %d must succeed", i)
	}
}

// ── Multiple sequential messages ─────────────────────────────────────────────

func TestLoopback_MultipleMessages_Sequential(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	defer client.Close()
	defer server.Close()

	messages := []string{
		"<rpc message-id=\"1\"><get/></rpc>",
		"<rpc message-id=\"2\"><get-config><source><running/></source></get-config></rpc>",
		"<rpc message-id=\"3\"><close-session/></rpc>",
	}

	done := make(chan error, 1)
	go func() {
		for _, m := range messages {
			if err := transport.WriteMsg(client, []byte(m)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i, expected := range messages {
		got, err := transport.ReadMsg(server)
		require.NoError(t, err, "message %d read must succeed", i)
		assert.Equal(t, expected, string(got), "message %d content must match", i)
	}

	require.NoError(t, <-done)
}

// ── EOM then chunked (Upgrade mid-stream) ─────────────────────────────────────

func TestLoopback_Upgrade_EOMModeToChunked(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	defer client.Close()
	defer server.Close()

	// Phase 1: hello exchange in EOM mode.
	// io.Pipe is synchronous/unbuffered: a write blocks until the peer reads.
	// To avoid deadlock, we run each side's write in a goroutine so that both
	// writes and their corresponding reads happen concurrently.
	helloClient := []byte("<hello><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>")
	helloServer := []byte("<hello><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities><session-id>1</session-id></hello>")

	// client→server pipe: client writes, server reads.
	clientWriteDone := make(chan error, 1)
	go func() {
		clientWriteDone <- transport.WriteMsg(client, helloClient)
	}()
	// Server reads client hello (unblocks client write goroutine).
	gotClientHello, err := transport.ReadMsg(server)
	require.NoError(t, err, "server must read client hello")
	require.Equal(t, helloClient, gotClientHello)
	require.NoError(t, <-clientWriteDone, "client write hello must succeed")

	// server→client pipe: server writes, client reads.
	serverWriteDone := make(chan error, 1)
	go func() {
		serverWriteDone <- transport.WriteMsg(server, helloServer)
	}()
	// Client reads server hello (unblocks server write goroutine).
	gotServerHello, err := transport.ReadMsg(client)
	require.NoError(t, err, "client must read server hello")
	require.Equal(t, helloServer, gotServerHello)
	require.NoError(t, <-serverWriteDone, "server write hello must succeed")

	// Phase 2: both sides upgrade to chunked.
	client.Upgrade()
	server.Upgrade()

	// Phase 3: exchange a message in chunked mode.
	rpcMsg := []byte("<rpc message-id=\"1\"><get/></rpc>")
	rpcReply := []byte("<rpc-reply message-id=\"1\"><ok/></rpc-reply>")

	// client→server: client writes rpc, server reads it.
	rpcWriteDone := make(chan error, 1)
	go func() {
		rpcWriteDone <- transport.WriteMsg(client, rpcMsg)
	}()
	gotRPC, err := transport.ReadMsg(server)
	require.NoError(t, err, "server must read rpc")
	require.Equal(t, rpcMsg, gotRPC)
	require.NoError(t, <-rpcWriteDone, "client write rpc must succeed")

	// server→client: server writes reply, client reads it.
	replyWriteDone := make(chan error, 1)
	go func() {
		replyWriteDone <- transport.WriteMsg(server, rpcReply)
	}()
	gotReply, err := transport.ReadMsg(client)
	require.NoError(t, err, "client must read reply")
	require.Equal(t, rpcReply, gotReply)
	require.NoError(t, <-replyWriteDone, "server write reply must succeed")
}

// ── Close makes subsequent calls error ───────────────────────────────────────

func TestLoopback_Close_MakesReadsError(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	require.NoError(t, client.Close())

	// Server tries to read from a closed client; the pipe write-end is closed
	// so server's MsgReader should see EOF or a pipe error.
	r, err := server.MsgReader()
	if err != nil {
		// MsgReader itself errored — acceptable.
		return
	}
	_, err = io.ReadAll(r)
	require.Error(t, err, "reading from a closed peer must return an error")
}

// ── Interface conformance (compile-time) ──────────────────────────────────────

// TestLoopback_ImplementsTransport verifies at compile time that
// *LoopbackTransport satisfies transport.Transport and transport.Upgrader.
// If the interface is not satisfied, this file will not compile.
func TestLoopback_ImplementsTransport(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	defer client.Close()
	defer server.Close()

	var _ transport.Transport = client
	var _ transport.Transport = server
	var _ transport.Upgrader = client
	var _ transport.Upgrader = server
}

// ── Additional loopback coverage tests ────────────────────────────────────────

func TestWriteMsg_WriterBodyError(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	// Close server so the pipe that client writes into is broken.
	require.NoError(t, server.Close())

	err := transport.WriteMsg(client, []byte("<hello/>"))
	require.Error(t, err, "WriteMsg on broken pipe must error")
}

func TestReadMsg_EmptyReadCloser(t *testing.T) {
	t.Parallel()
	client, server := transport.NewLoopback()
	// Close client so server's read end sees EOF.
	require.NoError(t, client.Close())

	_, err := transport.ReadMsg(server)
	require.Error(t, err, "ReadMsg from closed peer must error")
}

func TestLoopback_Close_WriteSideErrors(t *testing.T) {
	t.Parallel()
	client, _ := transport.NewLoopback()
	require.NoError(t, client.Close())

	err := transport.WriteMsg(client, []byte("<rpc/>"))
	require.Error(t, err, "WriteMsg after Close must error")
}
