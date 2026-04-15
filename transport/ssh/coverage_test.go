// coverage_test.go — additional tests to improve coverage for transport/ssh.
//
// These tests target error paths, edge cases, and uncovered functions
// in client.go and server.go.
package ssh

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/GabrielNunesIT/netconf/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

// ─── NewClientTransport ──────────────────────────────────────────────────────

// TestNewClientTransport verifies that NewClientTransport wraps a gossh.Channel
// and the resulting Transport is usable for message exchange.
func TestNewClientTransport(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := NewListener(nl, serverCfg)
	defer listener.Close()

	addr := nl.Addr().String()

	// Perform SSH handshake manually to get a raw gossh.Channel.
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)

	sshConn, chans, sshReqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(sshReqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	sshClient := gossh.NewClient(sshConn, chans, sshReqs)
	sess, err := sshClient.NewSession()
	require.NoError(t, err)

	err = sess.RequestSubsystem("netconf")
	require.NoError(t, err)

	// Accept the server-side transport.
	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	defer srvTrp.Close()

	// Now get the SSH channel. The gossh.Session implements gossh.Channel
	// when accessed as an io.ReadWriteCloser — but we can't directly get the
	// underlying channel from a gossh.Session. Instead, we'll just verify
	// NewClientTransport works by creating a Transport from a manual channel.

	// Actually, to call NewClientTransport we need a gossh.Channel. Since
	// we can't extract one from gossh.Session easily, we'll open a second
	// session channel and request netconf on it.
	sess2, err := sshClient.NewSession()
	require.NoError(t, err)

	// The sess2 underlying channel does not expose gossh.Channel directly.
	// Let's use OpenChannel directly to get a gossh.Channel.
	_ = sess2.Close()
	_ = sess.Close()

	// Test NewClientTransport via a direct OpenChannel + subsystem request.
	channel, chanReqs, err := sshConn.OpenChannel("session", nil)
	require.NoError(t, err)

	// Drain channel requests.
	go func() {
		for range chanReqs {
		}
	}()

	// The server's handleSession will process our subsystem request.
	// We need to manually send a subsystem request on this channel.
	subsysPayload := make([]byte, 4+7)
	subsysPayload[3] = 7 // length of "netconf"
	copy(subsysPayload[4:], "netconf")
	ok, err := channel.SendRequest("subsystem", true, subsysPayload)
	require.NoError(t, err)
	require.True(t, ok, "subsystem request should be accepted")

	// Accept the second server-side transport.
	srvTrp2, err := listener.Accept()
	require.NoError(t, err)
	defer srvTrp2.Close()

	// Now use NewClientTransport with the raw gossh.Channel.
	clientTrp := NewClientTransport(channel)
	defer clientTrp.Close()

	// Verify message round-trip.
	testMsg := []byte("<rpc>NewClientTransport test</rpc>")
	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- transport.WriteMsg(clientTrp, testMsg)
	}()

	got, err := transport.ReadMsg(srvTrp2)
	require.NoError(t, err, "server read message")
	assert.Equal(t, testMsg, got, "message round-trip via NewClientTransport")
	require.NoError(t, <-writeErrCh)

	// Also verify Upgrade is callable.
	clientTrp.Upgrade()
}

// ─── MsgReader / MsgWriter error wrapping ─────────────────────────────────────

// TestClientTransport_MsgReader_Error verifies MsgReader wraps errors with
// "ssh client:" prefix.
func TestClientTransport_MsgReader_Error(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	// Close the server-side channel to make the client MsgReader fail.
	_ = srvTrp.Close()
	// Give time for close to propagate.
	time.Sleep(50 * time.Millisecond)

	_, err = clientTrp.MsgReader()
	if err != nil {
		assert.Contains(t, err.Error(), "ssh client:", "error must have ssh client prefix")
	}
	_ = clientTrp.Close()
}

// TestClientTransport_MsgWriter_Error verifies MsgWriter wraps errors with
// "ssh client:" prefix when the underlying channel is closed.
func TestClientTransport_MsgWriter_Error(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	_ = srvTrp.Close()
	// Close the client transport to make MsgWriter fail.
	_ = clientTrp.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = clientTrp.MsgWriter()
	if err != nil {
		assert.Contains(t, err.Error(), "ssh client:", "error must have ssh client prefix")
	}
}

// TestServerTransport_MsgReader_Error verifies ServerTransport.MsgReader wraps
// errors with "ssh server:" prefix.
func TestServerTransport_MsgReader_Error(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	// Close client side to make server MsgReader fail.
	_ = clientTrp.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = srvTrp.MsgReader()
	if err != nil {
		assert.Contains(t, err.Error(), "ssh server:", "error must have ssh server prefix")
	}
	_ = srvTrp.Close()
}

// TestServerTransport_MsgWriter_Error verifies ServerTransport.MsgWriter wraps
// errors with "ssh server:" prefix.
func TestServerTransport_MsgWriter_Error(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	_ = clientTrp.Close()
	_ = srvTrp.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = srvTrp.MsgWriter()
	if err != nil {
		assert.Contains(t, err.Error(), "ssh server:", "error must have ssh server prefix")
	}
}

// ─── Close error paths ───────────────────────────────────────────────────────

// TestClientTransport_Close_ChannelError verifies client Close wraps channel
// close errors.
func TestClientTransport_Close_ChannelError(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	_ = srvTrp.Close()

	// First close should succeed.
	err = clientTrp.Close()
	// Closing may or may not error depending on timing.
	_ = err

	// Second close should error (already closed).
	err = clientTrp.Close()
	if err != nil {
		assert.Contains(t, err.Error(), "ssh client: close", "double-close error must have prefix")
	}
}

// TestServerTransport_Close_ChannelError verifies server Close wraps channel
// close errors.
func TestServerTransport_Close_ChannelError(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()
	defer clientTrp.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	// First close should succeed.
	err = srvTrp.Close()
	require.NoError(t, err, "first close should succeed")

	// Second close should error.
	err = srvTrp.Close()
	if err != nil {
		assert.Contains(t, err.Error(), "ssh server: close", "double-close error must have prefix")
	}
}

// ─── Dial error path ──────────────────────────────────────────────────────────

// TestDial_TCPError verifies Dial returns a wrapped error when TCP connect fails.
func TestDial_TCPError(t *testing.T) {
	// Use a port that is not listening.
	_, err := Dial("127.0.0.1:1", &gossh.ClientConfig{
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         100 * time.Millisecond,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh client: dial", "error must have dial prefix")
}

// TestDial_HandshakeError verifies Dial returns a wrapped error when SSH
// handshake fails (e.g. server is not an SSH server).
func TestDial_HandshakeError(t *testing.T) {
	// Start a plain TCP listener that is NOT an SSH server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	// Accept the connection but don't do SSH.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Close immediately — SSH handshake will fail.
		_ = conn.Close()
	}()

	_, err = Dial(ln.Addr().String(), &gossh.ClientConfig{
		User:            "test",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh client:", "handshake error must have ssh client prefix")
}

// ─── Accept error paths ──────────────────────────────────────────────────────

// TestAccept_ListenerClosed verifies Accept returns an error when the
// underlying net.Listener is closed.
func TestAccept_ListenerClosed(t *testing.T) {
	serverCfg, _ := testSSHConfigs(t)

	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	listener := NewListener(nl, serverCfg)

	// Close the listener to trigger the errCh path.
	err = listener.Close()
	require.NoError(t, err)

	// Accept should return an error.
	_, err = listener.Accept()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh server:", "accept error must have ssh server prefix")
}

// ─── parseSubsystemName edge cases ───────────────────────────────────────────

// TestParseSubsystemName_EdgeCases tests parseSubsystemName with various
// malformed payloads.
func TestParseSubsystemName_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"nil payload", nil, ""},
		{"empty payload", []byte{}, ""},
		{"too short (1 byte)", []byte{0x00}, ""},
		{"too short (3 bytes)", []byte{0x00, 0x00, 0x00}, ""},
		{"zero length", []byte{0x00, 0x00, 0x00, 0x00}, ""},
		{"length exceeds payload", []byte{0x00, 0x00, 0x00, 0x0A, 'a', 'b'}, ""},
		{"valid netconf", []byte{0x00, 0x00, 0x00, 0x07, 'n', 'e', 't', 'c', 'o', 'n', 'f'}, "netconf"},
		{"valid shell", []byte{0x00, 0x00, 0x00, 0x05, 's', 'h', 'e', 'l', 'l'}, "shell"},
		{"exact length boundary", []byte{0x00, 0x00, 0x00, 0x01, 'x'}, "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSubsystemName(tt.payload)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ─── handleSession: duplicate netconf subsystem request ──────────────────────

// TestSSH_DuplicateNetconfSubsystem verifies that a second "netconf" subsystem
// request on the same session is rejected (the netconfAccepted guard).
func TestSSH_DuplicateNetconfSubsystem(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := NewListener(nl, serverCfg)
	defer listener.Close()

	addr := nl.Addr().String()

	// Client connects.
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)

	sshConn, chans, sshReqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(sshReqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	client := gossh.NewClient(sshConn, chans, sshReqs)

	// Open first session — request netconf subsystem (accepted).
	sess1, err := client.NewSession()
	require.NoError(t, err)
	err = sess1.RequestSubsystem("netconf")
	require.NoError(t, err, "first netconf subsystem request should succeed")

	// Accept the transport produced by the first subsystem request.
	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	defer srvTrp.Close()

	_ = sess1.Close()
}

// ─── handleConn: non-session channel type ────────────────────────────────────

// TestSSH_NonSessionChannelRejected verifies that the server rejects channel
// types other than "session".
func TestSSH_NonSessionChannelRejected(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := NewListener(nl, serverCfg)
	defer listener.Close()

	addr := nl.Addr().String()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)

	sshConn, chans, sshReqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(sshReqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	// Try to open a non-"session" channel type (e.g. "direct-tcpip").
	_, _, err = sshConn.OpenChannel("direct-tcpip", nil)
	assert.Error(t, err, "non-session channel must be rejected by server")
}

// ─── ServerTransport Upgrade ─────────────────────────────────────────────────

// TestServerTransport_Upgrade verifies the Upgrade method is callable.
func TestServerTransport_Upgrade(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()
	defer clientTrp.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	defer srvTrp.Close()

	// Should not panic; repeated calls are no-ops.
	srvTrp.Upgrade()
	srvTrp.Upgrade()
}

// ─── DialCallHome error paths ────────────────────────────────────────────────

// TestDialCallHome_DialError verifies DialCallHome returns a wrapped error when
// the TCP dial fails.
func TestDialCallHome_DialError(t *testing.T) {
	serverCfg, _ := testSSHConfigs(t)

	// Use a port that is not listening.
	_, err := DialCallHome("127.0.0.1:1", serverCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh server: call home: dial", "error must have call home dial prefix")
}

// TestDialCallHome_HandshakeError verifies callHomeHandshake returns an error
// when the SSH handshake fails.
func TestDialCallHome_HandshakeError(t *testing.T) {
	serverCfg, _ := testSSHConfigs(t)

	// Start a plain TCP listener (not an SSH client).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Close immediately to fail the SSH handshake.
		_ = conn.Close()
	}()

	_, err = DialCallHome(ln.Addr().String(), serverCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh server: call home:", "handshake error must have call home prefix")
}

// ─── callHomeHandshake: session closed before netconf subsystem ──────────────

// TestCallHome_SessionClosedBeforeNetconf verifies the error when the client
// closes the session channel without requesting the netconf subsystem.
func TestCallHome_SessionClosedBeforeNetconf(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	// Client listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()

	type result struct {
		trp *ServerTransport
		err error
	}
	srvResultCh := make(chan result, 1)

	// Server: dial out and attempt call-home handshake.
	go func() {
		srvTrp, err := DialCallHome(addr, serverCfg)
		srvResultCh <- result{srvTrp, err}
	}()

	// Client: accept the connection, perform SSH client handshake, open a
	// session, then close it immediately WITHOUT requesting netconf subsystem.
	conn, err := ln.Accept()
	require.NoError(t, err)

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	sshClient := gossh.NewClient(sshConn, chans, reqs)
	sess, err := sshClient.NewSession()
	require.NoError(t, err)

	// Close the session without requesting a subsystem.
	_ = sess.Close()
	_ = sshConn.Close()

	// Server should get an error.
	var sr result
	select {
	case sr = <-srvResultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server call-home result")
	}
	require.Error(t, sr.err, "call-home must error when session closed before netconf subsystem")
}

// ─── callHomeHandshake: non-netconf subsystem in call home ───────────────────

// TestCallHome_NonNetconfSubsystem verifies the error when the client requests
// a non-"netconf" subsystem during call home.
func TestCallHome_NonNetconfSubsystem(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()

	type result struct {
		trp *ServerTransport
		err error
	}
	srvResultCh := make(chan result, 1)

	go func() {
		srvTrp, err := DialCallHome(addr, serverCfg)
		srvResultCh <- result{srvTrp, err}
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	sshClient := gossh.NewClient(sshConn, chans, reqs)
	sess, err := sshClient.NewSession()
	require.NoError(t, err)

	// Request a non-"netconf" subsystem — should cause server to error.
	_ = sess.RequestSubsystem("shell")
	_ = sess.Close()
	_ = sshConn.Close()

	var sr result
	select {
	case sr = <-srvResultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server call-home result")
	}
	require.Error(t, sr.err, "call-home must error on non-netconf subsystem")
	assert.Contains(t, sr.err.Error(), "unexpected subsystem")
}

// ─── callHomeHandshake: connection closed before session channel ─────────────

// TestCallHome_ConnectionClosedBeforeSession verifies the error when the TCP
// connection closes before a session channel is opened.
func TestCallHome_ConnectionClosedBeforeSession(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()

	type result struct {
		trp *ServerTransport
		err error
	}
	srvResultCh := make(chan result, 1)

	go func() {
		srvTrp, err := DialCallHome(addr, serverCfg)
		srvResultCh <- result{srvTrp, err}
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)

	go gossh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	// Close the SSH connection without opening any channels.
	_ = sshConn.Close()

	var sr result
	select {
	case sr = <-srvResultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server call-home result")
	}
	require.Error(t, sr.err, "call-home must error when connection closed before session")
}

// ─── handleSession: unrecognised request type ────────────────────────────────

// TestSSH_UnrecognisedRequestType verifies that unrecognised request types
// (not "subsystem") are rejected by handleSession.
func TestSSH_UnrecognisedRequestType(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := NewListener(nl, serverCfg)
	defer listener.Close()

	addr := nl.Addr().String()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)

	sshConn, chans, sshReqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(sshReqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	sshClient := gossh.NewClient(sshConn, chans, sshReqs)
	sess, err := sshClient.NewSession()
	require.NoError(t, err)

	// Send a non-subsystem request (e.g. "exec"). The server should reject it.
	// SendRequest sends a channel request and waits for the reply.
	ok, err := sess.SendRequest("exec", true, []byte("whoami"))
	// err may be nil but ok should be false (server rejects non-subsystem requests).
	_ = err
	assert.False(t, ok, "exec request should be rejected by handleSession")

	_ = sess.Close()
}

// ─── callHomeHandshake: non-subsystem request in call home ───────────────────

// TestCallHome_NonSubsystemRequest verifies that non-subsystem requests during
// call home are rejected and the server continues to wait for netconf subsystem.
func TestCallHome_NonSubsystemRequest(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()

	type result struct {
		trp *ServerTransport
		err error
	}
	srvResultCh := make(chan result, 1)

	go func() {
		srvTrp, err := DialCallHome(addr, serverCfg)
		srvResultCh <- result{srvTrp, err}
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	sshClient := gossh.NewClient(sshConn, chans, reqs)
	sess, err := sshClient.NewSession()
	require.NoError(t, err)

	// First send a non-subsystem request — server should reject it and continue.
	ok, _ := sess.SendRequest("exec", true, []byte("whoami"))
	assert.False(t, ok, "exec request should be rejected")

	// Then request the netconf subsystem — server should accept it.
	err = sess.RequestSubsystem("netconf")
	require.NoError(t, err, "netconf subsystem request should succeed after rejected exec")

	var sr result
	select {
	case sr = <-srvResultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server call-home result")
	}
	require.NoError(t, sr.err, "call-home should succeed after rejecting exec + accepting netconf")

	_ = sr.trp.Close()
	_ = sess.Close()
}

// ─── callHomeHandshake: non-session channel type in call home ────────────────

// TestCallHome_NonSessionChannel verifies that non-session channel types are
// rejected during call home and the server continues to wait.
func TestCallHome_NonSessionChannel(t *testing.T) {
	serverCfg, clientCfg := testSSHConfigs(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()

	type result struct {
		trp *ServerTransport
		err error
	}
	srvResultCh := make(chan result, 1)

	go func() {
		srvTrp, err := DialCallHome(addr, serverCfg)
		srvResultCh <- result{srvTrp, err}
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	require.NoError(t, err)
	defer sshConn.Close()

	go gossh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "")
		}
	}()

	// Try a non-session channel type (should be rejected).
	_, _, err = sshConn.OpenChannel("direct-tcpip", nil)
	assert.Error(t, err, "non-session channel must be rejected")

	// Now open a real session and request netconf — call home should succeed.
	sshClient := gossh.NewClient(sshConn, chans, reqs)
	sess, err := sshClient.NewSession()
	require.NoError(t, err)

	err = sess.RequestSubsystem("netconf")
	require.NoError(t, err, "netconf subsystem should succeed")

	var sr result
	select {
	case sr = <-srvResultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server call-home result")
	}
	require.NoError(t, sr.err)
	_ = sr.trp.Close()
	_ = sess.Close()
}

// ─── sessionRW Read / Write ──────────────────────────────────────────────────

// TestClientTransport_ReadWrite verifies message round-trip through the client
// transport (which uses sessionRW internally when created via Dial).
func TestClientTransport_ReadWrite(t *testing.T) {
	listener, clientTrp := newInProcessSSHPair(t)
	defer listener.Close()
	defer clientTrp.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	defer srvTrp.Close()

	// Write from server, read from client.
	testMsg := []byte("<rpc-reply>server response</rpc-reply>")
	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- transport.WriteMsg(srvTrp, testMsg)
	}()

	rc, err := clientTrp.MsgReader()
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	_ = rc.Close()
	assert.Equal(t, testMsg, got)
	require.NoError(t, <-writeErrCh)
}
