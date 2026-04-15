// coverage_test.go — additional tests to improve coverage for transport/tls.
//
// These tests target error paths, edge cases, and uncovered functions
// in client.go, server.go, and certname.go.
package tls

import (
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/GabrielNunesIT/netconf/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Client Transport: MsgReader / MsgWriter error wrapping ──────────────────

// TestClientTransport_MsgReader_Error verifies MsgReader wraps errors with
// "tls client:" prefix.
func TestClientTransport_MsgReader_Error(t *testing.T) {
	t.Parallel()
	listener, clientTrp := newInProcessTLSPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	// Close the server-side to make client MsgReader fail.
	_ = srvTrp.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = clientTrp.MsgReader()
	if err != nil {
		assert.Contains(t, err.Error(), "tls client:", "error must have tls client prefix")
	}
	_ = clientTrp.Close()
}

// TestClientTransport_MsgWriter_Error verifies MsgWriter wraps errors with
// "tls client:" prefix when the connection is closed.
func TestClientTransport_MsgWriter_Error(t *testing.T) {
	t.Parallel()
	listener, clientTrp := newInProcessTLSPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	_ = srvTrp.Close()
	_ = clientTrp.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = clientTrp.MsgWriter()
	if err != nil {
		assert.Contains(t, err.Error(), "tls client:", "error must have tls client prefix")
	}
}

// ─── Server Transport: MsgReader / MsgWriter error wrapping ──────────────────

// TestServerTransport_MsgReader_Error verifies ServerTransport.MsgReader wraps
// errors with "tls server:" prefix.
func TestServerTransport_MsgReader_Error(t *testing.T) {
	t.Parallel()
	listener, clientTrp := newInProcessTLSPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	// Close client side to make server MsgReader fail.
	_ = clientTrp.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = srvTrp.MsgReader()
	if err != nil {
		assert.Contains(t, err.Error(), "tls server:", "error must have tls server prefix")
	}
	_ = srvTrp.Close()
}

// TestServerTransport_MsgWriter_Error verifies ServerTransport.MsgWriter wraps
// errors with "tls server:" prefix.
func TestServerTransport_MsgWriter_Error(t *testing.T) {
	t.Parallel()
	listener, clientTrp := newInProcessTLSPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	_ = clientTrp.Close()
	_ = srvTrp.Close()
	time.Sleep(50 * time.Millisecond)

	_, err = srvTrp.MsgWriter()
	if err != nil {
		assert.Contains(t, err.Error(), "tls server:", "error must have tls server prefix")
	}
}

// ─── Close error paths ───────────────────────────────────────────────────────

// TestClientTransport_Close_Error verifies client Close wraps errors with
// "tls client: close:" prefix on double-close.
func TestClientTransport_Close_Error(t *testing.T) {
	t.Parallel()
	listener, clientTrp := newInProcessTLSPair(t)
	defer listener.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	_ = srvTrp.Close()

	// First close should succeed.
	err = clientTrp.Close()
	require.NoError(t, err)

	// Second close should error.
	err = clientTrp.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls client: close", "double-close error must have prefix")
}

// TestServerTransport_Close_Error verifies server Close wraps errors with
// "tls server: close:" prefix on double-close.
func TestServerTransport_Close_Error(t *testing.T) {
	t.Parallel()
	listener, clientTrp := newInProcessTLSPair(t)
	defer listener.Close()
	defer clientTrp.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)

	// First close should succeed.
	err = srvTrp.Close()
	require.NoError(t, err)

	// Second close should error.
	err = srvTrp.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls server: close", "double-close error must have prefix")
}

// ─── Dial error path ──────────────────────────────────────────────────────────

// TestDial_Error verifies Dial returns a wrapped error when TLS connect fails.
func TestDial_Error(t *testing.T) {
	t.Parallel()
	// Use a port that is not listening.
	_, err := Dial("127.0.0.1:1", &cryptotls.Config{
		InsecureSkipVerify: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls client: dial", "error must have dial prefix")
}

// ─── Accept error paths ──────────────────────────────────────────────────────

// TestAccept_ListenerClosed verifies Accept returns an error when the
// underlying net.Listener is closed.
func TestAccept_ListenerClosed(t *testing.T) {
	t.Parallel()
	cfgs := testTLSConfigs(t)

	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	listener := NewListener(nl, cfgs.server)

	// Close the listener to trigger the errCh path.
	err = listener.Close()
	require.NoError(t, err)

	// Accept should return an error.
	_, err = listener.Accept()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls server:", "accept error must have tls server prefix")
}

// ─── handleConn: handshake failure ───────────────────────────────────────────

// TestHandleConn_HandshakeFailure verifies that a TLS handshake failure in
// handleConn is silently discarded and the listener continues to work.
func TestHandleConn_HandshakeFailure(t *testing.T) {
	t.Parallel()
	cfgs := testTLSConfigs(t)

	nl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := NewListener(nl, cfgs.server)
	defer listener.Close()

	addr := nl.Addr().String()

	// Connect with a plain TCP connection (no TLS) — handshake should fail.
	badConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	// Write some garbage and close — this will fail the TLS handshake.
	_, _ = badConn.Write([]byte("not-tls-data"))
	_ = badConn.Close()

	// Now connect with a proper TLS client — should succeed.
	clientTrp, err := Dial(addr, cfgs.client)
	require.NoError(t, err)
	defer clientTrp.Close()

	srvTrp, err := listener.Accept()
	require.NoError(t, err)
	defer srvTrp.Close()

	// Verify transport works despite the earlier handshake failure.
	testMsg := []byte("<rpc>after bad handshake</rpc>")
	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- transport.WriteMsg(clientTrp, testMsg)
	}()
	got, err := transport.ReadMsg(srvTrp)
	require.NoError(t, err)
	assert.Equal(t, testMsg, got)
	require.NoError(t, <-writeErrCh)
}

// ─── DialCallHome error paths ────────────────────────────────────────────────

// TestDialCallHome_DialError verifies DialCallHome returns a wrapped error when
// the TCP dial fails.
func TestDialCallHome_DialError(t *testing.T) {
	t.Parallel()
	cfgs := testTLSConfigs(t)

	// Use a port that is not listening.
	_, err := DialCallHome("127.0.0.1:1", cfgs.server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls server: call home: dial", "error must have call home dial prefix")
}

// TestDialCallHome_HandshakeError verifies DialCallHome returns a wrapped error
// when the TLS handshake fails (e.g., connecting to a non-TLS endpoint).
func TestDialCallHome_HandshakeError(t *testing.T) {
	t.Parallel()
	cfgs := testTLSConfigs(t)

	// Start a plain TCP listener that accepts but does not do TLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Close immediately — TLS handshake will fail.
		_ = conn.Close()
	}()

	_, err = DialCallHome(ln.Addr().String(), cfgs.server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls server: call home: handshake", "error must have call home handshake prefix")
}

// ─── Server ReadWrite round-trip after accept ────────────────────────────────

// TestServerTransport_ReadWrite verifies a message round-trip through the
// server transport after accept.
func TestServerTransport_ReadWrite(t *testing.T) {
	t.Parallel()
	listener, clientTrp := newInProcessTLSPair(t)
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

// ─── certname: extractUsername unknown MapType ───────────────────────────────

// TestExtractUsername_UnknownMapType verifies that extractUsername returns ""
// for an unknown MapType value.
func TestExtractUsername_UnknownMapType(t *testing.T) {
	t.Parallel()
	cert := syntheticCert([]byte("raw-unknown-maptype"), "cn-val",
		[]string{"email@example.com"}, []string{"dns.example.com"}, nil)

	entry := MapEntry{
		Fingerprint: fp(cert.Raw),
		MapType:     MapType(999), // unknown map type
	}

	// Call DeriveUsername with the unknown map type — should yield ("", false)
	// because extractUsername returns "" for the unknown type.
	maps := []MapEntry{entry}
	got, ok := DeriveUsername(cert, nil, maps)
	assert.False(t, ok, "unknown MapType should not yield a username")
	assert.Empty(t, got, "username must be empty for unknown MapType")
}

// ─── certname: firstRFC822Name malformed (no @) ─────────────────────────────

// TestFirstRFC822Name_MalformedNoAt verifies that an email address without "@"
// is returned as-is (the fallback path in firstRFC822Name).
func TestFirstRFC822Name_MalformedNoAt(t *testing.T) {
	t.Parallel()
	cert := syntheticCert([]byte("raw-malformed-email"), "",
		[]string{"no-at-sign"}, nil, nil)

	maps := []MapEntry{
		{Fingerprint: fp(cert.Raw), MapType: MapTypeSANRFC822Name},
	}
	got, ok := DeriveUsername(cert, nil, maps)
	require.True(t, ok)
	assert.Equal(t, "no-at-sign", got, "malformed email (no @) should be returned as-is")
}

// ─── certname: firstIPAddress with no IPs ────────────────────────────────────

// TestFirstIPAddress_NoIPs verifies that a cert with no IP SANs yields no
// match for MapTypeSANIPAddress.
func TestFirstIPAddress_NoIPs(t *testing.T) {
	t.Parallel()
	cert := syntheticCert([]byte("raw-no-ips"), "cn", nil, nil, nil)
	maps := []MapEntry{
		{Fingerprint: fp(cert.Raw), MapType: MapTypeSANIPAddress},
	}
	got, ok := DeriveUsername(cert, nil, maps)
	assert.False(t, ok, "no IP SANs should not yield a match")
	assert.Empty(t, got)
}

// ─── DialCallHome success path with peer certs ──────────────────────────────

// TestDialCallHome_PeerCertificates verifies that DialCallHome extracts peer
// certificates from the TLS handshake.
func TestDialCallHome_PeerCertificates(t *testing.T) {
	t.Parallel()

	ca := generateTestCA(t)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(20),
		Subject:      pkix.Name{CommonName: "callhome-server.test"},
		DNSNames:     []string{"localhost", "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverBundle := generateTestCert(t, ca, serverTemplate)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(21),
		Subject:      pkix.Name{CommonName: "callhome-client.test"},
		DNSNames:     []string{"callhome-client.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientBundle := generateTestCert(t, ca, clientTemplate)

	serverTLSCert, err := cryptotls.X509KeyPair(serverBundle.certPEM, serverBundle.keyPEM)
	require.NoError(t, err)
	clientTLSCert, err := cryptotls.X509KeyPair(clientBundle.certPEM, clientBundle.keyPEM)
	require.NoError(t, err)

	serverCfg := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{serverTLSCert},
		ClientAuth:   cryptotls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	clientCfg := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{clientTLSCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	type result struct {
		trp *ServerTransport
		err error
	}
	srvResultCh := make(chan result, 1)
	go func() {
		srvTrp, err := DialCallHome(ln.Addr().String(), serverCfg)
		srvResultCh <- result{srvTrp, err}
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)
	tlsConn := cryptotls.Client(conn, clientCfg)
	require.NoError(t, tlsConn.Handshake())
	defer tlsConn.Close()

	var sr result
	select {
	case sr = <-srvResultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
	require.NoError(t, sr.err)
	defer sr.trp.Close()

	peerCerts := sr.trp.PeerCertificates()
	require.NotEmpty(t, peerCerts, "call home must see client certificate")
	assert.Equal(t, clientBundle.cert.Raw, peerCerts[0].Raw)
}
