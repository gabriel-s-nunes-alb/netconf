// server.go — TLS server transport for NETCONF.
//
// The Listener accepts incoming TCP connections, upgrades each to TLS
// (performing the mutual-auth handshake), and presents each accepted
// connection as a [ServerTransport] via Accept.
//
// # Observability
//
// Every error returned by Accept and ServerTransport methods includes a
// descriptive context prefix ("tls server:"). TLS handshake failures in
// handleConn are discarded silently — they are background noise on a server,
// the same pattern as the SSH transport.
//
// Failure inspection:
//   - `Listener.Accept` blocks until a client completes the TLS handshake or
//     an error occurs; the error value names the failed step.
//   - `go test ./... -v` prints per-test PASS/FAIL.
package tls

import (
	cryptotls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/GabrielNunesIT/netconf/transport"
)

// ServerTransport is a server-side NETCONF transport backed by a TLS
// connection.
//
// It implements transport.Transport and transport.Upgrader. The peer
// certificate chain (extracted from the TLS handshake) is available via
// PeerCertificates for cert-to-name username derivation.
type ServerTransport struct {
	framer    *transport.Framer
	conn      net.Conn // *cryptotls.Conn stored as net.Conn
	peerCerts []*x509.Certificate
}

// PeerCertificates returns the client's certificate chain as presented during
// the TLS handshake. The leaf certificate is at index 0. The slice is nil if
// the client did not present a certificate (i.e., mutual auth was not
// configured or the handshake was unauthenticated).
//
// The returned slice is safe to read; it is not modified after construction.
func (t *ServerTransport) PeerCertificates() []*x509.Certificate {
	return t.peerCerts
}

// MsgReader returns a ReadCloser for exactly one complete NETCONF message.
// Implements transport.Transport.
func (t *ServerTransport) MsgReader() (io.ReadCloser, error) {
	rc, err := t.framer.MsgReader()
	if err != nil {
		return nil, fmt.Errorf("tls server: MsgReader: %w", err)
	}
	return rc, nil
}

// MsgWriter returns a WriteCloser that commits one NETCONF message on Close.
// Implements transport.Transport.
func (t *ServerTransport) MsgWriter() (io.WriteCloser, error) {
	wc, err := t.framer.MsgWriter()
	if err != nil {
		return nil, fmt.Errorf("tls server: MsgWriter: %w", err)
	}
	return wc, nil
}

// Close closes the underlying TLS connection.
// Implements transport.Transport.
func (t *ServerTransport) Close() error {
	if err := t.conn.Close(); err != nil {
		return fmt.Errorf("tls server: close: %w", err)
	}
	return nil
}

// Upgrade switches the transport from EOM to chunked framing.
// Implements transport.Upgrader. Repeated calls are no-ops.
func (t *ServerTransport) Upgrade() {
	t.framer.Upgrade()
}

// ─── Listener ─────────────────────────────────────────────────────────────────

// Listener wraps a net.Listener and serves TLS connections, presenting each
// accepted connection as a *ServerTransport via Accept.
type Listener struct {
	netListener net.Listener
	tlsConfig   *cryptotls.Config
	// transportCh buffers transports produced by background goroutines.
	transportCh chan *ServerTransport
	// errCh carries the first fatal Accept-level error (e.g., net.Listener closed).
	errCh chan error
}

// NewListener wraps netListener with tlsConfig and starts the accept loop in
// the background. The caller must call Accept to obtain transports and Close
// to shut down.
func NewListener(netListener net.Listener, config *cryptotls.Config) *Listener {
	l := &Listener{
		netListener: netListener,
		tlsConfig:   config,
		transportCh: make(chan *ServerTransport, 8),
		errCh:       make(chan error, 1),
	}
	go l.acceptLoop()
	return l
}

// Accept blocks until a client completes the TLS handshake and returns the
// resulting ServerTransport. It returns an error if the Listener has been
// closed or a fatal network error occurred.
func (l *Listener) Accept() (*ServerTransport, error) {
	select {
	case t, ok := <-l.transportCh:
		if !ok {
			return nil, errors.New("tls server: listener closed")
		}
		return t, nil
	case err := <-l.errCh:
		return nil, fmt.Errorf("tls server: accept: %w", err)
	}
}

// Close closes the underlying net.Listener, which causes acceptLoop to exit.
func (l *Listener) Close() error {
	return l.netListener.Close()
}

// acceptLoop accepts TCP connections and dispatches each to handleConn in its
// own goroutine. It exits when the net.Listener is closed.
func (l *Listener) acceptLoop() {
	for {
		conn, err := l.netListener.Accept()
		if err != nil {
			// Send the error to the first waiting Accept call and exit.
			// A closed listener triggers this path.
			select {
			case l.errCh <- err:
			default:
			}
			return
		}
		go l.handleConn(conn)
	}
}

// handleConn upgrades conn to TLS, performs the mutual-auth handshake,
// extracts the peer certificate chain, and delivers a ServerTransport to
// Accept via transportCh. Handshake failures are discarded silently — they
// are background noise on a server (same as the SSH transport pattern).
func (l *Listener) handleConn(conn net.Conn) {
	tlsConn := cryptotls.Server(conn, l.tlsConfig)

	// Handshake must be called explicitly before reading ConnectionState;
	// otherwise PeerCertificates will be empty even for mutual-auth configs.
	if err := tlsConn.Handshake(); err != nil {
		// Discard silently — same pattern as SSH Listener.handleConn.
		_ = tlsConn.Close()
		return
	}

	state := tlsConn.ConnectionState()
	peerCerts := state.PeerCertificates // nil if no client cert

	l.transportCh <- &ServerTransport{
		framer:    transport.NewFramer(tlsConn),
		conn:      tlsConn,
		peerCerts: peerCerts,
	}
}

// ─── Call Home (RFC 8071) ─────────────────────────────────────────────────────

// DialCallHome dials addr (the NETCONF client's call-home listening address),
// performs the TLS server handshake over the outbound TCP connection, and
// returns a *ServerTransport ready for the NETCONF hello exchange.
//
// The caller is the NETCONF server. addr is the NETCONF client's call-home
// listening address (RFC 8071 default port 4335). For tests, use any
// available port obtained from net.Listen("tcp", "127.0.0.1:0").
//
// RFC 8071 inverts TCP direction: the NETCONF server initiates TCP to the
// NETCONF client, but the TLS server/client roles are unchanged — the
// NETCONF server still runs the TLS server protocol over the outbound
// connection. config must include the server certificate; set ClientAuth and
// ClientCAs for mutual authentication.
func DialCallHome(addr string, config *cryptotls.Config) (*ServerTransport, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls server: call home: dial %s: %w", addr, err)
	}

	tlsConn := cryptotls.Server(conn, config)

	// Explicit Handshake() before ConnectionState() — required to populate
	// PeerCertificates (Go's TLS library only populates them after the handshake).
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tls server: call home: handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	peerCerts := state.PeerCertificates // nil if no client cert

	return &ServerTransport{
		framer:    transport.NewFramer(tlsConn),
		conn:      tlsConn,
		peerCerts: peerCerts,
	}, nil
}
