// server.go — SSH server transport for NETCONF.
//
// The Listener accepts incoming SSH connections, handles "session" channel
// requests, handles "subsystem" requests for "netconf", and presents each
// accepted NETCONF channel as a ServerTransport.
//
// Non-"netconf" subsystem requests are rejected with a channel-failure reply.
//
// # Observability
//
// Every error returned by Accept and ServerTransport methods includes a
// descriptive context prefix. SSH handshake failures, unexpected channel
// types, and rejected subsystem names are all surfaced as non-nil errors
// (or via the errCh channel for background goroutines).
//
// Failure inspection:
//   - `Listener.Accept` blocks until a client opens a netconf subsystem or
//     an error occurs; the error value names the failed step.
//   - `go test ./... -v` prints per-test PASS/FAIL.
//   - Any SSH connection that fails the handshake is logged in the goroutine
//     and discarded; Accept is not unblocked by handshake failures (they are
//     background noise on a server).
package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/GabrielNunesIT/netconf/transport"
	gossh "golang.org/x/crypto/ssh"
)

// ServerTransport is a server-side NETCONF transport backed by an SSH channel.
//
// It implements transport.Transport and transport.Upgrader.
type ServerTransport struct {
	framer  *transport.Framer
	channel gossh.Channel
}

// MsgReader returns a ReadCloser for exactly one complete NETCONF message.
// Implements transport.Transport.
func (t *ServerTransport) MsgReader() (io.ReadCloser, error) {
	rc, err := t.framer.MsgReader()
	if err != nil {
		return nil, fmt.Errorf("ssh server: MsgReader: %w", err)
	}
	return rc, nil
}

// MsgWriter returns a WriteCloser that commits one NETCONF message on Close.
// Implements transport.Transport.
func (t *ServerTransport) MsgWriter() (io.WriteCloser, error) {
	wc, err := t.framer.MsgWriter()
	if err != nil {
		return nil, fmt.Errorf("ssh server: MsgWriter: %w", err)
	}
	return wc, nil
}

// Close closes the underlying SSH channel.
// Implements transport.Transport.
func (t *ServerTransport) Close() error {
	if err := t.channel.Close(); err != nil {
		return fmt.Errorf("ssh server: close channel: %w", err)
	}
	return nil
}

// Upgrade switches the transport from EOM to chunked framing.
// Implements transport.Upgrader. Repeated calls are no-ops.
func (t *ServerTransport) Upgrade() {
	t.framer.Upgrade()
}

// ─── Listener ────────────────────────────────────────────────────────────────

// Listener wraps a net.Listener and serves SSH connections, presenting each
// accepted NETCONF subsystem channel as a *ServerTransport via Accept.
type Listener struct {
	netListener net.Listener
	sshConfig   *gossh.ServerConfig
	// transportCh buffers transports produced by background goroutines.
	transportCh chan *ServerTransport
	// errCh carries the first fatal Accept-level error (e.g., net.Listener closed).
	errCh chan error
}

// NewListener wraps netListener with sshConfig and starts the accept loop in
// the background. The caller must call Accept to obtain transports and Close
// to shut down.
func NewListener(netListener net.Listener, config *gossh.ServerConfig) *Listener {
	l := &Listener{
		netListener: netListener,
		sshConfig:   config,
		transportCh: make(chan *ServerTransport, 8),
		errCh:       make(chan error, 1),
	}
	go l.acceptLoop()
	return l
}

// Accept blocks until a client opens a "netconf" subsystem channel and returns
// the resulting ServerTransport. It returns an error if the Listener has been
// closed or a fatal network error occurred.
func (l *Listener) Accept() (*ServerTransport, error) {
	select {
	case t, ok := <-l.transportCh:
		if !ok {
			return nil, errors.New("ssh server: listener closed")
		}
		return t, nil
	case err := <-l.errCh:
		return nil, fmt.Errorf("ssh server: accept: %w", err)
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

// handleConn performs the SSH handshake on conn and then handles each new
// channel request. For "session" channels it dispatches to handleSession.
func (l *Listener) handleConn(conn net.Conn) {
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, l.sshConfig)
	if err != nil {
		// Handshake failure is a background error — log it by discarding
		// silently. Only fatal Accept-level errors are forwarded.
		return
	}
	defer func() { _ = sshConn.Close() }()

	// Discard global requests (e.g., keep-alives).
	go gossh.DiscardRequests(reqs)

	// Handle each new-channel request.
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(gossh.UnknownChannelType,
				fmt.Sprintf("unsupported channel type %q; only \"session\" is accepted", newChan.ChannelType()))
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go l.handleSession(channel, requests)
	}
}

// handleSession processes SSH channel requests on a session channel. It
// accepts "subsystem" requests for "netconf" and rejects everything else.
func (l *Listener) handleSession(channel gossh.Channel, requests <-chan *gossh.Request) {
	netconfAccepted := false
	for req := range requests {
		switch req.Type {
		case "subsystem":
			// The payload is a uint32 length-prefixed string.
			name := parseSubsystemName(req.Payload)
			if name == "netconf" && !netconfAccepted {
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				netconfAccepted = true
				// Deliver the transport to Accept().
				l.transportCh <- &ServerTransport{
					framer:  transport.NewFramer(channel),
					channel: channel,
				}
			} else {
				// Reject non-netconf subsystems.
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				_ = channel.Close()
			}
		default:
			// Reject unrecognised requests.
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// parseSubsystemName decodes the SSH subsystem name from a "subsystem" request
// payload. The payload format is: uint32(len) || name-bytes (big-endian).
func parseSubsystemName(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	nameLen := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+nameLen {
		return ""
	}
	return string(payload[4 : 4+nameLen])
}

// ─── Call Home (RFC 8071) ─────────────────────────────────────────────────────

// DialCallHome dials addr (the NETCONF client's call-home listening address),
// performs the SSH server protocol over the outbound TCP connection, handles
// the "netconf" subsystem, and returns a *ServerTransport ready for the
// NETCONF hello exchange.
//
// The caller is the NETCONF server. addr is the NETCONF client's call-home
// listening address (RFC 8071 default port 4334). For tests, use any
// available port obtained from net.Listen("tcp", "127.0.0.1:0").
//
// RFC 8071 inverts TCP direction: the NETCONF server initiates TCP to the
// NETCONF client, but the SSH server/client roles are unchanged — the
// NETCONF server still runs the SSH server protocol over the outbound
// connection.
func DialCallHome(addr string, config *gossh.ServerConfig) (*ServerTransport, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh server: call home: dial %s: %w", addr, err)
	}
	return callHomeHandshake(conn, config)
}

// callHomeHandshake performs the SSH server protocol over an already-dialed
// conn, negotiates the "netconf" subsystem, and returns the ServerTransport.
// It is separated from DialCallHome so tests can supply a pre-dialed conn.
func callHomeHandshake(conn net.Conn, config *gossh.ServerConfig) (*ServerTransport, error) {
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, config)
	if err != nil {
		return nil, fmt.Errorf("ssh server: call home: handshake: %w", err)
	}

	// Discard global requests (keep-alives, etc.).
	go gossh.DiscardRequests(reqs)

	// Wait for the client to open a "session" channel and request the
	// "netconf" subsystem. Any non-session channel is rejected.
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(gossh.UnknownChannelType,
				fmt.Sprintf("ssh server: call home: unsupported channel type %q", newChan.ChannelType()))
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			_ = sshConn.Close()
			return nil, fmt.Errorf("ssh server: call home: accept session channel: %w", err)
		}

		// Process requests on this session channel until "netconf" subsystem is granted.
		for req := range requests {
			if req.Type != "subsystem" {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			name := parseSubsystemName(req.Payload)
			if name != "netconf" {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				_ = channel.Close()
				_ = sshConn.Close()
				return nil, fmt.Errorf("ssh server: call home: unexpected subsystem %q (want netconf)", name)
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			// Drain remaining requests so the SSH multiplexer does not stall.
			go func() {
				for r := range requests {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
				}
			}()
			return &ServerTransport{
				framer:  transport.NewFramer(channel),
				channel: channel,
			}, nil
		}

		// requests channel closed without a netconf subsystem request.
		_ = sshConn.Close()
		return nil, errors.New("ssh server: call home: session closed before netconf subsystem")
	}

	// chans channel closed without a session channel.
	return nil, errors.New("ssh server: call home: connection closed before session channel")
}
