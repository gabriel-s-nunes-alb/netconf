// Package ssh provides SSH transport implementations for NETCONF.
//
// NETCONF over SSH is mandated by RFC 6242, using the SSH subsystem name
// "netconf". This package wraps golang.org/x/crypto/ssh channels as
// transport.Transport + transport.Upgrader implementations for both
// production use (Dial) and in-process tests (NewClientTransport).
//
// # Observability
//
// Every error returned by MsgReader, MsgWriter, and Close includes descriptive
// context prefixed with "ssh client:" so log lines identify the layer.
// No credentials or secrets pass through this layer after the SSH handshake;
// session-ids and capability URNs are safe to log verbatim.
//
// Failure inspection:
//   - Dial errors name the address and the failed step (dial TCP, SSH
//     handshake, new session, or request subsystem).
//   - A closed channel yields io.EOF from MsgReader; treat any non-nil error
//     as a permanent transport failure and close the session.
//   - `go test ./... -v` prints per-test PASS/FAIL.
package ssh

import (
	"fmt"
	"io"
	"net"

	"github.com/GabrielNunesIT/netconf/transport"
	gossh "golang.org/x/crypto/ssh"
)

// Transport is an SSH-backed NETCONF client transport.
//
// It wraps a single SSH channel opened for the "netconf" subsystem and
// exposes both transport.Transport and transport.Upgrader so the Session layer
// can switch framing after the hello exchange.
type Transport struct {
	framer  *transport.Framer
	channel io.Closer  // gossh.Channel (for NewClientTransport) or *sessionRW (for Dial)
	conn    gossh.Conn // non-nil only when created via Dial
}

// NewClientTransport wraps a pre-established SSH gossh.Channel as a NETCONF
// transport. The channel must already be open for the "netconf" subsystem.
//
// This constructor is intended for in-process tests that set up SSH
// connections over net.Pipe(). Production code should use Dial.
func NewClientTransport(channel gossh.Channel) *Transport {
	return &Transport{
		framer:  transport.NewFramer(channel),
		channel: channel,
	}
}

// Dial opens a TCP connection to addr, performs the SSH handshake, requests a
// "netconf" subsystem channel, and returns the resulting transport.
// addr must be in "host:port" form.
func Dial(addr string, config *gossh.ClientConfig) (*Transport, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh client: dial %s: %w", addr, err)
	}
	return DialConn(conn, addr, config)
}

// DialConn performs the SSH handshake over an already-established conn,
// requests a "netconf" subsystem channel, and returns the resulting transport.
//
// addr is used only in error messages; it does not need to match the actual
// remote address. This function is useful for call home (RFC 8071), where the
// transport layer provides a pre-accepted net.Conn rather than dialing TCP.
func DialConn(conn net.Conn, addr string, config *gossh.ClientConfig) (*Transport, error) {
	return handshakeAndOpenSubsystem(conn, addr, config)
}

// handshakeAndOpenSubsystem completes the SSH handshake over conn and opens
// the "netconf" subsystem channel. It is separated from Dial so tests can
// supply a net.Pipe() connection instead of a real TCP socket.
func handshakeAndOpenSubsystem(conn net.Conn, addr string, config *gossh.ClientConfig) (*Transport, error) {
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, fmt.Errorf("ssh client: handshake with %s: %w", addr, err)
	}

	// Discard global SSH requests (keep-alives etc.) and any server-initiated
	// channel requests so the multiplexer does not stall.
	go gossh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(gossh.UnknownChannelType, "client does not accept inbound channels")
		}
	}()

	sshClient := gossh.NewClient(sshConn, chans, reqs)
	rw, err := openNetconfSubsystem(sshClient)
	if err != nil {
		_ = sshConn.Close()
		return nil, fmt.Errorf("ssh client: open netconf subsystem at %s: %w", addr, err)
	}

	return &Transport{
		framer:  transport.NewFramer(rw),
		channel: rw,
		conn:    sshConn,
	}, nil
}

// sessionRW adapts a gossh.Session's separate stdin/stdout into a single
// io.ReadWriteCloser for the Framer. Used only by Dial.
type sessionRW struct {
	sess   *gossh.Session
	stdout io.Reader
	stdin  io.WriteCloser
}

func (s *sessionRW) Read(p []byte) (int, error)  { return s.stdout.Read(p) }
func (s *sessionRW) Write(p []byte) (int, error) { return s.stdin.Write(p) }
func (s *sessionRW) Close() error                { return s.sess.Close() }

// openNetconfSubsystem opens a new SSH session on client, requests the
// "netconf" subsystem, and returns a sessionRW bridging the session's
// stdin/stdout.
func openNetconfSubsystem(client *gossh.Client) (*sessionRW, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new SSH session: %w", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	if err := sess.RequestSubsystem("netconf"); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("request netconf subsystem: %w", err)
	}

	return &sessionRW{sess: sess, stdout: stdout, stdin: stdin}, nil
}

// MsgReader returns a ReadCloser for exactly one complete NETCONF message.
// Implements transport.Transport.
func (t *Transport) MsgReader() (io.ReadCloser, error) {
	rc, err := t.framer.MsgReader()
	if err != nil {
		return nil, fmt.Errorf("ssh client: MsgReader: %w", err)
	}
	return rc, nil
}

// MsgWriter returns a WriteCloser that commits one NETCONF message on Close.
// Implements transport.Transport.
func (t *Transport) MsgWriter() (io.WriteCloser, error) {
	wc, err := t.framer.MsgWriter()
	if err != nil {
		return nil, fmt.Errorf("ssh client: MsgWriter: %w", err)
	}
	return wc, nil
}

// Close closes the SSH channel (and the SSH connection if created via Dial).
// Implements transport.Transport.
func (t *Transport) Close() error {
	err1 := t.channel.Close()
	var err2 error
	if t.conn != nil {
		err2 = t.conn.Close()
	}
	if err1 != nil {
		return fmt.Errorf("ssh client: close channel: %w", err1)
	}
	if err2 != nil {
		return fmt.Errorf("ssh client: close connection: %w", err2)
	}
	return nil
}

// Upgrade switches the transport from EOM to chunked framing.
// Implements transport.Upgrader. Repeated calls are no-ops.
func (t *Transport) Upgrade() {
	t.framer.Upgrade()
}
