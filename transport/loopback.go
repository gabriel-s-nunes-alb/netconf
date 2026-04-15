// Loopback — in-process transport pair for tests.

package transport

import (
	"fmt"
	"io"
)

// LoopbackTransport is one end of an in-process loopback pair. It wraps a
// Framer whose underlying ReadWriter is an io.Pipe pair — writes from the
// remote end become reads on this end, and vice versa.
//
// LoopbackTransport satisfies both transport.Transport and transport.Upgrader.
type LoopbackTransport struct {
	framer *Framer
	// closer tears down both directions (write end of our pipe + read end of
	// the remote pipe). Stored as a single func so Close() is idempotent.
	closer func() error
}

// NewLoopback creates a matched pair of in-process transports.
//
//	client, server := transport.NewLoopback()
//
// Bytes written by client become readable by server and vice versa.
// Both transports start in EOM mode (pre-hello default per RFC 6241 §8.1).
func NewLoopback() (*LoopbackTransport, *LoopbackTransport) {
	// clientW → serverR : client writes, server reads
	serverR, clientW := io.Pipe()
	// serverW → clientR : server writes, client reads
	clientR, serverW := io.Pipe()

	clientRW := &pipeReadWriter{r: clientR, w: clientW}
	serverRW := &pipeReadWriter{r: serverR, w: serverW}

	clientT := &LoopbackTransport{
		framer: NewFramer(clientRW),
		closer: func() error {
			e1 := clientW.Close()
			e2 := clientR.Close()
			if e1 != nil {
				return e1
			}
			return e2
		},
	}
	serverT := &LoopbackTransport{
		framer: NewFramer(serverRW),
		closer: func() error {
			e1 := serverW.Close()
			e2 := serverR.Close()
			if e1 != nil {
				return e1
			}
			return e2
		},
	}
	return clientT, serverT
}

// MsgReader returns a ReadCloser for exactly one complete NETCONF message.
// Implements Transport.
func (t *LoopbackTransport) MsgReader() (io.ReadCloser, error) {
	return t.framer.MsgReader()
}

// MsgWriter returns a WriteCloser whose Close commits the message.
// Implements Transport.
func (t *LoopbackTransport) MsgWriter() (io.WriteCloser, error) {
	return t.framer.MsgWriter()
}

// Close tears down the underlying pipe pair. After Close, all further calls
// to MsgReader and MsgWriter return errors (io.ErrClosedPipe from the pipe).
// Implements Transport.
func (t *LoopbackTransport) Close() error {
	return t.closer()
}

// Upgrade switches this end of the loopback from EOM to chunked framing.
// Implements Upgrader. Repeated calls are no-ops.
func (t *LoopbackTransport) Upgrade() {
	t.framer.Upgrade()
}

// ── pipeReadWriter ────────────────────────────────────────────────────────────

// pipeReadWriter combines separate read and write ends of io.Pipes into a
// single io.ReadWriter so the Framer can wrap it uniformly.
type pipeReadWriter struct {
	r io.Reader
	w io.Writer
}

func (p *pipeReadWriter) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeReadWriter) Write(b []byte) (int, error) { return p.w.Write(b) }

// ── helper: write a complete message via MsgWriter ───────────────────────────

// WriteMsg is a convenience function that obtains a MsgWriter, writes all of
// msg, then calls Close to commit. It is used internally by loopback tests.
// A non-nil error means the message was NOT committed.
func WriteMsg(t Transport, msg []byte) error {
	w, err := t.MsgWriter()
	if err != nil {
		return fmt.Errorf("WriteMsg: MsgWriter: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close() // best-effort cleanup
		return fmt.Errorf("WriteMsg: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("WriteMsg: close (commit): %w", err)
	}
	return nil
}

// ReadMsg is a convenience function that obtains a MsgReader, reads the
// complete message body, and closes the reader. Used internally by tests.
func ReadMsg(t Transport) ([]byte, error) {
	r, err := t.MsgReader()
	if err != nil {
		return nil, fmt.Errorf("ReadMsg: MsgReader: %w", err)
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("ReadMsg: read body: %w", err)
	}
	return data, nil
}
