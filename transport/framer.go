// Framer — EOM and chunked framing for RFC 6242.

package transport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// eomDelimiter is the end-of-message sentinel for base:1.0 framing.
const eomDelimiter = "]]>]]>"

// maxEOMMessageSize is the maximum accepted NETCONF message size in EOM mode.
// This bounds memory use when reading until the EOM delimiter.
const maxEOMMessageSize = 16 * 1024 * 1024 // 16 MiB

// maxChunkSize is the maximum legal chunk data size per RFC 6242 §4.2:
// chunk-size = 1*DIGIT, where the value fits in uint32.
const maxChunkSize = 4294967295 // max uint32

// framingMode distinguishes the two supported framing modes.
type framingMode int

const (
	modeEOM     framingMode = iota // base:1.0 end-of-message framing
	modeChunked                    // base:1.1 chunked framing
)

// bufPool pools bytes.Buffer objects to reduce per-message allocations in the
// EOM read path and both write paths. Callers must Reset() before use.
var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func getBuf() *bytes.Buffer {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

func putBuf(b *bytes.Buffer) {
	// Discard large buffers to avoid keeping multi-MB slices alive in the pool.
	if b.Cap() > 2*1024*1024 {
		return
	}
	bufPool.Put(b)
}

// Framer implements the Transport interface, adding Upgrade() to satisfy the
// Upgrader interface. It wraps an io.ReadWriter and manages all framing.
//
// Concurrent MsgReader or concurrent MsgWriter calls are not safe; the caller
// (Session) serialises access per direction.
type Framer struct {
	mu   sync.Mutex  // protects mode only; read/write are single-goroutine
	mode framingMode // current framing mode

	rw io.ReadWriter // underlying byte stream
	br *bufio.Reader // buffered reader over rw (read side)
}

// NewFramer creates a Framer that starts in EOM mode (base:1.0).
// The underlying ReadWriter must remain valid for the lifetime of the Framer.
func NewFramer(rw io.ReadWriter) *Framer {
	return &Framer{
		mode: modeEOM,
		rw:   rw,
		br:   bufio.NewReaderSize(rw, 65536),
	}
}

// Upgrade switches the Framer from EOM framing to chunked framing.
// It is safe to call multiple times; repeated calls are no-ops.
func (f *Framer) Upgrade() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mode == modeChunked {
		return
	}
	f.mode = modeChunked
}

// currentMode returns the current framing mode safely.
func (f *Framer) currentMode() framingMode {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode
}

// ── MsgReader ────────────────────────────────────────────────────────────────

// MsgReader returns a ReadCloser that delivers exactly one complete NETCONF
// message, stripped of framing bytes. The caller must drain and Close it
// before calling MsgReader again.
func (f *Framer) MsgReader() (io.ReadCloser, error) {
	switch f.currentMode() {
	case modeEOM:
		return f.eomReader()
	case modeChunked:
		return f.chunkedReader()
	default:
		return nil, fmt.Errorf("framer: unknown framing mode %d", f.currentMode())
	}
}

// eomReader reads from the buffered stream until the "]]>]]>" delimiter is
// found, then returns the message body (excluding the delimiter) as a
// ReadCloser backed by a bytes.Reader. Uses a pooled bytes.Buffer for
// accumulation.
//
// The delimiter may span multiple underlying reads; bufio.Reader handles
// the buffering so we scan the accumulated bytes correctly.
func (f *Framer) eomReader() (io.ReadCloser, error) {
	buf := getBuf()
	delim := []byte(eomDelimiter)

	for {
		b, err := f.br.ReadByte()
		if err != nil {
			hadData := buf.Len() > 0
			putBuf(buf)
			if errors.Is(err, io.EOF) && hadData {
				return nil, errors.New("eom: unexpected EOF before ]]>]]> delimiter")
			}
			return nil, fmt.Errorf("eom: read: %w", err)
		}

		if buf.Len()+1 > maxEOMMessageSize {
			putBuf(buf)
			return nil, fmt.Errorf("eom: message exceeds maximum size of %d bytes", maxEOMMessageSize)
		}
		buf.WriteByte(b)

		// Check if the tail of buf matches the delimiter.
		if buf.Len() >= len(delim) {
			tail := buf.Bytes()[buf.Len()-len(delim):]
			if bytes.Equal(tail, delim) {
				// Copy the message body (excluding delimiter) to a fresh slice,
				// then return the pooled buffer immediately.
				msg := make([]byte, buf.Len()-len(delim))
				copy(msg, buf.Bytes())
				putBuf(buf)
				return io.NopCloser(bytes.NewReader(msg)), nil
			}
		}
	}
}

// chunkedReader returns a streaming ReadCloser that reads RFC 6242 §4.2
// chunked framing directly from the buffered stream without accumulating
// all chunk data into an intermediate buffer.
//
// The returned reader reads chunk-by-chunk: each Read call draws bytes from
// the current chunk in the bufio.Reader. When a chunk is exhausted, the next
// chunk header is parsed transparently. After the end-of-chunks marker is
// consumed, Read returns io.EOF.
//
// The caller must Close the reader before calling MsgReader again. Close
// drains any unread bytes so the stream position is correct for the next
// message.
func (f *Framer) chunkedReader() (io.ReadCloser, error) {
	// Read the first chunk header eagerly so that framing errors surface at
	// MsgReader time (consistent with eomReader behaviour) rather than at the
	// first Read call.
	size, end, err := readChunkHeader(f.br)
	if err != nil {
		return nil, err
	}
	r := &chunkedStreamReader{br: f.br}
	if end {
		// Empty message (end-of-chunks immediately) — return a closed reader.
		r.done = true
	} else {
		r.remaining = size
	}
	return r, nil
}

// chunkedStreamReader is an io.ReadCloser that reads RFC 6242 chunked data
// directly from a bufio.Reader without intermediate buffering.
type chunkedStreamReader struct {
	br        *bufio.Reader
	remaining int64 // bytes remaining in the current chunk; 0 means fetch next header
	done      bool  // true after the end-of-chunks marker has been consumed
}

// Read reads up to len(p) bytes from the current chunk. When the current chunk
// is exhausted it transparently reads the next chunk header. Returns io.EOF
// after the end-of-chunks marker.
func (r *chunkedStreamReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}

	// Advance to the next chunk header when the current chunk is empty.
	for r.remaining == 0 {
		size, end, err := readChunkHeader(r.br)
		if err != nil {
			return 0, err
		}
		if end {
			r.done = true
			return 0, io.EOF
		}
		r.remaining = size
	}

	// Read up to remaining bytes from the current chunk.
	toRead := int64(len(p))
	toRead = min(toRead, r.remaining)
	n, err := r.br.Read(p[:toRead])
	r.remaining -= int64(n)
	return n, err
}

// Close drains any unread bytes in the current and remaining chunks so that
// the next MsgReader call finds the stream positioned at the start of the
// next message. Close is idempotent.
func (r *chunkedStreamReader) Close() error {
	if r.done {
		return nil
	}
	_, err := io.Copy(io.Discard, r)
	return err
}

// readChunkHeader reads one RFC 6242 chunk header from br.
//
// A chunk header is either:
//   - "\n#<size>\n"  — returns (size, false, nil)
//   - "\n##\n"       — returns (0, true, nil)  [end-of-chunks]
func readChunkHeader(br *bufio.Reader) (size int64, end bool, err error) {
	nl, err := br.ReadByte()
	if err != nil {
		return 0, false, fmt.Errorf("chunked: read chunk header start: %w", err)
	}
	if nl != '\n' {
		return 0, false, fmt.Errorf("chunked: expected '\\n' at chunk start, got %q", nl)
	}

	hash, err := br.ReadByte()
	if err != nil {
		return 0, false, fmt.Errorf("chunked: read '#' marker: %w", err)
	}
	if hash != '#' {
		return 0, false, fmt.Errorf("chunked: expected '#' after '\\n', got %q", hash)
	}

	next, err := br.ReadByte()
	if err != nil {
		return 0, false, fmt.Errorf("chunked: read after '#': %w", err)
	}

	if next == '#' {
		// End-of-chunks: consume the trailing '\n'.
		trailingNL, err := br.ReadByte()
		if err != nil {
			return 0, false, fmt.Errorf("chunked: read trailing '\\n' after '##': %w", err)
		}
		if trailingNL != '\n' {
			return 0, false, fmt.Errorf("chunked: expected '\\n' after '\\n##', got %q", trailingNL)
		}
		return 0, true, nil
	}

	if next < '0' || next > '9' {
		return 0, false, fmt.Errorf("chunked: chunk header: expected digit after '#', got %q", next)
	}
	sizeBuf := []byte{next}
	for {
		c, err := br.ReadByte()
		if err != nil {
			return 0, false, fmt.Errorf("chunked: read chunk size: %w", err)
		}
		if c == '\n' {
			break
		}
		if c < '0' || c > '9' {
			return 0, false, fmt.Errorf("chunked: chunk size contains non-digit %q", c)
		}
		sizeBuf = append(sizeBuf, c)
	}

	size64, err := strconv.ParseUint(string(sizeBuf), 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("chunked: chunk size %q is not a valid uint: %w", string(sizeBuf), err)
	}
	if size64 == 0 {
		return 0, false, errors.New("chunked: chunk size 0 is invalid (RFC 6242 §4.2 requires size ≥ 1)")
	}
	if size64 > maxChunkSize {
		return 0, false, fmt.Errorf("chunked: chunk size %d exceeds maximum %d", size64, maxChunkSize)
	}
	return int64(size64), false, nil
}

// ── MsgWriter ────────────────────────────────────────────────────────────────

// MsgWriter returns a WriteCloser. The caller writes the complete message body
// and then calls Close to commit (frame and flush) it to the peer.
func (f *Framer) MsgWriter() (io.WriteCloser, error) {
	switch f.currentMode() {
	case modeEOM:
		return &eomWriter{w: f.rw, buf: getBuf()}, nil
	case modeChunked:
		return &chunkedWriter{w: f.rw, buf: getBuf()}, nil
	default:
		return nil, fmt.Errorf("framer: unknown framing mode %d", f.currentMode())
	}
}

// eomWriter buffers the message body using a pooled bytes.Buffer. On Close it
// writes body + "]]>]]>" to the underlying writer and returns the buffer to
// the pool.
type eomWriter struct {
	w   io.Writer
	buf *bytes.Buffer // from bufPool
}

func (w *eomWriter) Write(p []byte) (int, error) {
	if w.buf == nil {
		return 0, errors.New("eom: write on closed writer")
	}
	return w.buf.Write(p)
}

// Close frames the accumulated body with the EOM delimiter, flushes it, and
// returns the buffer to the pool.
func (w *eomWriter) Close() error {
	if w.buf == nil {
		return nil
	}
	w.buf.WriteString(eomDelimiter)
	_, err := w.w.Write(w.buf.Bytes())
	putBuf(w.buf)
	w.buf = nil
	if err != nil {
		return fmt.Errorf("eom: write message+delimiter: %w", err)
	}
	return nil
}

// chunkedWriter buffers the message body using a pooled bytes.Buffer. On Close
// it encodes and writes the message as a single chunk followed by the
// end-of-chunks marker, then returns the buffer to the pool.
//
// RFC 6242 §4.2 grammar (simplified for single-chunk messages):
//
//	"\n#" chunk-size "\n" chunk-data "\n##\n"
type chunkedWriter struct {
	w   io.Writer
	buf *bytes.Buffer // from bufPool
}

func (w *chunkedWriter) Write(p []byte) (int, error) {
	if w.buf == nil {
		return 0, errors.New("chunked: write on closed writer")
	}
	return w.buf.Write(p)
}

// Close encodes the buffered body as chunked framing, flushes, and returns the
// buffer to the pool.
func (w *chunkedWriter) Close() error {
	if w.buf == nil {
		return nil
	}
	var out strings.Builder

	if w.buf.Len() > 0 {
		size := w.buf.Len()
		out.WriteString("\n#")
		out.WriteString(strconv.Itoa(size))
		out.WriteByte('\n')
		out.Write(w.buf.Bytes())
	}
	// End-of-chunks marker.
	out.WriteString("\n##\n")

	putBuf(w.buf)
	w.buf = nil

	_, err := io.WriteString(w.w, out.String())
	if err != nil {
		return fmt.Errorf("chunked: write framed message: %w", err)
	}
	return nil
}

// ── Framer lifecycle ──────────────────────────────────────────────────────────

// Close is a no-op on the Framer itself. The caller (LoopbackTransport, SSH
// transport, etc.) owns the underlying ReadWriter and is responsible for
// closing it.
func (f *Framer) Close() error { return nil }
