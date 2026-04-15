package transport_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/GabrielNunesIT/netconf/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failWriter satisfies io.ReadWriter; Write always returns an error.
type failWriter struct{}

func (f *failWriter) Read(p []byte) (int, error)  { return 0, io.EOF }
func (f *failWriter) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

// readOnlyRW wraps a byte slice as an io.ReadWriter whose Write is a no-op
// discard. Used to feed pre-encoded wire bytes into NewFramer for decode tests
// (strings.NewReader is read-only and does not satisfy io.ReadWriter).
type readOnlyRW struct{ r *bytes.Reader }

func newReadOnlyRW(b []byte) *readOnlyRW           { return &readOnlyRW{r: bytes.NewReader(b)} }
func (ro *readOnlyRW) Read(p []byte) (int, error)  { return ro.r.Read(p) }
func (ro *readOnlyRW) Write(p []byte) (int, error) { return len(p), nil } // discard

// ── helpers ───────────────────────────────────────────────────────────────────

// framerRoundTrip writes msg through framer's MsgWriter, then reads it back
// through MsgReader. The Framer must wrap an io.ReadWriter that supports
// round-tripping (e.g. *bytes.Buffer).
func framerRoundTrip(t *testing.T, framer *transport.Framer, msg []byte) []byte {
	t.Helper()
	w, err := framer.MsgWriter()
	require.NoError(t, err, "MsgWriter should not error")
	_, err = w.Write(msg)
	require.NoError(t, err, "Write body should not error")
	require.NoError(t, w.Close(), "Close (commit) should not error")

	r, err := framer.MsgReader()
	require.NoError(t, err, "MsgReader should not error")
	defer r.Close()

	got, err := io.ReadAll(r)
	require.NoError(t, err, "ReadAll should not error")
	return got
}

// ── EOM mode: encoding ────────────────────────────────────────────────────────

func TestEOM_MsgWriter_AppendsDelimiter(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)

	w, err := framer.MsgWriter()
	require.NoError(t, err)
	_, err = w.Write([]byte("<hello/>"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	raw := buf.String()
	assert.True(t, strings.HasSuffix(raw, "]]>]]>"),
		"EOM framer must append ]]>]]> after message body; got: %q", raw)
	assert.Contains(t, raw, "<hello/>", "message body must be present")
}

func TestEOM_MsgWriter_EmptyBody(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)

	w, err := framer.MsgWriter()
	require.NoError(t, err)
	// Write nothing — empty message.
	require.NoError(t, w.Close())

	assert.Equal(t, "]]>]]>", buf.String(),
		"empty body should still produce the delimiter")
}

// ── EOM mode: decoding ────────────────────────────────────────────────────────

func TestEOM_MsgReader_StripDelimiter(t *testing.T) {
	t.Parallel()
	wire := []byte("<rpc message-id=\"1\"><get/></rpc>]]>]]>")
	framer := transport.NewFramer(newReadOnlyRW(wire))

	r, err := framer.MsgReader()
	require.NoError(t, err)
	defer r.Close()

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "<rpc message-id=\"1\"><get/></rpc>", string(got),
		"MsgReader must strip the ]]>]]> delimiter")
}

func TestEOM_MsgReader_UnexpectedEOF(t *testing.T) {
	t.Parallel()
	// Message without terminating delimiter → should error.
	framer := transport.NewFramer(newReadOnlyRW([]byte("<hello/>")))
	_, err := framer.MsgReader()
	require.Error(t, err, "missing delimiter must produce an error")
	assert.Contains(t, err.Error(), "EOF",
		"error should mention EOF")
}

func TestEOM_MsgReader_OversizedMessage_Error(t *testing.T) {
	t.Parallel()

	// transport/framer.go enforces a 16 MiB EOM read limit.
	oversized := strings.Repeat("x", 16*1024*1024+1)
	framer := transport.NewFramer(newReadOnlyRW([]byte(oversized + "]]>]]>")))

	_, err := framer.MsgReader()
	require.Error(t, err, "oversized EOM message must return an error")
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

// ── EOM mode: round-trip ──────────────────────────────────────────────────────

func TestEOM_RoundTrip_Single(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)

	msg := []byte("<hello><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>")
	got := framerRoundTrip(t, framer, msg)
	assert.Equal(t, msg, got, "EOM round-trip must preserve message body")
}

func TestEOM_RoundTrip_MultipleMessages(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)

	messages := []string{
		"<hello/>",
		"<rpc message-id=\"1\"><get/></rpc>",
		"<rpc-reply message-id=\"1\"><ok/></rpc-reply>",
	}

	// Write all messages.
	for _, m := range messages {
		w, err := framer.MsgWriter()
		require.NoError(t, err)
		_, err = w.Write([]byte(m))
		require.NoError(t, err)
		require.NoError(t, w.Close())
	}

	// Read all messages back.
	for i, expected := range messages {
		r, err := framer.MsgReader()
		require.NoError(t, err, "MsgReader for message %d", i)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		assert.Equal(t, expected, string(got), "message %d must match", i)
	}
}

// ── EOM edge case: body containing the delimiter ───────────────────────────────
//
// In RFC 6241 base:1.0 framing, the "]]>]]>" sequence is illegal inside a
// message body. The EOM reader treats the first occurrence as the end-of-
// message sentinel regardless. This test documents that behaviour.

func TestEOM_BodyContainsDelimiter_SplitsAtFirst(t *testing.T) {
	t.Parallel()
	// Wire: two "messages" where the first body itself contains ]]>]]>.
	// The reader treats the first ]]>]]> as EOM sentinel: body1 = "BEFORE",
	// and the remainder "AFTER]]>]]>" is the next message.
	wire := []byte("BEFORE]]>]]>AFTER]]>]]>")
	framer := transport.NewFramer(newReadOnlyRW(wire))

	r1, err := framer.MsgReader()
	require.NoError(t, err)
	got1, err := io.ReadAll(r1)
	require.NoError(t, err)
	require.NoError(t, r1.Close())
	assert.Equal(t, "BEFORE", string(got1),
		"EOM reader must split at first ]]>]]>")

	r2, err := framer.MsgReader()
	require.NoError(t, err)
	got2, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.NoError(t, r2.Close())
	assert.Equal(t, "AFTER", string(got2))
}

// ── Chunked mode: encoding ────────────────────────────────────────────────────

func TestChunked_MsgWriter_Format(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)
	framer.Upgrade()

	msg := []byte("<hello/>")
	w, err := framer.MsgWriter()
	require.NoError(t, err)
	_, err = w.Write(msg)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	raw := buf.String()
	// Expected: "\n#8\n<hello/>\n##\n"
	expected := fmt.Sprintf("\n#%d\n%s\n##\n", len(msg), msg)
	assert.Equal(t, expected, raw,
		"chunked writer must produce \\n#<size>\\n<data>\\n##\\n")
}

func TestChunked_MsgWriter_EmptyBody(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)
	framer.Upgrade()

	w, err := framer.MsgWriter()
	require.NoError(t, err)
	// Write nothing.
	require.NoError(t, w.Close())

	// Empty body → end-of-chunks only (no chunk header).
	assert.Equal(t, "\n##\n", buf.String(),
		"empty body should produce only the end-of-chunks marker")
}

// ── Chunked mode: decoding ────────────────────────────────────────────────────

func TestChunked_MsgReader_SingleChunk(t *testing.T) {
	t.Parallel()
	msg := "<get/>"
	wire := fmt.Appendf(nil, "\n#%d\n%s\n##\n", len(msg), msg)
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	r, err := framer.MsgReader()
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.Equal(t, msg, string(got))
}

func TestChunked_MsgReader_MultipleChunks(t *testing.T) {
	t.Parallel()
	// Two chunks concatenated before the end-of-chunks marker.
	part1 := "<rpc message-id=\"1\">"
	part2 := "<get/></rpc>"
	wire := fmt.Appendf(nil, "\n#%d\n%s\n#%d\n%s\n##\n",
		len(part1), part1, len(part2), part2)

	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	r, err := framer.MsgReader()
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.Equal(t, part1+part2, string(got),
		"multi-chunk message must be reassembled in order")
}

// ── Chunked mode: round-trip ──────────────────────────────────────────────────

func TestChunked_RoundTrip_Single(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)
	framer.Upgrade()

	msg := []byte("<rpc-reply message-id=\"1\"><ok/></rpc-reply>")
	got := framerRoundTrip(t, framer, msg)
	assert.Equal(t, msg, got)
}

func TestChunked_RoundTrip_MultipleMessages(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)
	framer.Upgrade()

	messages := []string{
		"<rpc message-id=\"1\"><get/></rpc>",
		"<rpc message-id=\"2\"><get-config><source><running/></source></get-config></rpc>",
		"<rpc-reply message-id=\"1\"><ok/></rpc-reply>",
	}

	for _, m := range messages {
		w, err := framer.MsgWriter()
		require.NoError(t, err)
		_, err = w.Write([]byte(m))
		require.NoError(t, err)
		require.NoError(t, w.Close())
	}

	for i, expected := range messages {
		r, err := framer.MsgReader()
		require.NoError(t, err, "MsgReader for message %d", i)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		assert.Equal(t, expected, string(got), "message %d must match", i)
	}
}

// ── Chunked mode: edge cases ──────────────────────────────────────────────────

func TestChunked_LargeMessage_ChunkSizeHeader(t *testing.T) {
	t.Parallel()
	// 1 MiB message — verify chunk size in header is correct.
	msg := make([]byte, 1<<20)
	for i := range msg {
		msg[i] = 'x'
	}
	buf := &bytes.Buffer{}
	framer := transport.NewFramer(buf)
	framer.Upgrade()

	w, err := framer.MsgWriter()
	require.NoError(t, err)
	_, err = w.Write(msg)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	raw := buf.Bytes()
	expectedPrefix := fmt.Appendf(nil, "\n#%d\n", len(msg))
	assert.True(t, bytes.HasPrefix(raw, expectedPrefix),
		"chunk header must carry the exact byte length")

	// Also verify decode.
	framer2 := transport.NewFramer(newReadOnlyRW(raw))
	framer2.Upgrade()
	r, err := framer2.MsgReader()
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.Equal(t, msg, got)
}

func TestChunked_MsgReader_ZeroSizeChunk_Error(t *testing.T) {
	t.Parallel()
	// Chunk size = 0 is illegal per RFC 6242 §4.2.
	wire := []byte("\n#0\ndata\n##\n")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	_, err := framer.MsgReader()
	require.Error(t, err, "zero-size chunk must return an error")
	assert.Contains(t, err.Error(), "0",
		"error should mention the invalid size")
}

func TestChunked_MsgReader_NonNumericSize_Error(t *testing.T) {
	t.Parallel()
	// Chunk size header with non-digits.
	wire := []byte("\n#abc\ndata\n##\n")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	_, err := framer.MsgReader()
	require.Error(t, err, "non-numeric chunk size must return an error")
}

func TestChunked_MsgReader_MissingLeadingNewline_Error(t *testing.T) {
	t.Parallel()
	// Frame starting with '#' instead of '\n' is malformed.
	wire := []byte("#5\nhello\n##\n")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	_, err := framer.MsgReader()
	require.Error(t, err, "missing leading \\n must return an error")
}

func TestChunked_MsgReader_MissingHash_Error(t *testing.T) {
	t.Parallel()
	// Frame has '\n' but next byte is not '#'.
	wire := []byte("\nXnotachunk")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	_, err := framer.MsgReader()
	require.Error(t, err, "missing '#' after '\\n' must return an error")
}

// ── Upgrade ───────────────────────────────────────────────────────────────────

// TestUpgrade_SwitchesMode_MidStream uses a capture buffer to record all wire
// bytes written, separate from the read side. This avoids the issue of
// bytes.Buffer draining on read: we write to captureBuf, but read via a
// readOnlyRW constructed from a snapshot of captureBuf before reading.
func TestUpgrade_SwitchesMode_MidStream(t *testing.T) {
	t.Parallel()
	// We use separate write-capture and read-supply buffers so that reading
	// does not drain the capture buffer we inspect at the end.
	var captureBuf bytes.Buffer

	// Phase 1: EOM write.
	eomMsg := []byte("<hello/>")
	eomFramer := transport.NewFramer(&captureBuf)
	w1, err := eomFramer.MsgWriter()
	require.NoError(t, err)
	_, err = w1.Write(eomMsg)
	require.NoError(t, err)
	require.NoError(t, w1.Close())

	// Verify EOM wire bytes.
	eomWire := append([]byte(nil), captureBuf.Bytes()...) // snapshot
	assert.True(t, bytes.HasSuffix(eomWire, []byte("]]>]]>")),
		"EOM wire bytes must end with ]]>]]>")

	// Phase 1: EOM read.
	eomReadFramer := transport.NewFramer(newReadOnlyRW(eomWire))
	r1, err := eomReadFramer.MsgReader()
	require.NoError(t, err)
	got1, err := io.ReadAll(r1)
	require.NoError(t, err)
	require.NoError(t, r1.Close())
	assert.Equal(t, eomMsg, got1, "EOM message must round-trip before upgrade")

	// Phase 2: capture a chunked message separately.
	var chunkedCapture bytes.Buffer
	chunkedFramer := transport.NewFramer(&chunkedCapture)
	chunkedFramer.Upgrade() // write in chunked mode

	chunkedMsg := []byte("<rpc message-id=\"1\"><get/></rpc>")
	w2, err := chunkedFramer.MsgWriter()
	require.NoError(t, err)
	_, err = w2.Write(chunkedMsg)
	require.NoError(t, err)
	require.NoError(t, w2.Close())

	// Verify chunked wire bytes.
	chunkedWire := append([]byte(nil), chunkedCapture.Bytes()...)
	assert.True(t, bytes.Contains(chunkedWire, []byte("\n##\n")),
		"chunked wire bytes must contain end-of-chunks marker \\n##\\n")

	// Phase 2: chunked read.
	chunkedReadFramer := transport.NewFramer(newReadOnlyRW(chunkedWire))
	chunkedReadFramer.Upgrade()
	r2, err := chunkedReadFramer.MsgReader()
	require.NoError(t, err)
	got2, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.NoError(t, r2.Close())
	assert.Equal(t, chunkedMsg, got2, "chunked message must round-trip after upgrade")

	// Verify the full wire output has no chunked markers in the EOM portion
	// and no EOM markers in the chunked portion.
	assert.NotContains(t, string(eomWire), "\n##\n",
		"EOM wire must not contain chunked end-of-chunks marker")
	assert.NotContains(t, string(chunkedWire), "]]>]]>",
		"chunked wire must not contain EOM delimiter")
}

func TestUpgrade_CalledTwice_NoPanic(t *testing.T) {
	t.Parallel()
	framer := transport.NewFramer(&bytes.Buffer{})
	framer.Upgrade()
	assert.NotPanics(t, func() {
		framer.Upgrade()
	}, "second Upgrade must be a no-op")
}

func TestEOMWriter_CloseIdempotent_AndWriteAfterCloseErrors(t *testing.T) {
	t.Parallel()
	framer := transport.NewFramer(&bytes.Buffer{})
	w, err := framer.MsgWriter()
	require.NoError(t, err)

	_, err = w.Write([]byte("<hello/>"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, w.Close(), "second close should be a no-op")

	_, err = w.Write([]byte("<rpc/>"))
	require.Error(t, err, "write after close must fail")
	assert.Contains(t, err.Error(), "closed")
}

func TestChunkedWriter_CloseIdempotent_AndWriteAfterCloseErrors(t *testing.T) {
	t.Parallel()
	framer := transport.NewFramer(&bytes.Buffer{})
	framer.Upgrade()
	w, err := framer.MsgWriter()
	require.NoError(t, err)

	_, err = w.Write([]byte("<hello/>"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, w.Close(), "second close should be a no-op")

	_, err = w.Write([]byte("<rpc/>"))
	require.Error(t, err, "write after close must fail")
	assert.Contains(t, err.Error(), "closed")
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// BenchmarkChunkedReader_4KB measures the streaming chunkedReader path for a
// typical 4KB NETCONF message (single chunk). This is the primary signal for
// the M006 streaming reader improvement vs the old bytes.Buffer accumulation.
func BenchmarkChunkedReader_4KB(b *testing.B) {
	b.ReportAllocs()

	body := strings.Repeat("A", 4096)
	// Pre-build the chunked wire encoding: \n#4096\nAAAA...\n##\n
	wire := "\n#4096\n" + body + "\n##\n"

	for b.Loop() {
		rw := newReadOnlyRW([]byte(wire))
		f := transport.NewFramer(rw)
		f.Upgrade()
		rc, err := f.MsgReader()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			b.Fatal(err)
		}
		rc.Close()
	}
}

// BenchmarkChunkedReader_1MB measures the streaming chunkedReader for a 1MB
// payload — the key allocation savings target for M006.
func BenchmarkChunkedReader_1MB(b *testing.B) {
	b.ReportAllocs()

	body := strings.Repeat("A", 1024*1024)
	size := len(body)
	wire := fmt.Sprintf("\n#%d\n", size) + body + "\n##\n"

	for b.Loop() {
		rw := newReadOnlyRW([]byte(wire))
		f := transport.NewFramer(rw)
		f.Upgrade()
		rc, err := f.MsgReader()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			b.Fatal(err)
		}
		rc.Close()
	}
}

// BenchmarkEOMReader_4KB provides an EOM baseline for comparison with the
// chunked streaming reader.
func BenchmarkEOMReader_4KB(b *testing.B) {
	b.ReportAllocs()

	body := strings.Repeat("A", 4096)
	wire := body + "]]>]]>"

	for b.Loop() {
		rw := newReadOnlyRW([]byte(wire))
		f := transport.NewFramer(rw)
		rc, err := f.MsgReader()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			b.Fatal(err)
		}
		rc.Close()
	}
}

// ── Additional coverage tests ─────────────────────────────────────────────────

func TestFramer_Close_IsNoop(t *testing.T) {
	t.Parallel()
	framer := transport.NewFramer(&bytes.Buffer{})
	require.NoError(t, framer.Close(), "Framer.Close must return nil")
}

func TestChunkedReader_CloseBeforeFullyRead(t *testing.T) {
	t.Parallel()
	// Two-chunk message: close the reader after reading only part of chunk 1.
	part1 := "AAAAAAAAAA" // 10 bytes
	part2 := "BBBBBBBBBB" // 10 bytes
	wire := fmt.Appendf(nil, "\n#%d\n%s\n#%d\n%s\n##\n",
		len(part1), part1, len(part2), part2)

	// Append a second complete message so we can verify stream position.
	msg2 := "<ok/>"
	wire = fmt.Appendf(wire, "\n#%d\n%s\n##\n", len(msg2), msg2)

	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	// First message: read only 3 bytes, then close (drain remaining).
	r1, err := framer.MsgReader()
	require.NoError(t, err)
	buf := make([]byte, 3)
	n, err := r1.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	require.NoError(t, r1.Close(), "Close on partially-read chunked reader must succeed")

	// Second message: must read correctly.
	r2, err := framer.MsgReader()
	require.NoError(t, err)
	got, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.NoError(t, r2.Close())
	assert.Equal(t, msg2, string(got), "second message after early Close must be correct")
}

func TestChunked_MsgReader_EmptyMessage(t *testing.T) {
	t.Parallel()
	// End-of-chunks immediately → empty message.
	wire := []byte("\n##\n")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	r, err := framer.MsgReader()
	require.NoError(t, err, "MsgReader for empty chunked message must not error")

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.Empty(t, got, "empty chunked message must yield zero bytes")
}

func TestChunked_ReadChunkHeader_TrailingNonNewline(t *testing.T) {
	t.Parallel()
	// After "##" we expect '\n', but get 'x'.
	wire := []byte("\n##x")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	_, err := framer.MsgReader()
	require.Error(t, err, "non-newline after ## must return an error")
	assert.Contains(t, err.Error(), "expected '\\n' after '\\n##'")
}

func TestChunked_ReadChunkHeader_EOFAfterHash(t *testing.T) {
	t.Parallel()
	// "\n#" with EOF — no more bytes after '#'.
	wire := []byte("\n#")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	_, err := framer.MsgReader()
	require.Error(t, err, "EOF after '#' must return an error")
	assert.Contains(t, err.Error(), "read after '#'")
}

func TestChunked_ReadChunkHeader_NonDigitInSize(t *testing.T) {
	t.Parallel()
	// "\n#12x\n" — 'x' is a non-digit within the size field.
	wire := []byte("\n#12x\ndata\n##\n")
	framer := transport.NewFramer(newReadOnlyRW(wire))
	framer.Upgrade()

	_, err := framer.MsgReader()
	require.Error(t, err, "non-digit in chunk size must return an error")
	assert.Contains(t, err.Error(), "non-digit")
}

func TestEOM_MsgReader_EmptyStream(t *testing.T) {
	t.Parallel()
	// Completely empty stream — EOF with no data at all.
	framer := transport.NewFramer(newReadOnlyRW([]byte{}))
	_, err := framer.MsgReader()
	require.Error(t, err, "empty stream must produce an error")
	// This should be a bare io.EOF (wrapped), not "unexpected EOF before delimiter".
	assert.NotContains(t, err.Error(), "unexpected",
		"bare EOF on empty stream should not say 'unexpected'")
	assert.Contains(t, err.Error(), "EOF")
}

func TestEOM_WriteError(t *testing.T) {
	t.Parallel()
	framer := transport.NewFramer(&failWriter{})
	w, err := framer.MsgWriter()
	require.NoError(t, err, "MsgWriter itself should succeed")
	_, err = w.Write([]byte("<hello/>"))
	require.NoError(t, err, "Write to buffer should succeed")
	err = w.Close()
	require.Error(t, err, "Close must propagate write error")
	assert.Contains(t, err.Error(), "write failed")
}

func TestChunked_WriteError(t *testing.T) {
	t.Parallel()
	framer := transport.NewFramer(&failWriter{})
	framer.Upgrade()
	w, err := framer.MsgWriter()
	require.NoError(t, err, "MsgWriter itself should succeed")
	_, err = w.Write([]byte("<hello/>"))
	require.NoError(t, err, "Write to buffer should succeed")
	err = w.Close()
	require.Error(t, err, "Close must propagate write error")
	assert.Contains(t, err.Error(), "write failed")
}
