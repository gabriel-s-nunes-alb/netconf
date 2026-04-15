package netconf_test

import (
	"encoding/xml"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/GabrielNunesIT/netconf"
	"github.com/GabrielNunesIT/netconf/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// caps builds a CapabilitySet from a variadic list of capability strings.
func caps(cs ...string) netconf.CapabilitySet {
	return netconf.NewCapabilitySet(cs)
}

// ── happy path: both peers support base:1.1 ───────────────────────────────────

func TestSession_BothSupport11_UpgradesToChunked(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	serverCaps := caps(netconf.BaseCap10, netconf.BaseCap11)
	clientCaps := caps(netconf.BaseCap10, netconf.BaseCap11)

	var (
		wg      sync.WaitGroup
		srvSess *netconf.Session
		srvErr  error
	)
	wg.Go(func() {
		srvSess, srvErr = netconf.ServerSession(serverT, serverCaps, 42)
	})

	cliSess, cliErr := netconf.ClientSession(clientT, clientCaps)
	wg.Wait()

	require.NoError(t, srvErr, "ServerSession must succeed")
	require.NoError(t, cliErr, "ClientSession must succeed")

	// Client sees the server-assigned session-id.
	assert.Equal(t, uint32(42), cliSess.SessionID(), "client must see session-id 42")

	// Both ends negotiated chunked framing.
	assert.Equal(t, netconf.FramingChunked, cliSess.FramingMode(), "client framing must be chunked")
	assert.Equal(t, netconf.FramingChunked, srvSess.FramingMode(), "server framing must be chunked")

	// Capabilities are visible on both sides.
	assert.True(t, cliSess.RemoteCapabilities().Contains(netconf.BaseCap10), "client sees server base:1.0")
	assert.True(t, cliSess.RemoteCapabilities().Contains(netconf.BaseCap11), "client sees server base:1.1")
	assert.True(t, srvSess.RemoteCapabilities().Contains(netconf.BaseCap10), "server sees client base:1.0")
	assert.True(t, srvSess.RemoteCapabilities().Contains(netconf.BaseCap11), "server sees client base:1.1")
}

// ── fallback to EOM: server only advertises base:1.0 ─────────────────────────

func TestSession_ServerOnly10_StaysEOM(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	serverCaps := caps(netconf.BaseCap10)                    // server supports 1.0 only
	clientCaps := caps(netconf.BaseCap10, netconf.BaseCap11) // client also supports 1.1

	var (
		wg      sync.WaitGroup
		srvSess *netconf.Session
		srvErr  error
	)
	wg.Go(func() {
		srvSess, srvErr = netconf.ServerSession(serverT, serverCaps, 7)
	})

	cliSess, cliErr := netconf.ClientSession(clientT, clientCaps)
	wg.Wait()

	require.NoError(t, srvErr)
	require.NoError(t, cliErr)

	// Neither side upgrades because server doesn't support 1.1.
	assert.Equal(t, netconf.FramingEOM, cliSess.FramingMode(), "client framing must stay EOM")
	assert.Equal(t, netconf.FramingEOM, srvSess.FramingMode(), "server framing must stay EOM")
}

// ── fallback to EOM: client only advertises base:1.0 ─────────────────────────

func TestSession_ClientOnly10_StaysEOM(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	serverCaps := caps(netconf.BaseCap10, netconf.BaseCap11)
	clientCaps := caps(netconf.BaseCap10) // client supports 1.0 only

	var (
		wg      sync.WaitGroup
		srvSess *netconf.Session
		srvErr  error
	)
	wg.Go(func() {
		srvSess, srvErr = netconf.ServerSession(serverT, serverCaps, 3)
	})

	cliSess, cliErr := netconf.ClientSession(clientT, clientCaps)
	wg.Wait()

	require.NoError(t, srvErr)
	require.NoError(t, cliErr)

	assert.Equal(t, netconf.FramingEOM, cliSess.FramingMode(), "client framing must stay EOM")
	assert.Equal(t, netconf.FramingEOM, srvSess.FramingMode(), "server framing must stay EOM")
}

// ── capability intersection: extra capabilities are visible on both sides ─────

func TestSession_CapabilityIntersection(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	// Well-known IETF NETCONF capability URNs.
	candidateCap := "urn:ietf:params:netconf:capability:candidate:1.0"
	validateCap := "urn:ietf:params:netconf:capability:validate:1.1"

	serverCaps := caps(netconf.BaseCap10, netconf.BaseCap11, candidateCap, validateCap)
	clientCaps := caps(netconf.BaseCap10, netconf.BaseCap11)

	var (
		wg      sync.WaitGroup
		srvSess *netconf.Session
		srvErr  error
	)
	wg.Go(func() {
		srvSess, srvErr = netconf.ServerSession(serverT, serverCaps, 99)
	})

	cliSess, cliErr := netconf.ClientSession(clientT, clientCaps)
	wg.Wait()

	require.NoError(t, srvErr)
	require.NoError(t, cliErr)

	// Client sees the extra server capabilities.
	assert.True(t, cliSess.RemoteCapabilities().Contains(candidateCap),
		"client must see candidate capability")
	assert.True(t, cliSess.RemoteCapabilities().Contains(validateCap),
		"client must see validate capability")

	// Server sees only the client capabilities.
	assert.False(t, srvSess.RemoteCapabilities().Contains(candidateCap),
		"server must not see candidate in client caps")
}

// ── session-id propagation ─────────────────────────────────────────────────────

func TestSession_SessionIDPropagation(t *testing.T) {
	t.Parallel()
	for _, id := range []uint32{1, 42, 1000, 4294967295} {
		t.Run("id="+strconv.FormatUint(uint64(id), 10), func(t *testing.T) {
			t.Parallel()
			clientT, serverT := transport.NewLoopback()
			defer clientT.Close()
			defer serverT.Close()

			var (
				wg     sync.WaitGroup
				srvErr error
			)
			wg.Go(func() {
				_, srvErr = netconf.ServerSession(serverT, caps(netconf.BaseCap10), id)
			})

			cliSess, cliErr := netconf.ClientSession(clientT, caps(netconf.BaseCap10))
			wg.Wait()

			require.NoError(t, srvErr)
			require.NoError(t, cliErr)
			assert.Equal(t, id, cliSess.SessionID(), "client session-id must match server's assignment")
		})
	}
}

// ── invalid hello: remote missing base:1.0 ────────────────────────────────────

// TestSession_ClientRejects_MissingBase10 proves that ClientSession returns
// an error when the server hello omits base:1.0. We inject a raw hello via the
// loopback to simulate a misbehaving server.
func TestSession_ClientRejects_MissingBase10(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	// Server side: send a hello without base:1.0 capability, then read the
	// client hello so the pipe doesn't block.
	done := make(chan error, 1)
	go func() {
		// Craft a hello that omits base:1.0 (has an unrelated capability).
		h := netconf.Hello{
			Capabilities: []string{"urn:ietf:params:netconf:capability:candidate:1.0"},
			SessionID:    1,
		}
		data, _ := xml.Marshal(&h)
		if err := transport.WriteMsg(serverT, data); err != nil {
			done <- err
			return
		}
		// Drain the client hello so the pipe doesn't deadlock.
		_, err := transport.ReadMsg(serverT)
		done <- err
	}()

	_, err := netconf.ClientSession(clientT, caps(netconf.BaseCap10))

	require.Error(t, err, "ClientSession must fail when server hello lacks base:1.0")
	assert.Contains(t, err.Error(), netconf.BaseCap10,
		"error message must name the missing capability")

	// Wait for server goroutine to finish.
	<-done
}

// TestSession_ServerRejects_MissingBase10 proves that ServerSession returns
// an error when the client hello omits base:1.0.
func TestSession_ServerRejects_MissingBase10(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	// Client side: send a hello without base:1.0 and read the server hello.
	done := make(chan error, 1)
	go func() {
		h := netconf.Hello{
			Capabilities: []string{"urn:ietf:params:netconf:capability:candidate:1.0"},
		}
		data, _ := xml.Marshal(&h)
		// First drain the server hello (server sends first).
		if _, err := transport.ReadMsg(clientT); err != nil {
			done <- err
			return
		}
		// Then send the bad hello.
		done <- transport.WriteMsg(clientT, data)
	}()

	_, err := netconf.ServerSession(serverT, caps(netconf.BaseCap10), 5)

	require.Error(t, err, "ServerSession must fail when client hello lacks base:1.0")
	assert.Contains(t, err.Error(), netconf.BaseCap10,
		"error message must name the missing capability")

	<-done
}

func TestSession_ClientRejects_OversizedHello(t *testing.T) {
	t.Parallel()

	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	// Build a valid hello whose payload exceeds the session hello limit (4 MiB).
	bigCap := "urn:test:" + strings.Repeat("x", 5*1024*1024)
	h := netconf.Hello{
		Capabilities: []string{netconf.BaseCap10, bigCap},
		SessionID:    1,
	}
	raw, err := xml.Marshal(&h)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- transport.WriteMsg(serverT, raw)
	}()

	_, err = netconf.ClientSession(clientT, caps(netconf.BaseCap10))
	require.Error(t, err, "ClientSession must reject oversized hello")
	assert.Contains(t, err.Error(), "hello exceeds maximum size")

	<-done
}

// ── local capabilities accessible ─────────────────────────────────────────────

func TestSession_LocalCapabilitiesAccessor(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	serverCaps := caps(netconf.BaseCap10, netconf.BaseCap11)
	clientCaps := caps(netconf.BaseCap10)

	var (
		wg      sync.WaitGroup
		srvSess *netconf.Session
		srvErr  error
	)
	wg.Go(func() {
		srvSess, srvErr = netconf.ServerSession(serverT, serverCaps, 1)
	})

	cliSess, cliErr := netconf.ClientSession(clientT, clientCaps)
	wg.Wait()

	require.NoError(t, srvErr)
	require.NoError(t, cliErr)

	// LocalCapabilities() returns what we passed in.
	assert.True(t, cliSess.LocalCapabilities().Contains(netconf.BaseCap10))
	assert.True(t, srvSess.LocalCapabilities().Contains(netconf.BaseCap10))
	assert.True(t, srvSess.LocalCapabilities().Contains(netconf.BaseCap11))
}

// ── Close / Send / Recv ───────────────────────────────────────────────────────

func TestSession_Close_Send_Recv(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	serverCaps := caps(netconf.BaseCap10)
	clientCaps := caps(netconf.BaseCap10)

	var (
		wg      sync.WaitGroup
		srvSess *netconf.Session
		srvErr  error
	)
	wg.Go(func() {
		srvSess, srvErr = netconf.ServerSession(serverT, serverCaps, 10)
	})

	cliSess, cliErr := netconf.ClientSession(clientT, clientCaps)
	wg.Wait()

	require.NoError(t, srvErr)
	require.NoError(t, cliErr)

	// Client sends a message, server receives it.
	msg := []byte("<rpc/>")
	var (
		recvData []byte
		recvErr  error
	)
	wg.Go(func() {
		recvData, recvErr = srvSess.Recv()
	})
	require.NoError(t, cliSess.Send(msg))
	wg.Wait()
	require.NoError(t, recvErr)
	assert.Equal(t, msg, recvData)

	// Server sends a reply, client receives it.
	reply := []byte("<rpc-reply/>")
	wg.Go(func() {
		recvData, recvErr = cliSess.Recv()
	})
	require.NoError(t, srvSess.Send(reply))
	wg.Wait()
	require.NoError(t, recvErr)
	assert.Equal(t, reply, recvData)

	// Close both sessions.
	assert.NoError(t, cliSess.Close())
	assert.NoError(t, srvSess.Close())
}

// ── RecvStream ────────────────────────────────────────────────────────────────

func TestSession_RecvStream(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	serverCaps := caps(netconf.BaseCap10)
	clientCaps := caps(netconf.BaseCap10)

	var (
		wg      sync.WaitGroup
		srvSess *netconf.Session
		srvErr  error
	)
	wg.Go(func() {
		srvSess, srvErr = netconf.ServerSession(serverT, serverCaps, 20)
	})

	cliSess, cliErr := netconf.ClientSession(clientT, clientCaps)
	wg.Wait()

	require.NoError(t, srvErr)
	require.NoError(t, cliErr)

	msg := []byte("<notification/>")

	// Client sends, server reads via RecvStream.
	var (
		streamData []byte
		streamErr  error
	)
	wg.Go(func() {
		var rc io.ReadCloser
		rc, streamErr = srvSess.RecvStream()
		if streamErr != nil {
			return
		}
		defer rc.Close()
		streamData, streamErr = io.ReadAll(rc)
	})
	require.NoError(t, cliSess.Send(msg))
	wg.Wait()

	require.NoError(t, streamErr)
	assert.Equal(t, msg, streamData)
}

// ── negotiateFraming error: transport without Upgrader ────────────────────────

// nonUpgraderTransport wraps a Transport but does NOT implement Upgrader.
type nonUpgraderTransport struct {
	t transport.Transport
}

func (n *nonUpgraderTransport) MsgReader() (io.ReadCloser, error) { return n.t.MsgReader() }
func (n *nonUpgraderTransport) MsgWriter() (io.WriteCloser, error) { return n.t.MsgWriter() }
func (n *nonUpgraderTransport) Close() error                      { return n.t.Close() }

func TestSession_NegotiateFraming_NonUpgrader(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	// Wrap the client side so it loses the Upgrader interface.
	wrapped := &nonUpgraderTransport{t: clientT}

	bothCaps := caps(netconf.BaseCap10, netconf.BaseCap11)

	// Server side: manually write a hello and drain the client hello.
	// We can't use ServerSession on the non-upgrader side, so we drive the
	// server raw on the real LoopbackTransport.
	done := make(chan error, 1)
	go func() {
		h := netconf.Hello{
			Capabilities: []string{netconf.BaseCap10, netconf.BaseCap11},
			SessionID:    50,
		}
		data, _ := xml.Marshal(&h)
		if err := transport.WriteMsg(serverT, data); err != nil {
			done <- err
			return
		}
		// Drain the client hello so the pipe doesn't deadlock.
		_, err := transport.ReadMsg(serverT)
		done <- err
	}()

	_, err := netconf.ClientSession(wrapped, bothCaps)
	require.Error(t, err, "ClientSession must fail when transport lacks Upgrader")
	assert.Contains(t, err.Error(), "framing upgrade required but transport does not implement Upgrader")

	<-done
}

// ── client rejects hello with missing session-id ──────────────────────────────

func TestSession_ClientRejects_MissingSessionID(t *testing.T) {
	t.Parallel()
	clientT, serverT := transport.NewLoopback()
	defer clientT.Close()
	defer serverT.Close()

	// Server side: send a hello with base:1.0 but session-id=0 (omitted).
	done := make(chan error, 1)
	go func() {
		h := netconf.Hello{
			Capabilities: []string{netconf.BaseCap10},
			SessionID:    0, // omitempty → missing in XML
		}
		data, _ := xml.Marshal(&h)
		if err := transport.WriteMsg(serverT, data); err != nil {
			done <- err
			return
		}
		_, err := transport.ReadMsg(serverT)
		done <- err
	}()

	_, err := netconf.ClientSession(clientT, caps(netconf.BaseCap10))
	require.Error(t, err, "ClientSession must fail when server hello lacks session-id")
	assert.Contains(t, err.Error(), "missing session-id")

	<-done
}
