// Package tls provides TLS transport implementations for NETCONF.
//
// NETCONF over TLS is defined by RFC 7589. This file implements the client
// side of the TLS transport: [Dial] opens a mutually-authenticated TLS
// connection to a NETCONF server and returns a [Transport] ready for the
// hello exchange. [NewClientTransport] wraps a pre-established [tls.Conn]
// for in-process tests.
//
// # Observability
//
// Every error returned by MsgReader, MsgWriter, and Close includes descriptive
// context prefixed with "tls client:" so log lines identify the layer.
// No credentials or secrets pass through this layer after the TLS handshake;
// cert fingerprints and capability URNs are safe to log verbatim.
//
// Failure inspection:
//   - Dial errors name the address and the failed step (e.g., "tls client: dial
//     127.0.0.1:6513: <underlying error>").
//   - `go test ./... -v` prints per-test PASS/FAIL.
package tls

import (
	cryptotls "crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/GabrielNunesIT/netconf/transport"
)

// Transport is a TLS-backed NETCONF client transport.
//
// It wraps a single TLS connection and exposes both transport.Transport and
// transport.Upgrader so the Session layer can switch framing after the hello
// exchange. Unlike the SSH transport there is no channel layer or subsystem
// negotiation: the TLS connection is the NETCONF transport directly.
type Transport struct {
	framer *transport.Framer
	conn   net.Conn // *cryptotls.Conn stored as net.Conn
}

// NewClientTransport wraps a pre-established TLS connection as a NETCONF
// transport. The handshake must already be complete.
//
// This constructor is intended for in-process tests. Production code should
// use Dial.
func NewClientTransport(conn *cryptotls.Conn) *Transport {
	return &Transport{
		framer: transport.NewFramer(conn),
		conn:   conn,
	}
}

// Dial opens a TLS connection to addr and returns the resulting transport.
// addr must be in "host:port" form. config must supply the client certificate
// and the server CA pool for mutual TLS authentication.
func Dial(addr string, config *cryptotls.Config) (*Transport, error) {
	conn, err := cryptotls.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("tls client: dial %s: %w", addr, err)
	}
	return &Transport{
		framer: transport.NewFramer(conn),
		conn:   conn,
	}, nil
}

// MsgReader returns a ReadCloser for exactly one complete NETCONF message.
// Implements transport.Transport.
func (t *Transport) MsgReader() (io.ReadCloser, error) {
	rc, err := t.framer.MsgReader()
	if err != nil {
		return nil, fmt.Errorf("tls client: MsgReader: %w", err)
	}
	return rc, nil
}

// MsgWriter returns a WriteCloser that commits one NETCONF message on Close.
// Implements transport.Transport.
func (t *Transport) MsgWriter() (io.WriteCloser, error) {
	wc, err := t.framer.MsgWriter()
	if err != nil {
		return nil, fmt.Errorf("tls client: MsgWriter: %w", err)
	}
	return wc, nil
}

// Close closes the underlying TLS connection.
// Implements transport.Transport.
func (t *Transport) Close() error {
	if err := t.conn.Close(); err != nil {
		return fmt.Errorf("tls client: close: %w", err)
	}
	return nil
}

// Upgrade switches the transport from EOM to chunked framing.
// Implements transport.Upgrader. Repeated calls are no-ops.
func (t *Transport) Upgrade() {
	t.framer.Upgrade()
}
