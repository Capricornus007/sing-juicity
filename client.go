/*
Copyright (C) 2025  dyhkwong

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package juicity

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context           context.Context
	Dialer            network.Dialer
	ServerAddress     metadata.Socksaddr
	QUICOptions       qtls.QUICOptions
	TLSConfig         tls.Config
	QUICConfig        *quic.Config
	UUID              [16]byte
	Password          string
	CongestionControl string
}

type Client struct {
	ctx               context.Context
	dialer            network.Dialer
	serverAddr        metadata.Socksaddr
	tlsConfig         tls.Config
	quicConfig        *quic.Config
	uuid              [16]byte
	password          string
	congestionControl string

	connAccess sync.Mutex
	conn       *clientQUICConnection
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := options.QUICConfig
	if quicConfig == nil {
		quicConfig = &quic.Config{
			DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		}
		qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	}
	congestionControl := options.CongestionControl
	switch congestionControl {
	case "":
		options.CongestionControl = "bbr"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, exceptions.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	return &Client{
		ctx:               options.Context,
		dialer:            options.Dialer,
		serverAddr:        options.ServerAddress,
		tlsConfig:         options.TLSConfig, // clients need to set ALPN `h3` themselves
		quicConfig:        quicConfig,
		uuid:              options.UUID,
		password:          options.Password,
		congestionControl: congestionControl,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := common.ContextWithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()
	go c.completeOffer(pending, offerCtx)
	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	var quicConn *quic.Conn
	quicConn, err = qtls.Dial(ctx, udpConn, c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, exceptions.Cause(err, "open connection")
	}
	setCongestion(c.ctx, quicConn, c.congestionControl)
	conn := &clientQUICConnection{
		quicConn: quicConn,
		rawConn:  udpConn,
		connDone: make(chan struct{}),
	}
	go func() {
		hErr := c.clientHandshake(quicConn)
		if hErr != nil {
			conn.closeWithError(hErr)
		}
	}()
	return conn, nil
}

func (c *Client) clientHandshake(conn *quic.Conn) error {
	handshakeState := conn.ConnectionState()
	authToken, err := handshakeState.TLS.ExportKeyingMaterial(string(c.uuid[:]), []byte(c.password), 32)
	if err != nil {
		return exceptions.Cause(err, "export keying material")
	}
	authStream, err := conn.OpenUniStream()
	if err != nil {
		return exceptions.Cause(err, "open handshake stream")
	}
	authRequest := buf.NewSize(AuthenticateLen)
	common.Must(authRequest.WriteByte(Version))
	common.Must(authRequest.WriteByte(CommandAuthenticate))
	common.Must1(authRequest.Write(c.uuid[:]))
	common.Must1(authRequest.Write(authToken))
	_, err = authStream.Write(authRequest.Bytes())
	authRequest.Release()
	authStream.Close()
	return err
}

func (c *Client) DialConn(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      conn,
		destination: destination,
		network:     NetworkTCP,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &udpPacketConn{
		Conn: &clientConn{
			Stream:      stream,
			parent:      conn,
			destination: destination,
			network:     NetworkUDP,
		},
	}, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()
	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn  *quic.Conn
	rawConn   io.Closer
	closeOnce sync.Once
	connDone  chan struct{}
	connErr   error
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

var (
	_ net.Conn            = (*clientConn)(nil)
	_ network.EarlyWriter = (*clientConn)(nil)
)

type clientConn struct {
	*quic.Stream
	parent         *clientQUICConnection
	destination    metadata.Socksaddr
	requestWritten bool
	network        int
}

func (c *clientConn) NeedHandshakeForWrite() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(b []byte) (int, error) {
	n, err := c.Stream.Read(b)
	return n, wrapQUICError(err)
}

func (c *clientConn) Write(b []byte) (int, error) {
	if !c.requestWritten {
		request := buf.NewSize(1 + AddressSerializer.AddrPortLen(c.destination) + len(b))
		common.Must(request.WriteByte(byte(c.network)))
		common.Must(AddressSerializer.WriteAddrPort(request, c.destination))
		common.Must1(request.Write(b))
		_, err := c.Stream.Write(request.Bytes())
		request.Release()
		if err != nil {
			c.parent.closeWithError(exceptions.Cause(err, "create new connection"))
			return 0, wrapQUICError(err)
		}
		c.requestWritten = true
		return len(b), nil
	}
	n, err := c.Stream.Write(b)
	return n, wrapQUICError(err)
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}

func (c *clientConn) LocalAddr() net.Addr {
	return metadata.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}
