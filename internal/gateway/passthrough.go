package gateway

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// sniListener sits under the gateway's TLS listener. It reads each
// connection's ClientHello without decrypting anything; connections for a
// passthrough service are piped to the app's own TLS port, all others are
// handed on (with the bytes replayed) to DevCA's TLS server.
type sniListener struct {
	net.Listener
	g      *Gateway
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newSNIListener(ln net.Listener, g *Gateway) *sniListener {
	l := &sniListener{Listener: ln, g: g, conns: make(chan net.Conn), closed: make(chan struct{})}
	go l.acceptLoop()
	return l
}

func (l *sniListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			l.Close()
			return
		}
		// Peek in its own goroutine so a slow client can't stall accepting.
		go l.route(c)
	}
}

func (l *sniListener) route(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	sni, hello := peekSNI(c)
	_ = c.SetReadDeadline(time.Time{})
	if rt := l.g.lookup(sni); sni != "" && rt != nil && rt.passthrough != "" {
		tunnel(c, hello, rt.passthrough, sni)
		return
	}
	select {
	case l.conns <- &replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(hello), c)}:
	case <-l.closed:
		c.Close()
	}
}

func (l *sniListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *sniListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

var errPeeked = errors.New("client hello read")

// peekSNI reads the ClientHello with crypto/tls's own parser and returns the
// requested server name plus every byte consumed, for replay. A client that
// sends no SNI (or isn't speaking TLS) yields "".
func peekSNI(c net.Conn) (string, []byte) {
	var buf bytes.Buffer
	var sni string
	_ = tls.Server(readOnlyConn{io.TeeReader(c, &buf)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, errPeeked
		},
	}).Handshake()
	return sni, buf.Bytes()
}

// tunnel connects client to the app's TLS port and copies both ways. The
// app terminates TLS with its own certificate; DevCA never sees the traffic.
func tunnel(client net.Conn, hello []byte, target, host string) {
	defer client.Close()
	d := net.Dialer{Timeout: 5 * time.Second, Control: loopbackOnly}
	up, err := d.Dial("tcp", target)
	if err != nil {
		slog.Warn("passthrough upstream unreachable", "host", host, "target", target, "err", err)
		return
	}
	defer up.Close()
	if _, err := up.Write(hello); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, client)
		closeWrite(up)
		close(done)
	}()
	_, _ = io.Copy(client, up)
	closeWrite(client)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}

// replayConn returns the peeked bytes before reading on from the connection.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// readOnlyConn feeds the TLS parser; it can't write (no alerts reach the client).
type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (readOnlyConn) Write(p []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return nil }
func (readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
