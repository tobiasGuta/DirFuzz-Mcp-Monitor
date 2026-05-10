package httpclient

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// MaxIdleConnsPerHost is the maximum number of idle keep-alive
	// connections to retain per host:port key.
	MaxIdleConnsPerHost = 16

	// IdleConnTimeout is how long an idle connection stays in the pool
	// before being discarded.
	IdleConnTimeout = 30 * time.Second

	// HealthCheckTimeout is the deadline for the idle connection health check.
	// A short, non-zero timeout is used to detect connections that have been
	// closed by the server without sending a FIN. This can be increased for
	// high-latency environments.
	HealthCheckTimeout = 50 * time.Millisecond
)

// pooledConn wraps a net.Conn with the scheme needed to decide whether a
// connection can be reused after a response is read.
type pooledConn struct {
	conn      net.Conn
	scheme    string
	expiresAt time.Time
}

// ConnPool is a simple per-host idle-connection pool for HTTP/1.1 keep-alive.
// The pool is safe for concurrent use by multiple goroutines.
type ConnPool struct {
	mu      sync.Mutex
	idle    map[string][]*pooledConn
	maxIdle int
}

// NewConnPool creates a new ConnPool.
func NewConnPool(maxIdlePerHost int) *ConnPool {
	return &ConnPool{
		idle:    make(map[string][]*pooledConn),
		maxIdle: maxIdlePerHost,
	}
}

// DefaultPool is the shared pool used by SendRawRequestWithContext.
var DefaultPool = NewConnPool(MaxIdleConnsPerHost)

// Get retrieves an idle connection for the given key (scheme://host:port).
// Returns nil when no idle connection is available.
func (p *ConnPool) Get(key string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	conns := p.idle[key]
	for len(conns) > 0 {
		pc := conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		p.idle[key] = conns

		// Discard if the idle timeout has passed.
		if time.Now().After(pc.expiresAt) {
			pc.conn.Close()
			continue
		}

		// Quick health check: set an immediate deadline and try a zero-byte
		// read.  If the server closed the connection we'll get io.EOF or an
		// error straight away.  Then restore a normal deadline.
		pc.conn.SetReadDeadline(time.Now().Add(HealthCheckTimeout))
		var buf [1]byte
		n, err := pc.conn.Read(buf[:])
		pc.conn.SetDeadline(time.Time{}) // clear deadline

		if err != nil {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				// Socket is closed or dead.
				pc.conn.Close()
				continue
			}
		}

		if n > 0 {
			// Unexpected data in the buffer — discard this connection.
			pc.conn.Close()
			continue
		}

		// Connection looks alive — return it.
		return pc.conn
	}

	return nil
}

// Put returns a connection to the pool.  The connection is silently closed if
// the pool for this key is already full.
func (p *ConnPool) Put(key, scheme string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.idle[key]) >= p.maxIdle {
		conn.Close()
		return
	}

	// Clear any lingering deadline before parking the connection.
	conn.SetDeadline(time.Time{})

	p.idle[key] = append(p.idle[key], &pooledConn{
		conn:      conn,
		scheme:    scheme,
		expiresAt: time.Now().Add(IdleConnTimeout),
	})
}

// Close closes and discards all idle connections in the pool.
func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for key, conns := range p.idle {
		for _, pc := range conns {
			pc.conn.Close()
		}
		delete(p.idle, key)
	}
}

// responseAllowsKeepalive returns true when the HTTP response indicates
// the server is willing to keep the connection open.
func responseAllowsKeepalive(isHTTP10 bool, headerMap map[string]string) bool {
	// HTTP/1.1 defaults to keep-alive unless Connection: close is present.
	// HTTP/1.0 defaults to close unless Connection: keep-alive is present.
	connectionHeader := headerMap["connection"]

	if connectionHeader != "" {
		values := strings.Split(connectionHeader, ",")
		for _, val := range values {
			trimmed := strings.TrimSpace(val)
			if strings.EqualFold(trimmed, "close") {
				return false
			}
			if strings.EqualFold(trimmed, "keep-alive") {
				return true
			}
		}
	}

	if isHTTP10 {
		return false // Default for HTTP/1.0 is close
	}

	return true // Default for HTTP/1.1 is keep-alive
}
