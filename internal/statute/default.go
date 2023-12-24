package statute

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/bepass-org/ipscanner/internal/dialer"
	"net"
	"net/http"
	"time"
)

func DefaultHTTPClient(rawDialer dialer.TDialerFunc, tlsDialer dialer.TDialerFunc) *http.Client {
	var defaultDialer dialer.TDialerFunc
	if rawDialer == nil {
		defaultDialer = DefaultDialerFunc
	} else {
		defaultDialer = rawDialer
	}
	var defaultTLSDialer dialer.TDialerFunc
	if rawDialer == nil {
		defaultTLSDialer = DefaultTLSDialerFunc
	} else {
		defaultTLSDialer = tlsDialer
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:       defaultDialer,
			DialTLSContext:    defaultTLSDialer,
			ForceAttemptHTTP2: false,
		},
		Timeout: 10 * time.Second,
	}
}

func DefaultDialerFunc(_ context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   5 * time.Second, // Connection timeout
		KeepAlive: 5 * time.Second, // KeepAlive period
		// Add other custom settings as needed
	}
	return d.Dial(network, addr)
}

// DefaultTLSDialerFunc is a custom TLS dialer function
func DefaultTLSDialerFunc(ctx context.Context, network, addr string) (net.Conn, error) {
	// Dial the raw connection using the default dialer
	rawConn, err := DefaultDialerFunc(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Initiate a TLS handshake over the connection
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: addr,
	})
	err = tlsConn.Handshake()
	if err != nil {
		err := rawConn.Close()
		if err != nil {
			return nil, err
		}
		return nil, err
	}

	// Return the established TLS connection
	return tlsConn, nil
}

// default logger

type Logger interface {
	Debug(s string, v ...interface{})
	Error(s string, v ...interface{})
}

type DefaultLogger struct{}

func (l DefaultLogger) Debug(s string, v ...interface{}) {
	fmt.Printf(fmt.Sprintf("%s\r\n", s), v...)
}

func (l DefaultLogger) Error(s string, v ...interface{}) {
	fmt.Printf(fmt.Sprintf("%s\r\n", s), v...)
}
