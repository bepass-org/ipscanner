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

func DefaultIPQueueChangeCallback(ips []IPInfo) {
	fmt.Printf("queue change: %d\r\n", len(ips))
	for _, ip := range ips {
		fmt.Printf("IP:%s\tRTT:%d\tTS:%s\r\n", ip.IP.String(), ip.RTT, ip.CreatedAt.String())
	}
}

var DefaultCFRanges = []string{
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"104.16.0.0/12",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"2400:cb00::/32",
	"2405:8100::/32",
	"2405:b500::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2c0f:f248::/32",
	"2a06:98c0::/29",
}
