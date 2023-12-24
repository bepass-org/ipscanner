package dialer

import (
	"context"
	"net"
	"time"
)

type TDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

var RawDialFunc TDialerFunc

var TLSDialFunc TDialerFunc

// AppDialer is a type that implements the CustomDialer interface.
type AppDialer struct {
	Timeout time.Duration
}

func (d *AppDialer) GetTimeout() time.Duration {
	return d.Timeout
}

func (d *AppDialer) SetTimeout(t time.Duration) {
	d.Timeout = t
}

// Dial implements the CustomDialer interface's Dial method.
func (d *AppDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext implements the CustomDialer interface's Dial method.
func (d *AppDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if RawDialFunc != nil {
		return RawDialFunc(ctx, network, address)
	}
	conn, err := net.DialTimeout(network, address, d.Timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// AppTLSDialer is a type that implements the CustomDialer interface.
type AppTLSDialer struct {
	Timeout time.Duration
}

// Dial implements the CustomDialer interface's Dial method.
func (d *AppTLSDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext implements the CustomDialer interface's Dial method.
func (d *AppTLSDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if TLSDialFunc != nil {
		return TLSDialFunc(ctx, network, address)
	}
	conn, err := net.DialTimeout(network, address, d.Timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *AppTLSDialer) GetTimeout() time.Duration {
	return d.Timeout
}

func (d *AppTLSDialer) SetTimeout(t time.Duration) {
	d.Timeout = t
}
