package statute

import (
	"context"
	"crypto/tls"
	"github.com/quic-go/quic-go"
	"net"
	"net/http"
	"time"
)

type TIPQueueChangeCallback func(ips []IPInfo)

type TDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)
type TQuicDialerFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)
type THTTPClientFunc func(rawDialer TDialerFunc, tlsDialer TDialerFunc, quicDialer TQuicDialerFunc, targetAddr ...string) *http.Client

var HTTPPing = 1 << 0
var TLSPing = 1 << 1
var TCPPing = 1 << 2
var QUICPing = 1 << 3

type IPInfo struct {
	IP        net.IP
	RTT       int
	CreatedAt time.Time
}

type ScannerOptions struct {
	UseIPv4               bool
	UseIPv6               bool
	CidrList              []string // CIDR ranges to scan
	SelectedOps           int
	Logger                Logger
	InsecureSkipVerify    bool
	RawDialerFunc         TDialerFunc
	TLSDialerFunc         TDialerFunc
	QuicDialerFunc        TQuicDialerFunc
	HttpClientFunc        THTTPClientFunc
	UseHTTP3              bool
	UseHTTP2              bool
	DisableCompression    bool
	HTTPPath              string
	Referrer              string
	UserAgent             string
	Hostname              string
	Port                  uint16
	IPQueueSize           int
	IPQueueTTL            time.Duration
	MaxDesirableRTT       int
	IPQueueChangeCallback TIPQueueChangeCallback
	ConnectionTimeout     time.Duration
	HandshakeTimeout      time.Duration
	TlsVersion            uint16
}
