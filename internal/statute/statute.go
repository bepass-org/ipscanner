package statute

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

type TIPQueueChangeCallback func(ips []IPInfo)

type TDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)
type TQuicDialerFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)
type THTTPClientFunc func(rawDialer TDialerFunc, tlsDialer TDialerFunc, quicDialer TQuicDialerFunc, targetAddr ...string) *http.Client

var HTTPPing = 1 << 1
var TLSPing = 1 << 2
var TCPPing = 1 << 3
var QUICPing = 1 << 4
var WARPPing = 1 << 5

type IPInfo struct {
	IP        netip.Addr
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
	WarpPrivateKey        string
	WarpPeerPublicKey     string
	WarpPresharedKey      string
	Port                  uint16
	IPQueueSize           int
	IPQueueTTL            time.Duration
	MaxDesirableRTT       int
	IPQueueChangeCallback TIPQueueChangeCallback
	ConnectionTimeout     time.Duration
	HandshakeTimeout      time.Duration
	TlsVersion            uint16
}
