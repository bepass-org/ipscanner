package ping

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/bepass-org/ipscanner/internal/statute"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type QuicPingResult struct {
	Time        int
	Err         error
	IP          net.IP
	QUICVersion uint32
	TLSVersion  uint16
}

func (h *QuicPingResult) Result() int {
	return h.Time
}

func (h *QuicPingResult) Error() error {
	return h.Err
}

func (h *QuicPingResult) String() string {
	if h.Err != nil {
		return fmt.Sprintf("%s", h.Err)
	} else {
		return fmt.Sprintf("%s: quic=%s, tls=%s, time=%d ms", h.IP.String(), quic.VersionNumber(h.QUICVersion).String(), statute.TlsVersionToString(h.TLSVersion), h.Time)
	}
}

type QuicPing struct {
	Host    string
	Port    uint16
	Timeout time.Duration

	Insecure bool
	ALPN     string
	IP       net.IP
}

func (h *QuicPing) Ping() statute.IPingResult {
	return h.PingContext(context.Background())
}

func (h *QuicPing) PingContext(ctx context.Context) statute.IPingResult {
	ip := statute.CloneIP(h.IP)
	if ip == nil {
		return h.errorResult(fmt.Errorf("no IP specified"))
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprint(h.Port))

	alpn := http3.NextProtoH3
	if h.ALPN != "" {
		alpn = h.ALPN
	}
	tlsconf := tls.Config{
		ServerName:         h.Host,
		InsecureSkipVerify: h.Insecure,
		NextProtos:         []string{alpn},
	}
	quicconf := quic.Config{
		HandshakeIdleTimeout: h.Timeout,
	}
	t0 := time.Now()
	conn, err := quic.DialAddr(ctx, addr, &tlsconf, &quicconf)
	if err != nil {
		return h.errorResult(err)
	}
	closecode := uint64(http3.ErrCodeNoError)
	if alpn != http3.NextProtoH3 {
		closecode = 0
	}
	defer conn.CloseWithError(quic.ApplicationErrorCode(closecode), "")
	return &QuicPingResult{int(time.Since(t0).Milliseconds()), nil, ip, uint32(conn.ConnectionState().Version), conn.ConnectionState().TLS.Version}
}

func NewQuicPing(ip net.IP, host string, port uint16, timeout time.Duration) *QuicPing {
	return &QuicPing{
		IP:      ip,
		Host:    host,
		Port:    port,
		Timeout: timeout,
	}
}

func (h *QuicPing) errorResult(err error) *QuicPingResult {
	r := &QuicPingResult{}
	r.Err = err
	return r
}

var (
	_ statute.IPing       = (*QuicPing)(nil)
	_ statute.IPingResult = (*QuicPingResult)(nil)
)
