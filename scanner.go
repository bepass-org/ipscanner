package ipscanner

import (
	"context"
	"github.com/bepass-org/ipscanner/internal/dialer"
	"github.com/bepass-org/ipscanner/internal/engine"
	"github.com/bepass-org/ipscanner/internal/statute"
	"net"
	"net/http"
	"time"
)

type IPScanner struct {
	options  statute.ScannerOptions
	logger   statute.Logger
	engine   *engine.Engine
	onChange func([]net.IP)
}

func NewScanner(options ...Option) *IPScanner {
	p := &IPScanner{
		options: statute.ScannerOptions{
			UseIPv4:               true,
			UseIPv6:               true,
			CidrList:              statute.DefaultCFRanges,
			SelectedOps:           statute.HTTPPing | statute.TLSPing | statute.TCPPing | statute.QUICPing,
			Logger:                statute.DefaultLogger{},
			Timeout:               1 * time.Minute,
			InsecureSkipVerify:    true,
			Dialer:                &dialer.AppDialer{},
			TLSDialer:             &dialer.AppTLSDialer{},
			RawDialerFunc:         statute.DefaultDialerFunc,
			TLSDialerFunc:         statute.DefaultTLSDialerFunc,
			HttpClient:            statute.DefaultHTTPClient(nil, nil),
			HTTPPath:              "/",
			Hostname:              "localhost",
			Port:                  443,
			IPQueueSize:           8,
			MaxDesirableRTT:       400,
			IPQueueTTL:            30 * time.Second,
			IPQueueChangeCallback: statute.DefaultIPQueueChangeCallback,
		},
		logger: statute.DefaultLogger{},
	}

	for _, option := range options {
		option(p)
	}

	return p
}

type Option func(*IPScanner)

func WithUseIPv4(useIPv4 bool) Option {
	return func(i *IPScanner) {
		i.options.UseIPv4 = useIPv4
	}
}

func WithUseIPv6(useIPv6 bool) Option {
	return func(i *IPScanner) {
		i.options.UseIPv6 = useIPv6
	}
}

func WithDialer(d dialer.TDialerFunc) Option {
	return func(i *IPScanner) {
		i.options.RawDialerFunc = d
		i.options.HttpClient = statute.DefaultHTTPClient(i.options.RawDialerFunc, i.options.TLSDialerFunc)
		dialer.RawDialFunc = d
		i.options.Dialer = &dialer.AppDialer{Timeout: i.options.Timeout}
	}
}

func WithTLSDialer(t dialer.TDialerFunc) Option {
	return func(i *IPScanner) {
		i.options.TLSDialerFunc = t
		i.options.HttpClient = statute.DefaultHTTPClient(i.options.RawDialerFunc, i.options.TLSDialerFunc)
		dialer.TLSDialFunc = t
		i.options.TLSDialer = &dialer.AppTLSDialer{Timeout: i.options.Timeout}
	}
}

func WithHttpClient(client *http.Client) Option {
	return func(i *IPScanner) {
		i.options.HttpClient = client
	}
}

func WithHttpPath(path string) Option {
	return func(i *IPScanner) {
		i.options.HTTPPath = path
	}
}

func WithLogger(logger statute.Logger) Option {
	return func(i *IPScanner) {
		i.options.Logger = logger
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(i *IPScanner) {
		i.options.Timeout = timeout
	}
}

func WithInsecureSkipVerify(insecureSkipVerify bool) Option {
	return func(i *IPScanner) {
		i.options.InsecureSkipVerify = insecureSkipVerify
	}
}

func WithHostname(hostname string) Option {
	return func(i *IPScanner) {
		i.options.Hostname = hostname
	}
}

func WithPort(port uint16) Option {
	return func(i *IPScanner) {
		i.options.Port = port
	}
}

func WithCidrList(cidrList []string) Option {
	return func(i *IPScanner) {
		i.options.CidrList = cidrList
	}
}

func WithHTTPPing() Option {
	return func(i *IPScanner) {
		i.options.SelectedOps |= statute.HTTPPing
	}
}

func WithQUICPing() Option {
	return func(i *IPScanner) {
		i.options.SelectedOps |= statute.QUICPing
	}
}

func WithTCPPing() Option {
	return func(i *IPScanner) {
		i.options.SelectedOps |= statute.TCPPing
	}
}

func WithTLSPing() Option {
	return func(i *IPScanner) {
		i.options.SelectedOps |= statute.TLSPing
	}
}

func WithIPQueueSize(size int) Option {
	return func(i *IPScanner) {
		i.options.IPQueueSize = size
	}
}

func WithMaxDesirableRTT(threshold int) Option {
	return func(i *IPScanner) {
		i.options.MaxDesirableRTT = threshold
	}
}

func WithIPQueueTTL(ttl time.Duration) Option {
	return func(i *IPScanner) {
		i.options.IPQueueTTL = ttl
	}
}

func WithIPQueueChangeCallback(callback statute.TIPQueueChangeCallback) Option {
	return func(i *IPScanner) {
		i.options.IPQueueChangeCallback = callback
	}
}

func (i *IPScanner) SetIPQueueChangeCallback(callback statute.TIPQueueChangeCallback) {
	i.options.IPQueueChangeCallback = callback
}

// run engine and in case of new event call onChange callback also if it gets canceled with context
// cancel all operations

func (i *IPScanner) Run() {
	if !i.options.UseIPv4 && !i.options.UseIPv6 {
		i.logger.Error("Fatal: both IPv4 and IPv6 are disabled, nothing to do")
		return
	}
	i.engine = engine.NewScannerEngine(&i.options, context.Background())
	i.engine.Run()
}
