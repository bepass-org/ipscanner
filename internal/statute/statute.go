package statute

import (
	"github.com/bepass-org/ipscanner/internal/dialer"
	"net/http"
	"time"
)

type ScannerOptions struct {
	UseIPv4            bool
	UseIPv6            bool
	CidrList           []string // CIDR ranges to scan
	SelectedOps        []string
	Logger             Logger
	Timeout            time.Duration
	InsecureSkipVerify bool
	Dialer             *dialer.AppDialer
	TLSDialer          *dialer.AppTLSDialer
	RawDialerFunc      dialer.TDialerFunc
	TLSDialerFunc      dialer.TDialerFunc
	HttpClient         *http.Client
	HTTPPath           string
	Hostname           string
	IPBasketSize       int
}
