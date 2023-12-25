package ping

import (
	"fmt"
	"github.com/bepass-org/ipscanner/internal/statute"
	"net"
)

type Ping struct {
	Options *statute.ScannerOptions
}

// DoPing performs a ping on the given IP address.
func (p *Ping) DoPing(ip net.IP) (int, error) {
	var sum, ops, hp, tp int
	var err error
	if p.Options.SelectedOps&statute.HTTPPing > 0 {
		hp, err = p.httpPing(ip)
		if err != nil {
			return 0, err
		}
		ops++
		sum += hp
	}
	if p.Options.SelectedOps&statute.TLSPing > 0 {
		tp, err = p.tlsPing(ip)
		if err != nil {
			return 0, err
		}
		ops++
		sum += tp
	}
	if p.Options.SelectedOps&statute.TCPPing > 0 {
		tp, err = p.tcpPing(ip)
		if err != nil {
			return 0, err
		}
		ops++
		sum += tp
	}
	if p.Options.SelectedOps&statute.QUICPing > 0 {
		tp, err = p.quicPing(ip)
		if err != nil {
			return 0, err
		}
		ops++
		sum += tp
	}
	if ops == 0 {
		return 99, nil
	}
	return sum / ops, nil
}

func (p *Ping) httpPing(ip net.IP) (int, error) {
	return p.calc(
		NewHttpPing(
			ip,
			"GET",
			fmt.Sprintf(
				"https://%s:%d%s",
				p.Options.Hostname,
				p.Options.Port,
				p.Options.HTTPPath,
			),
			p.Options.Timeout,
		),
	)
}

func (p *Ping) tlsPing(ip net.IP) (int, error) {
	return p.calc(
		NewTlsPing(ip, p.Options.Hostname, p.Options.Port, p.Options.Timeout, p.Options.Timeout),
	)
}

func (p *Ping) tcpPing(ip net.IP) (int, error) {
	return p.calc(
		NewTcpPing(ip, p.Options.Hostname, p.Options.Port, p.Options.Timeout),
	)
}

func (p *Ping) quicPing(ip net.IP) (int, error) {
	return p.calc(
		NewQuicPing(ip, p.Options.Hostname, p.Options.Port, p.Options.Timeout),
	)
}

func (p *Ping) calc(tp statute.IPing) (int, error) {
	pr := tp.Ping()
	err := pr.Error()
	if err != nil {
		return 0, err
	}
	return pr.Result(), nil
}
