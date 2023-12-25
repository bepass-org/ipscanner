package ping

import (
	"fmt"
	"github.com/bepass-org/ipscanner/internal/statute"
	"net"
)

type Ping struct {
	IP      net.IP
	options statute.ScannerOptions
}

// Do ping
func (p *Ping) Do(ip net.IP) (int, error) {
	var sum, ops, hp, tp int
	var err error
	if p.options.SelectedOps&statute.HTTPPing > 0 {
		hp, err = p.httpPing(ip)
		if err != nil {
			return 0, err
		}
		ops++
		sum += hp
	}
	if p.options.SelectedOps&statute.TLSPing > 0 {
		tp, err = p.tlsPing(ip)
		if err != nil {
			return 0, err
		}
		ops++
		sum += tp
	}
	if p.options.SelectedOps&statute.TCPPing > 0 {
		tp, err = p.tcpPing(ip)
		if err != nil {
			return 0, err
		}
		ops++
		sum += tp
	}
	if p.options.SelectedOps&statute.QUICPing > 0 {
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
				p.options.Hostname,
				p.options.Port,
				p.options.HTTPPath,
			),
			p.options.Timeout,
		),
	)
}

func (p *Ping) tlsPing(ip net.IP) (int, error) {
	return p.calc(
		NewTlsPing(ip, p.options.Hostname, p.options.Port, p.options.Timeout, p.options.Timeout),
	)
}

func (p *Ping) tcpPing(ip net.IP) (int, error) {
	return p.calc(
		NewTcpPing(ip, p.options.Hostname, p.options.Port, p.options.Timeout),
	)
}

func (p *Ping) quicPing(ip net.IP) (int, error) {
	return p.calc(
		NewQuicPing(ip, p.options.Hostname, p.options.Port, p.options.Timeout),
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
