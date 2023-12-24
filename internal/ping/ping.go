package ping

import (
	"net"
	"time"
)

func Do(ip net.IP) (int, error) {
	// sum all available ping methods
	sum := 0
	hp, err := httpPing(ip)
	if err != nil {
		return 0, err
	}
	sum += hp
	tp, err := tlsPing(ip)
	if err != nil {
		return 0, err
	}
	sum += tp
	tp, err = tcpPing(ip)
	if err != nil {
		return 0, err
	}
	sum += tp
	return sum / 3, nil
}

func httpPing(ip net.IP) (int, error) {
	hp := NewHttpPing("GET", "https://"+ip.String()+"/", 5*time.Second)
	hp.IP = ip
	pr := hp.Ping()
	err := pr.Error()
	if err != nil {
		return 0, err
	}
	return pr.Result(), nil
}

func tlsPing(ip net.IP) (int, error) {
	tp := NewTlsPing(ip.String(), 443, 5*time.Second, 5*time.Second)
	tp.IP = ip
	pr := tp.Ping()
	err := pr.Error()
	if err != nil {
		return 0, err
	}
	return pr.Result(), nil
}

func tcpPing(ip net.IP) (int, error) {
	tp := NewTcpPing(ip.String(), 443, 5*time.Second)
	pr := tp.Ping()
	err := pr.Error()
	if err != nil {
		return 0, err
	}
	return pr.Result(), nil
}
