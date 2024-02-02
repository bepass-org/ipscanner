package main

import (
	"crypto/rand"
	"fmt"
	"github.com/bepass-org/ipscanner"
	"net"
	"time"
)

func canConnectIPv6(remoteAddr string) bool {
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := dialer.Dial("tcp6", remoteAddr)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func main() {
	// new scanner
	scanner := ipscanner.NewScanner(
		ipscanner.WithWarpPing(),
		ipscanner.WithWarpPrivateKey("yGXeX7gMyUIZmK5QIgC7+XX5USUSskQvBYiQ6LdkiXI="),
		ipscanner.WithWarpPeerPublicKey("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="),
		ipscanner.WithUseIPv6(canConnectIPv6("[2001:4860:4860::8888]:80")),
		ipscanner.WithUseIPv4(true),
		ipscanner.WithMaxDesirableRTT(2000),
		ipscanner.WithCidrList([]string{
			"162.159.192.0/24",
			"162.159.193.0/24",
			"162.159.195.0/24",
			"188.114.96.0/24",
			"188.114.97.0/24",
			"188.114.98.0/24",
			"188.114.99.0/24",
			"2606:4700:d0::/48",
			"2606:4700:d1::/48",
		}),
	)
	scanner.Run()
	var ipList []net.IP
	for {
		ipList = scanner.GetAvailableIPS()
		if len(ipList) > 2 {
			scanner.Stop()
			break
		}
		time.Sleep(1 * time.Second)
	}
	var result []string
	for i := 0; i < 2; i++ {
		result = append(result, ipToAddress(ipList[i]))
	}
	fmt.Println(result)
	time.Sleep(15 * time.Second)
}

func ipToAddress(ip net.IP) string {
	ports := []int{500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
		943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701,
		1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886}

	// Pick a random port number
	b := make([]byte, 8)
	n, err := rand.Read(b)
	if n != 8 {
		panic(n)
	} else if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s:%d", ip.String(), ports[int(b[0])%len(ports)])
}
