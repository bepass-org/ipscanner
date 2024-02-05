package main

import "github.com/bepass-org/ipscanner"

func main() {
	// new scanner
	scanner := ipscanner.NewScanner(
		ipscanner.WithHTTPPing(),
		ipscanner.WithUseIPv6(canConnectIPv6("[2001:4860:4860::8888]:80")),
	)
	go scanner.Run()
	select {}
}
