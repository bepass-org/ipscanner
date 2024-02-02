package main

import "github.com/bepass-org/ipscanner"

func main() {
	// new scanner
	scanner := ipscanner.NewScanner(
		ipscanner.WithHTTPPing(),
		// TODO: fix blackrock for 128 bit
		ipscanner.WithUseIPv6(false),
	)
	go scanner.Run()
	select {}
}
