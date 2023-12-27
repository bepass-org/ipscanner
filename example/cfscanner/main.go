package main

import "github.com/bepass-org/ipscanner"

func main() {
	// new scanner
	scanner := ipscanner.NewScanner()
	scanner.Run()
}
