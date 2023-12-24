package iterator

import (
	"fmt"
	"github.com/bepass-org/ipscanner/internal/blackrock"
	"math/big"
	"net"
	"time"
)

type ipRange struct {
	ipNet *net.IPNet
	br    *blackrock.Blackrock
	start net.IP
	stop  net.IP
	size  uint64
	index uint64
}

func newIPRange(cidr string) (ipRange, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ipRange{}, err
	}
	return ipRange{
		ipNet: ipNet,
		start: ipNet.IP,
		stop:  lastIP(ipNet),
		size:  ipRangeSize(ipNet),
		index: 0,
		br:    blackrock.New(ipRangeSize(ipNet), blackrock.DefaultRounds, time.Now().UnixNano()),
	}, nil
}

func lastIP(ipNet *net.IPNet) net.IP {
	lastIP := make(net.IP, len(ipNet.IP))
	copy(lastIP, ipNet.IP)
	for i := range ipNet.Mask {
		lastIP[i] |= ^ipNet.Mask[i]
	}
	return lastIP
}

func ipToBigInt(ip net.IP) *big.Int {
	return new(big.Int).SetBytes(ip)
}

func bigIntToIP(n *big.Int) net.IP {
	return n.Bytes()
}

func addIP(ip net.IP, num uint64) net.IP {
	ipInt := ipToBigInt(ip)
	ipInt.Add(ipInt, big.NewInt(int64(num)))
	return bigIntToIP(ipInt)
}

// Function to calculate the number of IP addresses in a CIDR range
func ipRangeSize(ipNet *net.IPNet) uint64 {
	ones, bits := ipNet.Mask.Size()
	return 1 << uint(bits-ones)
}

type IpGenerator struct {
	ipRanges []ipRange
}

func (g *IpGenerator) NextBatch() ([]net.IP, error) {
	var results []net.IP
	for i, r := range g.ipRanges {
		if r.index >= r.size {
			continue
		}
		results = append(results, addIP(r.start, r.br.Shuffle(r.index)))
		g.ipRanges[i].index++
	}
	if len(results) == 0 {
		okFlag := false
		for i := range g.ipRanges {
			if g.ipRanges[i].index > 0 {
				okFlag = true
			}
			g.ipRanges[i].index = 0
		}
		if okFlag {
			// reshuffle and start over
			for i := range g.ipRanges {
				g.ipRanges[i].br = blackrock.New(ipRangeSize(g.ipRanges[i].ipNet), blackrock.DefaultRounds, time.Now().UnixNano())
			}
			return g.NextBatch()
		} else {
			return nil, fmt.Errorf("no more IP addresses")
		}
	}
	return results, nil
}

func NewIterator(cidrs []string) *IpGenerator {
	var ranges []ipRange
	for _, cidr := range cidrs {
		ipRange, err := newIPRange(cidr)
		if err != nil {
			fmt.Printf("Error parsing CIDR %s: %v\n", cidr, err)
			continue
		}
		ranges = append(ranges, ipRange)
	}

	return &IpGenerator{
		ipRanges: ranges,
	}
}
