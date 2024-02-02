package iterator

import (
	"crypto/rand"
	"fmt"
	"github.com/bepass-org/ipscanner/internal/blackrock"
	"github.com/bepass-org/ipscanner/internal/statute"
	"log"
	"math/big"
	"net"
	"strings"
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

func ipRangeSize(ipNet *net.IPNet) uint64 {
	ones, bits := ipNet.Mask.Size()
	size := big.NewInt(1)
	size.Lsh(size, uint(bits-ones))
	return size.Uint64()
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

// Helper function to split the CIDR into smaller subnets if necessary
func splitCIDR(cidr string) ([]string, error) {
	if strings.Contains(cidr, ".") {
		// if ip4
		return []string{cidr}, nil
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, _ := ipnet.Mask.Size()

	if ones >= 65 {
		return []string{cidr}, nil
	}

	additionalBits := 65 - ones
	subnetCount := 1 << additionalBits
	subnets := make([]string, 0, subnetCount)

	startIP := new(big.Int).SetBytes(ip.To16())

	for i := 0; i < subnetCount; i++ {
		offset := new(big.Int).Lsh(big.NewInt(int64(i)), uint(additionalBits))
		subnetStartIP := new(big.Int).Add(startIP, offset)
		paddedIPBytes := padIPv6Address(subnetStartIP.Bytes())

		subnet := &net.IPNet{
			IP:   paddedIPBytes,
			Mask: net.CIDRMask(65, 128),
		}
		subnets = append(subnets, subnet.String())
	}

	err = shuffleSubnets(subnets)
	if err != nil {
		return nil, err
	}

	return subnets, nil
}

func padIPv6Address(ip []byte) []byte {
	paddedIP := make([]byte, 16)
	copy(paddedIP[16-len(ip):], ip)
	return paddedIP
}

// shuffleSubnets shuffles a slice of strings using crypto/rand
func shuffleSubnets(subnets []string) error {
	for i := range subnets {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(subnets))))
		if err != nil {
			return err
		}
		j := jBig.Int64()

		subnets[i], subnets[j] = subnets[j], subnets[i]
	}
	return nil
}

// shuffleSubnets shuffles a slice of strings using crypto/rand
func shuffleSubnetsIpRange(subnets []ipRange) error {
	for i := range subnets {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(subnets))))
		if err != nil {
			return err
		}
		j := jBig.Int64()

		subnets[i], subnets[j] = subnets[j], subnets[i]
	}
	return nil
}

func NewIterator(opts *statute.ScannerOptions) *IpGenerator {
	var ranges []ipRange
	for _, cidr := range opts.CidrList {
		if !opts.UseIPv6 && strings.Contains(cidr, ":") {
			continue
		}
		if !opts.UseIPv4 && strings.Contains(cidr, ".") {
			continue
		}

		subnets, err := splitCIDR(cidr)
		if err != nil {
			fmt.Printf("Error splitting CIDR %s: %v\n", cidr, err)
			continue
		}

		for _, subnet := range subnets {
			ipRange, err := newIPRange(subnet) // Assuming newIPRange is defined elsewhere
			if err != nil {
				fmt.Printf("Error parsing CIDR %s: %v\n", subnet, err)
				continue
			}
			ranges = append(ranges, ipRange)
		}
	}
	if len(ranges) == 0 {
		log.Fatal("No valid CIDR ranges found")
	}
	err := shuffleSubnetsIpRange(ranges)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return &IpGenerator{
		ipRanges: ranges,
	}
}
