package iterator

import (
	"crypto/rand"
	"fmt"
	"github.com/bepass-org/ipscanner/internal/statute"
	"log"
	"math/big"
	"net"
	"strings"
	"github.com/bepass-org/ipscanner/internal/cache"
)

// LCG represents a linear congruential generator with full period.
type LCG struct {
	modulus    *big.Int
	multiplier *big.Int
	increment  *big.Int
	current    *big.Int
}

// NewLCG creates a new LCG instance with a given size.
func NewLCG(size *big.Int) *LCG {
	modulus := new(big.Int).Set(size)

	// Generate random multiplier (a) and increment (c) that satisfy Hull-Dobell Theorem
	var multiplier, increment *big.Int
	for {
		var err error
		multiplier, err = rand.Int(rand.Reader, modulus)
		if err != nil {
			continue
		}
		increment, err = rand.Int(rand.Reader, modulus)
		if err != nil {
			continue
		}

		// Check Hull-Dobell Theorem conditions
		if checkHullDobell(modulus, multiplier, increment) {
			break
		}
	}

	return &LCG{
		modulus:    modulus,
		multiplier: multiplier,
		increment:  increment,
		current:    big.NewInt(0),
	}
}

// checkHullDobell checks if the given parameters satisfy the Hull-Dobell Theorem.
func checkHullDobell(modulus, multiplier, increment *big.Int) bool {
	// c and m are relatively prime
	gcd := new(big.Int).GCD(nil, nil, increment, modulus)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return false
	}

	// a - 1 is divisible by all prime factors of m
	aMinusOne := new(big.Int).Sub(multiplier, big.NewInt(1))

	// a - 1 is divisible by 4 if m is divisible by 4
	if new(big.Int).And(modulus, big.NewInt(3)).Cmp(big.NewInt(0)) == 0 {
		if new(big.Int).And(aMinusOne, big.NewInt(3)).Cmp(big.NewInt(0)) != 0 {
			return false
		}
	}

	return true
}

// Next generates the next number in the sequence.
func (lcg *LCG) Next() *big.Int {
	if lcg.current.Cmp(lcg.modulus) == 0 {
		return nil // Sequence complete
	}

	next := new(big.Int)
	next.Mul(lcg.multiplier, lcg.current)
	next.Add(next, lcg.increment)
	next.Mod(next, lcg.modulus)

	lcg.current.Set(next)
	return next
}

type ipRange struct {
	ipNet *net.IPNet
	lcg   *LCG
	start net.IP
	stop  net.IP
	size  *big.Int
	index *big.Int
}

func newIPRange(cidr string) (ipRange, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ipRange{}, err
	}
	size := ipRangeSize(ipNet)
	return ipRange{
		ipNet: ipNet,
		start: ipNet.IP,
		stop:  lastIP(ipNet),
		size:  size,
		index: big.NewInt(0),
		lcg:   NewLCG(size),
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

// func ipToBigInt(ip net.IP) *big.Int {
// 	return new(big.Int).SetBytes(ip)
// }

// func bigIntToIP(n *big.Int) net.IP {
// 	return net.IP(n.Bytes())
// }


var biDirectionalCache, _ = cache.NewBiDirectionalCache(1024) // initial cache size

func ipToBigInt(ip net.IP) *big.Int {
    if bigInt, found := biDirectionalCache.GetBigIntFromIP(ip); found {
        return bigInt
    }

    ip = ip.To16()
    result := new(big.Int).SetBytes(ip)

    biDirectionalCache.PutIPAndBigInt(ip, result)

    return result
}

func bigIntToIP(n *big.Int) net.IP {
    if ip, found := biDirectionalCache.GetIPFromBigInt(n.String()); found {
        return ip
    }

    ipBytes := n.Bytes()
    if len(ipBytes) < 16 {
        padded := make([]byte, 16-len(ipBytes), 16)
        ipBytes = append(padded, ipBytes...)
    }
    ip := net.IP(ipBytes)

    biDirectionalCache.PutIPAndBigInt(ip, n)

    return ip
}



func addIP(ip net.IP, num *big.Int) net.IP {
	ipInt := ipToBigInt(ip)
	ipInt.Add(ipInt, num)
	return bigIntToIP(ipInt)
}

func ipRangeSize(ipNet *net.IPNet) *big.Int {
	ones, bits := ipNet.Mask.Size()
	size := big.NewInt(1)
	size.Lsh(size, uint(bits-ones))
	return size
}

type IpGenerator struct {
	ipRanges []ipRange
}

func (g *IpGenerator) NextBatch() ([]net.IP, error) {
	var results []net.IP
	for i, r := range g.ipRanges {
		if r.index.Cmp(r.size) >= 0 {
			continue
		}
		shuffleIndex := r.lcg.Next()
		if shuffleIndex == nil {
			continue
		}
		results = append(results, addIP(r.start, shuffleIndex))
		g.ipRanges[i].index.Add(g.ipRanges[i].index, big.NewInt(1))
	}
	if len(results) == 0 {
		okFlag := false
		for i := range g.ipRanges {
			if g.ipRanges[i].index.Cmp(big.NewInt(0)) > 0 {
				okFlag = true
			}
			g.ipRanges[i].index.SetInt64(0)
		}
		if okFlag {
			// Reshuffle and start over
			for i := range g.ipRanges {
				g.ipRanges[i].lcg = NewLCG(g.ipRanges[i].size)
			}
			return g.NextBatch()
		} else {
			return nil, fmt.Errorf("no more IP addresses")
		}
	}
	return results, nil
}

// shuffleSubnetsIpRange shuffles a slice of ipRange using crypto/rand
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

		ipRange, err := newIPRange(cidr)
		if err != nil {
			fmt.Printf("Error parsing CIDR %s: %v\n", cidr, err)
			continue
		}
		ranges = append(ranges, ipRange)
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
