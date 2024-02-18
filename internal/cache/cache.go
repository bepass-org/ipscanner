package cache

import (
	"net"
	"sync"
	"github.com/hashicorp/golang-lru"
	"math/big"
)

type BiDirectionalCache struct {
	ipToBigIntCache *lru.Cache
	bigIntToIPCache *lru.Cache
	lock            sync.RWMutex
}

func NewBiDirectionalCache(size int) (*BiDirectionalCache, error) {
	ipToBigInt, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	bigIntToIP, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	return &BiDirectionalCache{
		ipToBigIntCache: ipToBigInt,
		bigIntToIPCache: bigIntToIP,
	}, nil
}

func (c *BiDirectionalCache) GetIPFromBigInt(bigIntKey string) (net.IP, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if ip, found := c.bigIntToIPCache.Get(bigIntKey); found {
		return ip.(net.IP), true
	}
	return nil, false
}

func (c *BiDirectionalCache) GetBigIntFromIP(ip net.IP) (*big.Int, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if bigInt, found := c.ipToBigIntCache.Get(ip.String()); found {
		return bigInt.(*big.Int), true
	}
	return nil, false
}

func (c *BiDirectionalCache) PutIPAndBigInt(ip net.IP, bigInt *big.Int) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.ipToBigIntCache.Add(ip.String(), bigInt)
	c.bigIntToIPCache.Add(bigInt.String(), ip)
}
