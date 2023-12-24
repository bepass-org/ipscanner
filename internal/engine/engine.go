package engine

import (
	"context"
	"github.com/bepass-org/ipscanner/internal/iterator"
	"github.com/bepass-org/ipscanner/internal/ping"
	"github.com/bepass-org/ipscanner/internal/statute"
	"net"
	"time"
)

type Engine struct {
	generator  *iterator.IpGenerator
	ipQueue    *IPQueue
	ctx        context.Context
	cancelFunc context.CancelFunc
	ping       func(net.IP) (int, error)
	statute.Logger
}

func NewScannerEngine(opts *statute.ScannerOptions, ctx ...context.Context) *Engine {
	queue := NewIPQueue(opts.IPBasketSize)
	var contextToUse context.Context
	var cancel context.CancelFunc

	if len(ctx) > 0 {
		contextToUse = ctx[0]
	} else {
		contextToUse, cancel = context.WithCancel(context.Background())
	}

	return &Engine{
		ipQueue:    queue,
		ctx:        contextToUse,
		cancelFunc: cancel,
		ping:       ping.Do,
		generator:  iterator.NewIterator(opts.CidrList),
	}
}

func (e *Engine) GetAvailableIPs() []net.IP {
	return e.ipQueue.AvailableIPs()
}

func (e *Engine) Run() {
	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			select {
			case <-e.ipQueue.available:
				e.Logger.Debug("New Scanning Round Started")
				batch, err := e.generator.NextBatch()
				if err != nil {
					e.Logger.Error("Error while generating IP: %v", err)
					// in case of disastrous error, to prevent resource draining wait for 2 seconds and try again
					time.Sleep(2 * time.Second)
					continue
				}
				for _, ip := range batch {
					e.Logger.Debug("Pinging IP: %s", ip)
					if rtt, err := e.ping(ip); err == nil {
						if rtt < 400 {
							ipInfo := IPInfo{
								IP:        ip,
								RTT:       rtt,
								CreatedAt: time.Now(),
							}
							if !e.ipQueue.Enqueue(ipInfo) {
								<-e.ipQueue.available
							}
						}
					}
				}
			default:
				e.ipQueue.Expire()
			}
		}
	}
}

func (e *Engine) Cancel() {
	e.cancelFunc()
}
