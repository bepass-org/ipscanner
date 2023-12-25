package engine

import (
	"github.com/bepass-org/ipscanner/internal/statute"
	"net"
	"sort"
	"sync"
	"time"
)

type IPQueue struct {
	queue        []statute.IPInfo
	maxQueueSize int
	mu           sync.Mutex
	available    chan struct{}
	maxTTL       time.Duration
	rttThreshold int
	inIdealMode  bool
	wg           sync.WaitGroup
}

func NewIPQueue(rttThreshold, maxQueueSize int, maxTTL time.Duration) *IPQueue {
	return &IPQueue{
		queue:        make([]statute.IPInfo, 0),
		maxQueueSize: maxQueueSize,
		maxTTL:       maxTTL,
		rttThreshold: rttThreshold,
		available:    make(chan struct{}, maxQueueSize),
	}
}

func (q *IPQueue) Enqueue(info statute.IPInfo) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Sort the queue every time when a new item is being enqueued to maintain order
	sort.Slice(q.queue, func(i, j int) bool {
		return q.queue[i].RTT < q.queue[j].RTT
	})

	if len(q.queue) == 0 {
		// If the queue is empty, add the item immediately.
		q.queue = append(q.queue, info)
		q.available <- struct{}{}
		q.wg.Add(1)
		return false
	}

	// Check if the new item's RTT is less than at least one of the members.
	if info.RTT < q.queue[len(q.queue)-1].RTT {
		if len(q.queue) >= q.maxQueueSize {
			// If the queue is full, remove the item with the highest RTT.
			q.queue = q.queue[:len(q.queue)-1]
		}

		// Insert the new item in a sorted position.
		index := sort.Search(len(q.queue), func(i int) bool { return q.queue[i].RTT > info.RTT })
		q.queue = append(q.queue[:index], append([]statute.IPInfo{info}, q.queue[index:]...)...)

		q.available <- struct{}{}
		q.wg.Add(1)
	}

	for _, member := range q.queue {
		if member.RTT > q.rttThreshold {
			return false // If any member has a higher RTT than the threshold, return false.
		}
	}

	if len(q.queue) < q.maxQueueSize {
		// the queue isn't full dont wait
		return false
	}

	q.inIdealMode = true
	// ok wait for expiration signal
	return true
}

func (q *IPQueue) Dequeue() (statute.IPInfo, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) == 0 {
		return statute.IPInfo{}, false
	}

	info := q.queue[len(q.queue)-1]
	q.queue = q.queue[0 : len(q.queue)-1]

	<-q.available
	q.wg.Done()

	return info, true
}

func (q *IPQueue) Expire() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.inIdealMode {
		// if we are not in ideal mode, we don't need to expire
		return
	}

	for i := 0; i < len(q.queue); i++ {
		if time.Since(q.queue[i].CreatedAt) > q.maxTTL {
			q.queue = append(q.queue[:i], q.queue[i+1:]...)
			i--
			q.wg.Done() // Release a slot in wait group
		}
	}
}

func (q *IPQueue) AvailableIPs() []net.IP {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Create a separate slice for sorting
	sortedQueue := make([]statute.IPInfo, len(q.queue))
	copy(sortedQueue, q.queue)

	// Sort by RTT ascending
	sort.Slice(sortedQueue, func(i, j int) bool {
		return sortedQueue[i].RTT < sortedQueue[j].RTT
	})

	ips := make([]net.IP, len(sortedQueue))
	for i, info := range sortedQueue {
		ips[i] = info.IP
	}

	return ips
}
