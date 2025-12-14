package ipid

import (
	"errors"
	"log"
	"math"
	"math/rand"
	"sync"
	"time"
)

const ipidTimeout = time.Second * 10

var (
	ErrNoMoreIds = errors.New("all IP IDs are currently in flight")

	instance *Pool
	once     sync.Once
)

// Pool keeps track of IP IDs that we use for traceroutes.
type Pool struct {
	sync.Mutex // Guards ipids.
	ipids      map[uint16]time.Time
}

// NewPool returns a new IP ID pool. The pool is a singleton because IP IDs are
// shared across all traceroutes.
func NewPool() *Pool {
	once.Do(func() {
		instance = &Pool{
			ipids: make(map[uint16]time.Time),
		}
	})
	return instance
}

// Size returns the number of IP IDs that are currently in flight.
func (s *Pool) Size() int {
	s.Lock()
	defer s.Unlock()

	return len(s.ipids)
}

// Borrow "borrows" an IP ID that's meant to be returned later.
func (s *Pool) Borrow() (uint16, error) {
	s.Lock()
	defer s.Unlock()

	if len(s.ipids) == math.MaxUint16 {
		return 0, ErrNoMoreIds
	}

	// Start at a random index and look for available IP IDs.  The id may wrap
	// back to 0.
	start := uint16(rand.Intn(math.MaxUint16))
	for id := start + 1; id != start; id++ {
		if _, exists := s.ipids[id]; !exists {
			s.ipids[id] = time.Now().UTC()
			return id, nil
		}
	}
	return 0, ErrNoMoreIds // Should never happen.
}

// ReleaseUnanswered releases expired IP IDs that were not explicitly released.
func (s *Pool) ReleaseUnanswered() {
	s.Lock()
	defer s.Unlock()

	var (
		before = len(s.ipids)
		now    = time.Now().UTC()
	)

	for id, added := range s.ipids {
		if now.Sub(added) > ipidTimeout {
			delete(s.ipids, id)
		}
	}
	numPruned := before - len(s.ipids)
	if numPruned > 0 {
		log.Printf("Pruned %d un-released IP IDs.", numPruned)
	}
}

// Release returns a previously-borrowed IP ID.
func (s *Pool) Release(id uint16) {
	s.Lock()
	defer s.Unlock()

	delete(s.ipids, id)
}
