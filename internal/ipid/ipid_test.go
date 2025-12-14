package ipid

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSingleton(t *testing.T) {
	pool1 := NewPool()
	pool2 := NewPool()
	assert.Same(t, pool1, pool2)
}

// newPool returns a new IP ID pool. Unlike `NewPool`, this function does not
// return a singleton to help with tests.
func newPool() *Pool {
	return &Pool{
		ipids: make(map[uint16]time.Time),
	}
}

func TestIPIDPoolExhaustion(t *testing.T) {
	p := newPool()

	// Exhaust the global state.
	for range math.MaxUint16 {
		_, err := p.Borrow()
		require.NoError(t, err)
	}
	assert.Equal(t, p.Size(), math.MaxUint16)

	// The global state is now full. Subsequent requests for IP IDs should
	// return an error.
	_, err := p.Borrow()
	assert.ErrorIs(t, err, ErrNoMoreIds)
}

func TestBorrowAndRelease(t *testing.T) {
	p := newPool()

	numIDs := 100
	borrowed := make(map[uint16]struct{})
	for range numIDs {
		id, err := p.Borrow()
		require.NoError(t, err)
		borrowed[id] = struct{}{}
	}
	assert.Equal(t, numIDs, p.Size())
	assert.Equal(t, numIDs, len(borrowed))

	for id := range borrowed {
		p.Release(id)
	}
	assert.Equal(t, p.Size(), 0)
}

func BenchmarkBorrow(b *testing.B) {
	for b.Loop() {
		p := newPool()
		for range math.MaxUint16 {
			_, err := p.Borrow()
			require.NoError(b, err)
		}
	}
}
