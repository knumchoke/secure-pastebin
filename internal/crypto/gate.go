package crypto

import (
	"context"
	"errors"
	"time"
)

// ErrBusy is returned when the gate cannot be acquired within the queue timeout.
var ErrBusy = errors.New("crypto: kdf gate busy")

// Gate bounds the number of concurrent memory-hard KDF operations (spec D16).
type Gate struct {
	slots   chan struct{}
	timeout time.Duration
}

// NewGate creates a gate with maxConcurrent slots and a wait budget.
func NewGate(maxConcurrent int, queueTimeout time.Duration) *Gate {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &Gate{slots: make(chan struct{}, maxConcurrent), timeout: queueTimeout}
}

// Acquire blocks until a slot is free, ctx is done, or the timeout elapses.
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	timer := time.NewTimer(g.timeout)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		return func() { <-g.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrBusy
	}
}
