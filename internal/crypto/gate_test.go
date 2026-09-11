package crypto

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestGate_LimitsConcurrency(t *testing.T) {
	g := NewGate(2, 50*time.Millisecond)
	ctx := context.Background()
	r1, err := g.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Acquire(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("third acquire err = %v, want ErrBusy", err)
	}
	r1()
	r3, err := g.Acquire(ctx)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	r2()
	r3()
}

func TestGate_ContextCancel(t *testing.T) {
	g := NewGate(1, time.Second)
	r, _ := g.Acquire(context.Background())
	defer r()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestGate_NPlusOne(t *testing.T) {
	const n = 4
	g := NewGate(n, 30*time.Millisecond)
	var wg sync.WaitGroup
	var mu sync.Mutex
	busy := 0
	start := make(chan struct{})
	for i := 0; i < n+1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rel, err := g.Acquire(context.Background())
			if errors.Is(err, ErrBusy) {
				mu.Lock()
				busy++
				mu.Unlock()
				return
			}
			time.Sleep(100 * time.Millisecond)
			rel()
		}()
	}
	close(start)
	wg.Wait()
	if busy != 1 {
		t.Fatalf("busy = %d, want 1", busy)
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3}
	Zero(b)
	for _, x := range b {
		if x != 0 {
			t.Fatal("not zeroed")
		}
	}
}
