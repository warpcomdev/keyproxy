package clock

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// UnixTimestamp defined to avoid having plain int64 type in APIs.
type UnixTimestamp int64

// AtomicTimestamp stores an atomic unix timestamp
type AtomicTimestamp struct {
	timestamp UnixTimestamp
}

// Load the timestamp atomically
func (a *AtomicTimestamp) Load() UnixTimestamp {
	return UnixTimestamp(atomic.LoadInt64((*int64)(&a.timestamp)))
}

// Store the timestamp atomically
func (a *AtomicTimestamp) Store(v UnixTimestamp) {
	atomic.StoreInt64((*int64)(&a.timestamp), int64(v))
}

// Tick updates the timestamp at periodic intervals
func (t *AtomicTimestamp) Tick(ctx context.Context, step time.Duration) {
	// Keep track of time
	ticker := time.NewTicker(step)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t.Store(UnixTimestamp(now.Unix()))
		}
	}
}

// Remaining time until expiration, considering the given lifetime
func (t *AtomicTimestamp) Remaining(lifetime time.Duration) time.Duration {
	now := UnixTimestamp(time.Now().Unix())
	timestamp := t.Load()
	return time.Duration(timestamp+UnixTimestamp(lifetime/time.Second)-now) * time.Second
}

// Keeper base struct for objects that need a cancellable ticker thread
type Keeper struct {
	// Must be the first field in every embedding struct
	timestamp  AtomicTimestamp
	CancelCtx  context.Context
	CancelFunc context.CancelFunc
	Mutex      sync.Mutex
	Group      sync.WaitGroup
}

// Tick starts updating timestamp each time.Duration interval
func (t *Keeper) Tick(step time.Duration) {
	t.CancelCtx, t.CancelFunc = context.WithCancel(context.Background())
	t.Group.Add(1)
	go func() {
		defer t.Group.Done()
		t.timestamp.Tick(t.CancelCtx, step)
	}()
}

// Clock returns the current timestamp value
func (t *Keeper) Clock() UnixTimestamp {
	return t.timestamp.Load()
}

// Cancel the ticker and wait the group
func (t *Keeper) Cancel() {
	var cancelFunc context.CancelFunc
	t.Mutex.Lock()
	if t.CancelFunc == nil {
		t.Mutex.Unlock()
		return
	}
	cancelFunc = t.CancelFunc
	t.CancelFunc = nil
	t.Mutex.Unlock()
	cancelFunc()
	t.Group.Wait()
}
