package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// UnixTimestamp is used to avoid magic int64 type
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

type TimeKeeper struct {
	// Must be the first field in every embedding struct
	timestamp  AtomicTimestamp
	cancelCtx  context.Context
	cancelFunc context.CancelFunc
	Mutex      sync.Mutex
	Group      sync.WaitGroup
}

func (t *TimeKeeper) Tick(step time.Duration) {
	t.cancelCtx, t.cancelFunc = context.WithCancel(context.Background())
	t.Group.Add(1)
	go func() {
		defer t.Group.Done()
		t.timestamp.Tick(t.cancelCtx, step)
	}()
}

func (t *TimeKeeper) Clock() UnixTimestamp {
	return t.timestamp.Load()
}

func (t *TimeKeeper) Cancel() {
	var cancelFunc context.CancelFunc
	t.Mutex.Lock()
	if t.cancelFunc == nil {
		t.Mutex.Unlock()
		return
	}
	cancelFunc = t.cancelFunc
	t.cancelFunc = nil
	t.Mutex.Unlock()
	cancelFunc()
	t.Group.Wait()
}
