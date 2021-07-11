package main

import (
	"context"
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

// timeKeeper updates the timestamp at periodic intervals
func (t *AtomicTimestamp) timeKeeper(ctx context.Context, step time.Duration) {
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
