// Package main

package main

import (
	"context"
	"sync"
)

type DynamicWorkerLimiter struct {
	changed chan struct{}
	limit   int
	active  int
	mu      sync.Mutex
}

// ============================================================================
// Worker INITIALIZATION
// ============================================================================

func NewDynamicWorkerLimiter(limit int) *DynamicWorkerLimiter {
	return &DynamicWorkerLimiter{
		limit:   normalizeWorkerLimit(limit),
		changed: make(chan struct{}),
	}
}

func (l *DynamicWorkerLimiter) SetLimit(limit int) {
	limit = normalizeWorkerLimit(limit)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.limit == limit {
		return
	}

	l.limit = limit
	l.notifyLocked()
}

func (l *DynamicWorkerLimiter) Acquire(ctx context.Context) bool {
	for {
		l.mu.Lock()
		if l.active < l.limit {
			l.active++
			l.mu.Unlock()

			return true
		}

		changed := l.changed
		l.mu.Unlock()

		select {
		case <-changed:
			continue
		case <-ctx.Done():
			return false
		}
	}
}

func (l *DynamicWorkerLimiter) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.active <= 0 {
		return
	}

	l.active--
	l.notifyLocked()
}

func (l *DynamicWorkerLimiter) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

func normalizeWorkerLimit(limit int) int {
	if limit < 1 {
		return 1
	}

	return limit
}

func setWorkerConcurrencyLimit(limit int) {
	if workerLimiter == nil {
		workerLimiter = NewDynamicWorkerLimiter(limit)

		return
	}
	workerLimiter.SetLimit(limit)
}
