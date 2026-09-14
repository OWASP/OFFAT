package engine

import (
	"context"
	"time"
)

// limiter is a minimal token-bucket rate limiter. A zero/negative rate disables
// throttling.
type limiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newLimiter(perSec float64) *limiter {
	if perSec <= 0 {
		return &limiter{}
	}
	l := &limiter{tokens: make(chan struct{}, 1), stop: make(chan struct{})}
	interval := time.Duration(float64(time.Second) / perSec)
	if interval <= 0 {
		interval = time.Millisecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return l
}

func (l *limiter) wait(ctx context.Context) {
	if l.tokens == nil {
		return
	}
	select {
	case <-l.tokens:
	case <-ctx.Done():
	}
}

func (l *limiter) close() {
	if l.stop != nil {
		close(l.stop)
	}
}
