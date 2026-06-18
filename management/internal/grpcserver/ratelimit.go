package grpcserver

import (
	"sync"
	"time"
)

// rateLimiter implements a per-key token bucket rate limiter.
// Default: 5 attempts per 60 seconds per source IP.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	cleaned time.Time
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

const (
	rlCapacity = 5.0
	rlRate     = 5.0 / 60.0 // tokens per second
)

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		cleaned: time.Now(),
	}
}

// Allow returns true if the key is within rate limits.
func (r *rateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Periodically evict idle buckets.
	if now.Sub(r.cleaned) > 2*time.Minute {
		for k, b := range r.buckets {
			if now.Sub(b.lastTime) > 5*time.Minute {
				delete(r.buckets, k)
			}
		}
		r.cleaned = now
	}

	b, ok := r.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: rlCapacity - 1, lastTime: now}
		r.buckets[key] = b
		return true
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rlRate
	if b.tokens > rlCapacity {
		b.tokens = rlCapacity
	}
	b.lastTime = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
