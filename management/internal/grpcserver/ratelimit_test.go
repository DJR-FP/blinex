package grpcserver

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsBurstThenBlocks(t *testing.T) {
	r := newRateLimiter()
	allowed := 0
	for i := 0; i < 10; i++ {
		if r.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != int(rlCapacity) {
		t.Fatalf("expected %d allowed in burst, got %d", int(rlCapacity), allowed)
	}
	if r.Allow("1.2.3.4") {
		t.Fatal("expected block after burst exhausted")
	}
}

func TestRateLimiterPerKeyIsolation(t *testing.T) {
	r := newRateLimiter()
	for i := 0; i < 10; i++ {
		r.Allow("1.1.1.1")
	}
	// A different key must have its own fresh bucket.
	if !r.Allow("2.2.2.2") {
		t.Fatal("expected independent key to be allowed")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	r := newRateLimiter()
	for i := 0; i < int(rlCapacity)+2; i++ {
		r.Allow("k")
	}
	if r.Allow("k") {
		t.Fatal("expected to be blocked")
	}
	// Simulate elapsed time by rewinding lastTime so a token refills.
	r.mu.Lock()
	r.buckets["k"].lastTime = time.Now().Add(-30 * time.Second) // 30s * (5/60)/s = 2.5 tokens
	r.mu.Unlock()
	if !r.Allow("k") {
		t.Fatal("expected allow after refill window")
	}
}
