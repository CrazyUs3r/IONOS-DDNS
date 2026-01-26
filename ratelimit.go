package main

import (
	"math"
	"time"
)

// ============================================================================
// RATE LIMITER
// ============================================================================

func NewRateLimiter(maxTokens float64, refillPerSecond float64) *RateLimiter {
	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillPerSecond,
		lastRefill: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens = math.Min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)
	rl.lastRefill = now

	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}

	return false
}

func (rl *RateLimiter) Remaining() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	tokens := math.Min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)

	return int(tokens)
}

func NewIPRateLimiter(tokensPerIP, refillRate float64) *IPRateLimiter {
	limiter := &IPRateLimiter{
		limiters:    make(map[string]*RateLimiter),
		cleanup:     5 * time.Minute,
		tokensPerIP: tokensPerIP,
		refillRate:  refillRate,
	}
	go limiter.cleanupRoutine()
	return limiter
}

func (ipl *IPRateLimiter) GetLimiter(ip string) *RateLimiter {
	ipl.mu.RLock()
	limiter, exists := ipl.limiters[ip]
	ipl.mu.RUnlock()

	if exists {
		return limiter
	}

	ipl.mu.Lock()
	defer ipl.mu.Unlock()

	if limiter, exists := ipl.limiters[ip]; exists {
		return limiter
	}

	limiter = NewRateLimiter(ipl.tokensPerIP, ipl.refillRate)
	ipl.limiters[ip] = limiter

	return limiter
}

func (ipl *IPRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(ipl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		ipl.mu.Lock()

		for ip, limiter := range ipl.limiters {
			limiter.mu.Lock()
			inactive := time.Since(limiter.lastRefill) > ipl.cleanup
			limiter.mu.Unlock()

			if inactive {
				delete(ipl.limiters, ip)
			}
		}

		ipl.mu.Unlock()
	}
}
