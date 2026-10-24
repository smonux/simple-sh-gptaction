package auth

import (
	"sync"
	"time"
)

const loginAttemptLimit = 5
const loginAttemptWindow = time.Minute

// A single-owner account uses one global budget. Rotating client IP addresses
// or forging proxy headers cannot bypass it; no unbounded per-IP map is kept.
type loginLimiter struct {
	mu      sync.Mutex
	used    int
	resetAt time.Time
}

func (l *loginLimiter) retryAfter(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.resetAt) {
		l.used = 0
		l.resetAt = now.Add(loginAttemptWindow)
	}
	if l.used >= loginAttemptLimit {
		return int(l.resetAt.Sub(now).Seconds()) + 1
	}
	l.used++
	return 0
}
