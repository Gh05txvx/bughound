// Package ratelimit provides the rate limiter that must sit in the engine
// execution path (bughound principle: "the rate limiter is in the execution
// path and is not easy to turn off"). Invalid configuration is clamped to safe
// values, and there is no option to disable the limiter or make it unlimited.
package ratelimit

import (
	"context"
	"fmt"

	"golang.org/x/time/rate"
)

const (
	defaultRPS   = 5.0  // default rate when not configured
	maxRPS       = 50.0 // upper bound: prevents "practically unlimited"
	defaultBurst = 1
	maxBurst     = 100
)

// Config sets the rate per program.
type Config struct {
	RequestsPerSecond float64
	Burst             int
}

// Limiter wraps a token bucket. It is always on; Wait always enforces the rate.
type Limiter struct {
	rl    *rate.Limiter
	rps   float64
	burst int
}

// New creates a Limiter. Invalid values are clamped to a safe range, so the
// limiter can never be turned off through configuration:
//   - RPS <= 0        => defaultRPS
//   - RPS > maxRPS    => maxRPS (must not be unlimited)
//   - Burst < 1       => defaultBurst
//   - Burst > maxBurst => maxBurst
func New(cfg Config) *Limiter {
	rps := cfg.RequestsPerSecond
	switch {
	case rps <= 0:
		rps = defaultRPS
	case rps > maxRPS:
		rps = maxRPS
	}
	b := cfg.Burst
	switch {
	case b < 1:
		b = defaultBurst
	case b > maxBurst:
		b = maxBurst
	}
	return &Limiter{rl: rate.NewLimiter(rate.Limit(rps), b), rps: rps, burst: b}
}

// Wait blocks until a token is available or ctx is cancelled. It never passes
// without a token: when ctx is cancelled it returns an error and the call does
// not go through.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := l.rl.Wait(ctx); err != nil {
		return fmt.Errorf("ratelimit: wait for token cancelled: %w", err)
	}
	return nil
}

// RPS returns the effective rate (after clamping).
func (l *Limiter) RPS() float64 { return l.rps }

// Burst returns the effective burst (after clamping).
func (l *Limiter) Burst() int { return l.burst }
