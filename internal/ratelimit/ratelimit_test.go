package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestClampConfig(t *testing.T) {
	if l := New(Config{}); l.RPS() != defaultRPS {
		t.Errorf("default rps = %v, want %v", l.RPS(), defaultRPS)
	}
	if l := New(Config{RequestsPerSecond: -5}); l.RPS() != defaultRPS {
		t.Errorf("a negative rps must fall back to the default, got %v", l.RPS())
	}
	if l := New(Config{RequestsPerSecond: 10000}); l.RPS() != maxRPS {
		t.Errorf("an excessive rps must be clamped to %v, got %v", maxRPS, l.RPS())
	}
	if l := New(Config{Burst: 0}); l.Burst() != defaultBurst {
		t.Errorf("burst<1 must fall back to the default, got %v", l.Burst())
	}
	if l := New(Config{Burst: 9999}); l.Burst() != maxBurst {
		t.Errorf("an excessive burst must be clamped to %v, got %v", maxBurst, l.Burst())
	}
}

func TestWaitAllowsBurstThenImmediate(t *testing.T) {
	l := New(Config{RequestsPerSecond: 1, Burst: 3})
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("Wait %d: %v", i, err)
		}
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("3 burst tokens should be immediate, took %v", d)
	}
}

func TestWaitRespectsCanceledContext(t *testing.T) {
	l := New(Config{RequestsPerSecond: 1, Burst: 1})
	if err := l.Wait(context.Background()); err != nil { // drain the burst
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Error("Wait with a cancelled ctx must error, not pass without a token")
	}
}
