package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestClampConfig(t *testing.T) {
	if l := New(Config{}); l.RPS() != defaultRPS {
		t.Errorf("default rps = %v, ingin %v", l.RPS(), defaultRPS)
	}
	if l := New(Config{RequestsPerSecond: -5}); l.RPS() != defaultRPS {
		t.Errorf("rps negatif harus jadi default, dapat %v", l.RPS())
	}
	if l := New(Config{RequestsPerSecond: 10000}); l.RPS() != maxRPS {
		t.Errorf("rps berlebih harus dijepit ke %v, dapat %v", maxRPS, l.RPS())
	}
	if l := New(Config{Burst: 0}); l.Burst() != defaultBurst {
		t.Errorf("burst<1 harus default, dapat %v", l.Burst())
	}
	if l := New(Config{Burst: 9999}); l.Burst() != maxBurst {
		t.Errorf("burst berlebih harus dijepit ke %v, dapat %v", maxBurst, l.Burst())
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
		t.Errorf("3 token burst seharusnya langsung, butuh %v", d)
	}
}

func TestWaitRespectsCanceledContext(t *testing.T) {
	l := New(Config{RequestsPerSecond: 1, Burst: 1})
	if err := l.Wait(context.Background()); err != nil { // habiskan burst
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Error("Wait dengan ctx dibatalkan harus error, bukan lolos tanpa token")
	}
}
