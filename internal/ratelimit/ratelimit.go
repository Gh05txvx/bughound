// Package ratelimit menyediakan pembatas laju yang WAJIB ada di jalur eksekusi
// engine (prinsip bughound: "rate limiter ada di jalur eksekusi dan tidak mudah
// dimatikan"). Konfigurasi yang tidak sah dijepit ke nilai aman, dan tidak ada
// opsi untuk menonaktifkannya atau menjadikannya tak terbatas.
package ratelimit

import (
	"context"
	"fmt"

	"golang.org/x/time/rate"
)

const (
	defaultRPS   = 5.0  // laju default bila tak dikonfigurasi
	maxRPS       = 50.0 // batas atas: mencegah "praktis tanpa batas"
	defaultBurst = 1
	maxBurst     = 100
)

// Config mengatur laju per program.
type Config struct {
	RequestsPerSecond float64
	Burst             int
}

// Limiter membungkus token-bucket. Selalu aktif; Wait selalu memberlakukan laju.
type Limiter struct {
	rl    *rate.Limiter
	rps   float64
	burst int
}

// New membuat Limiter. Nilai tak sah dijepit ke rentang aman sehingga limiter
// tidak pernah bisa dimatikan lewat konfigurasi:
//   - RPS <= 0        => defaultRPS
//   - RPS > maxRPS    => maxRPS (tak boleh tak terbatas)
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

// Wait memblok sampai satu token tersedia atau ctx dibatalkan. Tidak pernah
// lolos tanpa token: bila ctx batal, mengembalikan error (bukan diam-diam jalan).
func (l *Limiter) Wait(ctx context.Context) error {
	if err := l.rl.Wait(ctx); err != nil {
		return fmt.Errorf("ratelimit: menunggu token dibatalkan: %w", err)
	}
	return nil
}

// RPS mengembalikan laju efektif (setelah penjepitan).
func (l *Limiter) RPS() float64 { return l.rps }

// Burst mengembalikan burst efektif (setelah penjepitan).
func (l *Limiter) Burst() int { return l.burst }
