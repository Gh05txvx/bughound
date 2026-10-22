package audit

import (
	"context"
	"sync"
	"time"
)

// MemLog adalah Log in-memory (test / ephemeral).
type MemLog struct {
	key    []byte
	now    func() time.Time
	mu     sync.Mutex
	events []Event
}

// NewMemLog membuat log in-memory dengan kunci HMAC key.
func NewMemLog(key []byte) *MemLog {
	return &MemLog{key: key, now: time.Now}
}

func (l *MemLog) Append(ctx context.Context, e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	e.Seq = int64(len(l.events)) + 1
	prev := ""
	if n := len(l.events); n > 0 {
		prev = l.events[n-1].Hash
	}
	e.PrevHash = prev
	e.Hash = mac(l.key, prev, e)
	l.events = append(l.events, e)
	return e, nil
}

func (l *MemLog) List(ctx context.Context, f Filter) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]Event, len(l.events))
	copy(cp, l.events)
	return applyFilter(cp, f), nil
}

func (l *MemLog) Verify(ctx context.Context) (Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return verifyChain(l.key, l.events), nil
}

func (l *MemLog) Close() error { return nil }
