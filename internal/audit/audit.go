// Package audit stores an audit trail that stays intact and cannot be deleted
// silently (binding bughound principle #6). Each entry binds the hash of the
// previous entry in a keyed HMAC-SHA256 chain; deleting or changing an entry
// breaks the chain and Verify detects it. The API is only Append + List +
// Verify. There is no Delete or Update, so the log is append-only by contract.
//
// The HMAC key is derived from the master key (secret.Keyring.Subkey), so the
// chain cannot be recomputed without the key. Deleting or truncating the WHOLE
// log (outside the application) leaves a short chain that is still internally
// valid; optional external anchoring covers that (see anchor.go, BH-F06).
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Event is one audit entry. Append fills in Hash and PrevHash.
type Event struct {
	Seq      int64
	Time     time.Time
	Kind     string // "scope.decision" | "run.start" | "run.finish" | ...
	Program  string
	RunID    string
	Target   string
	Allowed  bool
	Reason   string
	Layer    string
	Message  string
	PrevHash string
	Hash     string
}

// content returns the canonical bytes of the entry (WITHOUT Hash/PrevHash) to be MACed.
func (e Event) content() []byte {
	type payload struct {
		Seq      int64  `json:"seq"`
		TimeNano int64  `json:"t"`
		Kind     string `json:"kind"`
		Program  string `json:"program"`
		RunID    string `json:"run_id"`
		Target   string `json:"target"`
		Allowed  bool   `json:"allowed"`
		Reason   string `json:"reason"`
		Layer    string `json:"layer"`
		Message  string `json:"message"`
	}
	b, _ := json.Marshal(payload{
		Seq: e.Seq, TimeNano: e.Time.UTC().UnixNano(), Kind: e.Kind,
		Program: e.Program, RunID: e.RunID, Target: e.Target, Allowed: e.Allowed,
		Reason: e.Reason, Layer: e.Layer, Message: e.Message,
	})
	return b
}

func mac(key []byte, prevHash string, e Event) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(prevHash))
	h.Write(e.content())
	return hex.EncodeToString(h.Sum(nil))
}

// Filter narrows List.
type Filter struct {
	Program string
	RunID   string
	Kind    string
	Limit   int
}

// Result is the outcome of Verify.
type Result struct {
	OK       bool
	Count    int64
	BrokenAt int64  // seq of the first broken entry (0 when OK)
	Reason   string // why it is broken (empty when OK)
	Anchors  int64  // number of external anchors checked (0 when there is no anchorer)
}

// Log is the append-only audit trail.
type Log interface {
	Append(ctx context.Context, e Event) (Event, error)
	List(ctx context.Context, f Filter) ([]Event, error) // newest first
	Verify(ctx context.Context) (Result, error)
	Close() error
}

// verifyChain checks the chain over entries ordered by ascending seq.
func verifyChain(key []byte, events []Event) Result {
	prev := ""
	for i, e := range events {
		if e.Seq != int64(i)+1 {
			return Result{OK: false, BrokenAt: e.Seq, Reason: "seq order is not contiguous (an entry may have been deleted)"}
		}
		if e.PrevHash != prev {
			return Result{OK: false, BrokenAt: e.Seq, Reason: "prev_hash link is broken"}
		}
		if e.Hash != mac(key, prev, e) {
			return Result{OK: false, BrokenAt: e.Seq, Reason: "hash mismatch (the entry was changed)"}
		}
		prev = e.Hash
	}
	return Result{OK: true, Count: int64(len(events))}
}

func reversed(in []Event) []Event {
	out := make([]Event, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}

func applyFilter(events []Event, f Filter) []Event {
	var out []Event
	for _, e := range events {
		if f.Program != "" && e.Program != f.Program {
			continue
		}
		if f.RunID != "" && e.RunID != f.RunID {
			continue
		}
		if f.Kind != "" && e.Kind != f.Kind {
			continue
		}
		out = append(out, e)
	}
	out = reversed(out) // newest first
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}
