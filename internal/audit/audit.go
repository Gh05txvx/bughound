// Package audit menyimpan audit trail yang utuh dan tak bisa dihapus diam-diam
// (prinsip mengikat bughound #6). Setiap entri mengikat hash entri sebelumnya
// dalam rantai HMAC-SHA256 ber-kunci; menghapus atau mengubah entri memutus
// rantai dan terdeteksi oleh Verify. API hanya Append + List + Verify — tidak
// ada Delete/Update, sehingga append-only secara kontrak.
//
// Kunci HMAC diturunkan dari master key (secret.Keyring.Subkey), jadi rantai
// tak bisa dihitung ulang tanpa kunci. Penghapusan/trunkasi SELURUH log (di
// luar aplikasi) menghasilkan rantai pendek yang masih valid internal; itu
// ditutup oleh anchoring eksternal opsional (lihat anchor.go, BH-F06).
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Event adalah satu entri audit. Hash & PrevHash diisi oleh Append.
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

// content mengembalikan byte kanonik entri (TANPA Hash/PrevHash) untuk di-MAC.
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

// Filter membatasi List.
type Filter struct {
	Program string
	RunID   string
	Kind    string
	Limit   int
}

// Result adalah hasil Verify.
type Result struct {
	OK       bool
	Count    int64
	BrokenAt int64  // seq entri pertama yang rusak (0 bila OK)
	Reason   string // alasan kerusakan (kosong bila OK)
	Anchors  int64  // jumlah anchor eksternal yang dicek (0 bila tak ada anchorer)
}

// Log adalah audit trail append-only.
type Log interface {
	Append(ctx context.Context, e Event) (Event, error)
	List(ctx context.Context, f Filter) ([]Event, error) // terbaru dulu
	Verify(ctx context.Context) (Result, error)
	Close() error
}

// verifyChain memeriksa rantai pada entri terurut seq menaik.
func verifyChain(key []byte, events []Event) Result {
	prev := ""
	for i, e := range events {
		if e.Seq != int64(i)+1 {
			return Result{OK: false, BrokenAt: e.Seq, Reason: "urutan seq tidak kontigu (entri mungkin dihapus)"}
		}
		if e.PrevHash != prev {
			return Result{OK: false, BrokenAt: e.Seq, Reason: "mata rantai prev_hash putus"}
		}
		if e.Hash != mac(key, prev, e) {
			return Result{OK: false, BrokenAt: e.Seq, Reason: "hash tidak cocok (entri diubah)"}
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
	out = reversed(out) // terbaru dulu
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}
