package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Anchor is a checkpoint of the audit chain head: the chain height (Seq) and
// the head Hash at that moment. It is stored SEPARATELY from the audit store as
// an external attestation. The HMAC chain detects changed or deleted entries,
// but deleting or truncating the WHOLE store (outside the application) leaves a
// short or empty chain that is still internally valid. Anchors close that gap
// (BH-F06): as long as the anchor file survives, Verify detects truncation,
// rollback or total deletion of the store. The Tag binds an anchor to the key,
// so it cannot be forged without the key.
//
// Limit: if the store AND the anchor file are both lost on the same host, that
// goes undetected. Catching it needs replication off the host (WORM/SIEM),
// which is out of scope here.
type Anchor struct {
	Seq  int64     `json:"seq"`
	Hash string    `json:"hash"`
	At   time.Time `json:"at"`
	Tag  string    `json:"tag"`
}

func anchorTag(key []byte, seq int64, hash string, at time.Time) string {
	h := hmac.New(sha256.New, key)
	fmt.Fprintf(h, "%d\n%s\n%d", seq, hash, at.UTC().UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

// Anchorer stores anchors append-only and reads them back.
type Anchorer interface {
	WriteAnchor(a Anchor) error
	Anchors() ([]Anchor, error)
}

// FileAnchorer writes anchors as append-only JSON Lines to a file. Ideally the
// file lives on separate or WORM storage, so deleting the audit store does not
// delete its attestation too.
type FileAnchorer struct {
	path string
	key  []byte
	mu   sync.Mutex
}

// NewFileAnchorer creates a file-backed anchorer at path with key.
func NewFileAnchorer(path string, key []byte) *FileAnchorer {
	return &FileAnchorer{path: path, key: key}
}

// WriteAnchor appends one anchor (with its tag) to the end of the file, then fsyncs.
func (f *FileAnchorer) WriteAnchor(a Anchor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a.Tag = anchorTag(f.key, a.Seq, a.Hash, a.At)
	line, err := json.Marshal(a)
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := fh.Write(append(line, '\n')); err != nil {
		return err
	}
	return fh.Sync()
}

// Anchors reads all anchors in write order. Empty or incomplete lines (e.g.
// from a crash mid-write) are skipped; tag validity is checked at verify time.
func (f *FileAnchorer) Anchors() ([]Anchor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fh, err := os.Open(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer fh.Close()

	var out []Anchor
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var a Anchor
		if err := json.Unmarshal(line, &a); err != nil {
			continue // incomplete line, skip it
		}
		out = append(out, a)
	}
	return out, sc.Err()
}

// verifyAnchors checks that the chain (events, ordered by ascending seq) is
// consistent with the anchors: each anchor must be authentic (its tag matches)
// and its (Seq,Hash) must match an entry in events. events may be LONGER than
// the last anchor (a tail that is not anchored yet), but it must not be shorter
// (truncation) or have a different hash (rewritten / rolled back).
func verifyAnchors(key []byte, events []Event, anchors []Anchor) Result {
	for _, a := range anchors {
		if a.Tag != anchorTag(key, a.Seq, a.Hash, a.At) {
			return Result{OK: false, BrokenAt: a.Seq, Reason: "anchor is not authentic (the anchor file was tampered with)"}
		}
		if a.Seq < 1 {
			continue
		}
		if a.Seq > int64(len(events)) {
			return Result{OK: false, BrokenAt: a.Seq,
				Reason: fmt.Sprintf("log is shorter than the anchor (seq %d is missing; probably deleted or truncated)", a.Seq)}
		}
		if events[a.Seq-1].Hash != a.Hash {
			return Result{OK: false, BrokenAt: a.Seq,
				Reason: fmt.Sprintf("head at seq %d does not match the anchor (the log was rewritten or rolled back)", a.Seq)}
		}
	}
	return Result{OK: true, Count: int64(len(events)), Anchors: int64(len(anchors))}
}
