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

// Anchor adalah checkpoint head rantai audit: tinggi rantai (Seq) + Hash head
// pada saat itu. Disimpan TERPISAH dari store audit sebagai attestation
// eksternal. Rantai HMAC mendeteksi perubahan/penghapusan entri, tetapi
// penghapusan/trunkasi SELURUH store (di luar aplikasi) menghasilkan rantai
// pendek/kosong yang tetap valid secara internal. Anchor menutup celah itu
// (BH-F06): selama berkas anchor bertahan, trunkasi/rollback/penghapusan total
// store terdeteksi oleh Verify. Tag mengikat anchor ke kunci sehingga tak bisa
// dipalsukan tanpa kunci.
//
// Batas: bila store DAN berkas anchor sama-sama hilang di host yang sama, ini
// tak terdeteksi — itu butuh replikasi ke luar host (WORM/SIEM), di luar lingkup.
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

// Anchorer menyimpan anchor secara append-only dan membacanya kembali.
type Anchorer interface {
	WriteAnchor(a Anchor) error
	Anchors() ([]Anchor, error)
}

// FileAnchorer menulis anchor sebagai JSON Lines append-only ke sebuah berkas.
// Idealnya berkas ini berada di penyimpanan terpisah/WORM agar penghapusan
// store audit tak ikut menghapus attestation-nya.
type FileAnchorer struct {
	path string
	key  []byte
	mu   sync.Mutex
}

// NewFileAnchorer membuat anchorer berbasis berkas pada path dengan kunci key.
func NewFileAnchorer(path string, key []byte) *FileAnchorer {
	return &FileAnchorer{path: path, key: key}
}

// WriteAnchor menambahkan satu anchor (dengan tag) ke akhir berkas, lalu fsync.
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

// Anchors membaca semua anchor terurut tulis. Baris kosong/tak lengkap (mis.
// crash saat menulis) dilewati; keabsahan tag diperiksa saat verify.
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
			continue // baris tak lengkap — lewati
		}
		out = append(out, a)
	}
	return out, sc.Err()
}

// verifyAnchors memeriksa rantai (events, terurut seq menaik) konsisten dengan
// anchor: tiap anchor harus otentik (tag cocok) dan (Seq,Hash)-nya cocok entri
// di events. events boleh LEBIH panjang dari anchor terakhir (tail belum
// ter-anchor), tetapi tak boleh lebih pendek (trunkasi) atau beda hash (ditulis
// ulang / rollback).
func verifyAnchors(key []byte, events []Event, anchors []Anchor) Result {
	for _, a := range anchors {
		if a.Tag != anchorTag(key, a.Seq, a.Hash, a.At) {
			return Result{OK: false, BrokenAt: a.Seq, Reason: "anchor tidak otentik (berkas anchor diutak-atik)"}
		}
		if a.Seq < 1 {
			continue
		}
		if a.Seq > int64(len(events)) {
			return Result{OK: false, BrokenAt: a.Seq,
				Reason: fmt.Sprintf("log lebih pendek dari anchor (seq %d hilang — kemungkinan dihapus/trunkasi)", a.Seq)}
		}
		if events[a.Seq-1].Hash != a.Hash {
			return Result{OK: false, BrokenAt: a.Seq,
				Reason: fmt.Sprintf("head pada seq %d tak cocok anchor (log ditulis ulang/rollback)", a.Seq)}
		}
	}
	return Result{OK: true, Count: int64(len(events)), Anchors: int64(len(anchors))}
}
