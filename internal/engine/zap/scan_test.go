package zap

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestMain: dengan BH_FAKE_ZAP=1 binary tes ini menyamar sebagai zap.sh (fakeZAP),
// agar Scan teruji end-to-end tanpa ZAP/JVM.
func TestMain(m *testing.M) {
	if os.Getenv("BH_FAKE_ZAP") == "1" {
		fakeZAP()
		return
	}
	os.Exit(m.Run())
}

// fakeZAP meniru `zap.sh -cmd -autorun plan`: bila BH_FAKE_ZAP_HOLD=1 menduduki
// port proxy lokal (-port; default 8080 seperti ZAP) selama "scan"; menulis
// laporan traditional-json ke dir plan (kecuali BH_FAKE_ZAP_NOREPORT); keluar
// dengan BH_FAKE_ZAP_EXIT (Automation Framework: 0 ok, 1 galat, 2 peringatan).
func fakeZAP() {
	port, plan := "8080", ""
	for i := 0; i+1 < len(os.Args); i++ {
		switch os.Args[i] {
		case "-port":
			port = os.Args[i+1]
		case "-autorun":
			plan = os.Args[i+1]
		}
	}
	if os.Getenv("BH_FAKE_ZAP_HOLD") == "1" {
		l, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "java.net.BindException: Address already in use")
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
		l.Close()
	}
	if os.Getenv("BH_FAKE_ZAP_NOREPORT") == "" {
		_ = os.WriteFile(filepath.Join(filepath.Dir(plan), "report.json"), sampleJSON, 0o600)
	}
	code, _ := strconv.Atoi(os.Getenv("BH_FAKE_ZAP_EXIT"))
	os.Exit(code)
}

func fakeZAPRunner(t *testing.T) *Runner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BH_FAKE_ZAP", "1")
	return &Runner{Binary: exe}
}

// Dua scan ZAP bersamaan dalam satu kontainer dulu SELALU menggagalkan salah
// satunya (BindException port proxy lokal, live 2026-11-16) → port per run.
func TestScanConcurrentZAPRuns(t *testing.T) {
	r := fakeZAPRunner(t)
	t.Setenv("BH_FAKE_ZAP_HOLD", "1")
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = (&Runner{Binary: r.Binary}).Scan(context.Background(), "http://t.test", "p", fmt.Sprint("r", i))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("scan ZAP bersamaan #%d gagal: %v", i, err)
		}
	}
}

// Exit 2 Automation Framework = plan selesai DENGAN peringatan (mis. target
// membalas 401 di semua halaman); laporannya tetap dipakai. Exit 1, atau exit 2
// tanpa laporan, tetap galat.
func TestScanZAPExitCodes(t *testing.T) {
	r := fakeZAPRunner(t)
	for _, tc := range []struct {
		exit, noReport string
		wantErr        bool
	}{
		{"0", "", false},
		{"2", "", false},
		{"1", "", true},
		{"2", "1", true},
	} {
		t.Setenv("BH_FAKE_ZAP_EXIT", tc.exit)
		t.Setenv("BH_FAKE_ZAP_NOREPORT", tc.noReport)
		fs, err := r.Scan(context.Background(), "http://t.test", "p", "r")
		if (err != nil) != tc.wantErr {
			t.Errorf("exit %s (tanpa laporan=%q): galat=%v, mau galat=%v", tc.exit, tc.noReport, err, tc.wantErr)
		}
		if !tc.wantErr && len(fs) != 2 {
			t.Errorf("exit %s: mau 2 temuan dari laporan, dapat %d", tc.exit, len(fs))
		}
	}
}
