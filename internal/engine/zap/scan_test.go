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

// TestMain: with BH_FAKE_ZAP=1 this test binary masquerades as zap.sh (fakeZAP),
// so Scan is tested end-to-end without ZAP/JVM.
func TestMain(m *testing.M) {
	if os.Getenv("BH_FAKE_ZAP") == "1" {
		fakeZAP()
		return
	}
	os.Exit(m.Run())
}

// fakeZAP mimics `zap.sh -cmd -autorun plan`: with BH_FAKE_ZAP_HOLD=1 it occupies
// the local proxy port (-port; default 8080 like ZAP) during the "scan"; it writes
// the traditional-json report to the plan dir (unless BH_FAKE_ZAP_NOREPORT); it exits
// with BH_FAKE_ZAP_EXIT (Automation Framework: 0 ok, 1 error, 2 warning).
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

// Two concurrent ZAP scans in one container used to ALWAYS fail one
// of them (local proxy port BindException, live 2026-11-16) → port per run.
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
			t.Errorf("concurrent ZAP scan #%d failed: %v", i, err)
		}
	}
}

// Automation Framework exit 2 = the plan finished WITH warnings (e.g. the target
// replies 401 on every page); its report is still used. Exit 1, or exit 2
// without a report, is still an error.
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
			t.Errorf("exit %s (no report=%q): err=%v, want err=%v", tc.exit, tc.noReport, err, tc.wantErr)
		}
		if !tc.wantErr && len(fs) != 2 {
			t.Errorf("exit %s: want 2 findings from the report, got %d", tc.exit, len(fs))
		}
	}
}
