package nuclei

import (
	"strings"
	"testing"
)

// Non-destruktif wajib ada di nucleiArgs apa pun profilnya: -no-interactsh dan
// -exclude-tags dos. Ini struktural, bukan opsi.
func TestSafetyNonDestructiveAlwaysOn(t *testing.T) {
	for _, st := range []bool{false, true} {
		r := &DASTRunner{RateLimit: 25, proxyAddr: "x:1", Safety: Safety{Stealth: st}}
		a := strings.Join(r.nucleiArgs("l"), " ")
		if !strings.Contains(a, "-no-interactsh") {
			t.Errorf("stealth=%v: -no-interactsh wajib ada; got: %s", st, a)
		}
		if !strings.Contains(a, "-exclude-tags dos") {
			t.Errorf("stealth=%v: -exclude-tags dos wajib ada; got: %s", st, a)
		}
	}
}

// Stealth menambah low-and-slow: -c 1, UA browser, laju dijepit ≤ stealthRateLimit,
// walau RateLimit yang diminta jauh lebih tinggi.
func TestSafetyStealthLowAndSlow(t *testing.T) {
	r := &DASTRunner{RateLimit: 50, proxyAddr: "x:1", Safety: Safety{Stealth: true}}
	a := strings.Join(r.nucleiArgs("l"), " ")
	for _, want := range []string{"-c 1", "-timeout 20", "User-Agent: Mozilla", "-rate-limit 3"} {
		if !strings.Contains(a, want) {
			t.Errorf("stealth nucleiArgs tak memuat %q; got: %s", want, a)
		}
	}
	// Laju 50 harus terjepit ke 3, BUKAN diteruskan apa adanya.
	if strings.Contains(a, "-rate-limit 50") {
		t.Errorf("stealth tak boleh memakai laju 50; got: %s", a)
	}
	// Katana juga low-and-slow.
	k := strings.Join(r.katanaArgs("http://t/"), " ")
	for _, want := range []string{"-c 1", "User-Agent: Mozilla", "-rate-limit 3"} {
		if !strings.Contains(k, want) {
			t.Errorf("stealth katanaArgs tak memuat %q; got: %s", want, k)
		}
	}
}

// Tanpa stealth, laju yang diminta dihormati dan tak ada knob stealth.
func TestSafetyStandardRespectsRate(t *testing.T) {
	r := &DASTRunner{RateLimit: 25, proxyAddr: "x:1"} // Safety zero value = standar
	a := strings.Join(r.nucleiArgs("l"), " ")
	if !strings.Contains(a, "-rate-limit 25") {
		t.Errorf("mode standar harus memakai -rate-limit 25; got: %s", a)
	}
	if strings.Contains(a, "-c 1") || strings.Contains(a, "User-Agent") {
		t.Errorf("mode standar tak boleh menyuntik knob stealth; got: %s", a)
	}
}

// Template unsafe destruktif ditolak: tag smuggling (desync) + 2 ID yang menulis
// ke target (webshell/F5). Wajib ada apa pun profilnya.
func TestSafetyExcludesDestructiveUnsafe(t *testing.T) {
	for _, st := range []bool{false, true} {
		r := &DASTRunner{RateLimit: 25, proxyAddr: "x:1", Safety: Safety{Stealth: st}}
		a := strings.Join(r.nucleiArgs("l"), " ")
		for _, want := range []string{"-exclude-tags dos,smuggling", "-exclude-id CVE-2021-30118,CVE-2023-46747"} {
			if !strings.Contains(a, want) {
				t.Errorf("stealth=%v: nucleiArgs tak memuat %q; got: %s", st, want, a)
			}
		}
	}
}

// maxURLs lebih kecil saat stealth (cakupan dipersempit).
func TestSafetyMaxURLs(t *testing.T) {
	if (Safety{Stealth: true}).maxURLs() >= (Safety{}).maxURLs() {
		t.Error("stealth harus mempersempit cap URL")
	}
	if (Safety{}).maxURLs() != maxDASTURLs {
		t.Errorf("mode standar maxURLs = %d, mau %d", (Safety{}).maxURLs(), maxDASTURLs)
	}
}
