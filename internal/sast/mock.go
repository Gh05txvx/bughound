package sast

import (
	"context"

	"bughound/internal/finding"
)

// Mock adalah adapter SAST palsu: mengembalikan temuan sampel deterministik
// tanpa membaca berkas atau menyentuh jaringan (untuk demo & E2E — mustahil
// memicu analisis nyata). Lokasi file:line bersifat ilustratif.
type Mock struct{}

// Name memenuhi Engine.
func (Mock) Name() string { return "semgrep (mock)" }

// Analyze mengembalikan temuan sampel; dir/ctx diabaikan (tanpa I/O nyata).
func (Mock) Analyze(_ context.Context, _, _, _ string) ([]*finding.Finding, error) {
	return []*finding.Finding{
		{
			Type:           "hardcoded-credentials",
			Title:          "Kredensial ter-hardcode di sumber",
			Description:    "Rahasia tertulis langsung di kode; pindahkan ke secret store / variabel lingkungan.",
			Severity:       finding.SeverityHigh,
			Confidence:     finding.ConfidenceHigh,
			Status:         finding.StatusNew,
			SourceEngine:   "semgrep (mock)",
			SourceTemplate: "generic.secrets.hardcoded",
			CWE:            []string{"CWE-798"},
			Location:       finding.Location{URL: "internal/config/db.go:14"},
			Evidence:       &finding.Evidence{Matched: `dbPassword := "s3cr3t-do-not-commit"`},
			Tags:           []string{"secrets", "sast"},
		},
		{
			Type:           "insecure-randomness",
			Title:          "PRNG non-kriptografis untuk nilai sensitif",
			Description:    "math/rand tidak aman untuk token/secret; gunakan crypto/rand.",
			Severity:       finding.SeverityMedium,
			Confidence:     finding.ConfidenceMedium,
			Status:         finding.StatusNew,
			SourceEngine:   "semgrep (mock)",
			SourceTemplate: "go.lang.security.audit.crypto.insecure-random",
			CWE:            []string{"CWE-338"},
			Location:       finding.Location{URL: "internal/token/token.go:8"},
			Evidence:       &finding.Evidence{Matched: "token := rand.Intn(1000000)"},
			Tags:           []string{"crypto", "sast"},
		},
	}, nil
}

func init() { Register("mock", func() Engine { return Mock{} }) }
