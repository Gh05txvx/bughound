package sast

import (
	"context"

	"bughound/internal/finding"
)

// Mock is a fake SAST adapter: it returns deterministic sample findings without
// reading files or touching the network (for demos and E2E, where a real
// analysis must be impossible to trigger). The file:line locations are
// illustrative.
type Mock struct{}

// Name implements Engine.
func (Mock) Name() string { return "semgrep (mock)" }

// Analyze returns sample findings; dir/ctx are ignored (no real I/O).
func (Mock) Analyze(_ context.Context, _, _, _ string) ([]*finding.Finding, error) {
	return []*finding.Finding{
		{
			Type:           "hardcoded-credentials",
			Title:          "Hardcoded credential in source",
			Description:    "A secret is written directly in the code; move it to a secret store / environment variable.",
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
			Title:          "Non-cryptographic PRNG for a sensitive value",
			Description:    "math/rand is not safe for tokens/secrets; use crypto/rand.",
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
