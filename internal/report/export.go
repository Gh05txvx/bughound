package report

import (
	"fmt"
	"strings"

	"bughound/internal/finding"
)

// Platform adalah platform bounty tujuan export (bentuk template submission).
type Platform string

const (
	PlatformHackerOne Platform = "hackerone"
	PlatformBugcrowd  Platform = "bugcrowd"
)

// Valid melaporkan apakah p didukung.
func (p Platform) Valid() bool { return p == PlatformHackerOne || p == PlatformBugcrowd }

// Label mengembalikan nama tampil platform.
func (p Platform) Label() string {
	switch p {
	case PlatformHackerOne:
		return "HackerOne"
	case PlatformBugcrowd:
		return "Bugcrowd"
	}
	return string(p)
}

// draftNote ditanam di tiap export agar sifat draft & "tanpa auto-submit" jelas.
const draftNote = "Draft BugHound — verifikasi & lengkapi, lalu submit MANUAL. Tanpa auto-submit."

// ExportFinding memformat SATU temuan ke template submission platform (Markdown).
// Hanya menghasilkan teks; pengiriman tetap manual (prinsip tanpa auto-submit).
// Evidence yang dipakai sudah tersensor di hulu (skema tak menyimpan secret mentah).
func ExportFinding(f *finding.Finding, p Platform) string {
	if p == PlatformBugcrowd {
		return exportBugcrowd(f)
	}
	return exportHackerOne(f)
}

// ExportReport memformat SEMUA temuan terkonfirmasi di report ke template
// platform, satu bagian per temuan (hunter men-submit tiap temuan terpisah).
func ExportReport(r Report, p Platform) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Export %s — %s\n\n", p.Label(), r.Program)
	fmt.Fprintf(&b, "_%d temuan terkonfirmasi · %s_\n\n", len(r.Items), draftNote)
	if len(r.Items) == 0 {
		b.WriteString("_Belum ada temuan terkonfirmasi untuk diekspor._\n")
		return b.String()
	}
	for i, f := range r.Items {
		fmt.Fprintf(&b, "<!-- Temuan %d/%d -->\n\n", i+1, len(r.Items))
		b.WriteString(ExportFinding(f, p))
		b.WriteString("\n---\n\n")
	}
	return b.String()
}

func assetOf(f *finding.Finding) string {
	if f.Location.URL != "" {
		return f.Location.URL
	}
	return f.Target
}

// h1Rating memetakan severity internal ke rating kualitatif HackerOne.
func h1Rating(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "Critical (9.0–10.0)"
	case finding.SeverityHigh:
		return "High (7.0–8.9)"
	case finding.SeverityMedium:
		return "Medium (4.0–6.9)"
	case finding.SeverityLow:
		return "Low (0.1–3.9)"
	default:
		return "None / Informational"
	}
}

// bugcrowdPriority memetakan severity internal ke prioritas P1–P5 Bugcrowd.
func bugcrowdPriority(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "P1 (Critical)"
	case finding.SeverityHigh:
		return "P2 (High)"
	case finding.SeverityMedium:
		return "P3 (Medium)"
	case finding.SeverityLow:
		return "P4 (Low)"
	default:
		return "P5 (Informational)"
	}
}

func writeSteps(b *strings.Builder, f *finding.Finding) {
	if len(f.Reproduction) > 0 {
		for i, s := range f.Reproduction {
			fmt.Fprintf(b, "%d. %s\n", i+1, s)
		}
		return
	}
	// Tanpa langkah eksplisit — beri kerangka dari lokasi + payload.
	if f.Location.Method != "" {
		fmt.Fprintf(b, "1. Kirim permintaan `%s` ke `%s`", f.Location.Method, assetOf(f))
	} else {
		fmt.Fprintf(b, "1. Akses `%s`", assetOf(f))
	}
	if f.Location.Parameter != "" {
		fmt.Fprintf(b, " melalui parameter `%s`", f.Location.Parameter)
	}
	b.WriteString(".\n")
	if f.Evidence != nil && f.Evidence.Payload != "" {
		fmt.Fprintf(b, "2. Gunakan payload: `%s`\n", f.Evidence.Payload)
	}
	b.WriteString("_(lengkapi langkah reproduksi sebelum submit)_\n")
}

func writeEvidence(b *strings.Builder, f *finding.Finding) {
	if f.Evidence == nil {
		return
	}
	e := f.Evidence
	if e.Request != "" {
		fmt.Fprintf(b, "Request:\n\n```\n%s\n```\n\n", e.Request)
	}
	if e.ResponseExcerpt != "" {
		fmt.Fprintf(b, "Response:\n\n```\n%s\n```\n\n", e.ResponseExcerpt)
	}
	if e.Payload != "" {
		fmt.Fprintf(b, "Payload: `%s`\n\n", e.Payload)
	}
	if e.Matched != "" {
		fmt.Fprintf(b, "Matched: `%s`\n\n", e.Matched)
	}
}

func exportHackerOne(f *finding.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", f.Title)
	fmt.Fprintf(&b, "<!-- %s -->\n\n", draftNote)

	b.WriteString("**Metadata (isi ke form HackerOne):**\n\n")
	fmt.Fprintf(&b, "- **Asset / URL:** %s\n", assetOf(f))
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "- **Weakness (CWE):** %s\n", strings.Join(f.CWE, ", "))
	}
	if f.OWASP != "" {
		fmt.Fprintf(&b, "- **OWASP (2021):** %s\n", f.OWASP.Label())
	}
	fmt.Fprintf(&b, "- **Severity:** %s\n", h1Rating(f.Severity))
	if f.CVSS != nil && f.CVSS.Vector != "" {
		fmt.Fprintf(&b, "- **CVSS:** %.1f `%s`\n", f.CVSS.Score, f.CVSS.Vector)
	}
	b.WriteString("\n")

	b.WriteString("## Summary\n\n")
	if f.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", f.Description)
	} else {
		fmt.Fprintf(&b, "%s pada `%s`.\n\n", f.Type, assetOf(f))
	}

	b.WriteString("## Steps To Reproduce\n\n")
	writeSteps(&b, f)
	b.WriteString("\n")

	if f.Evidence != nil {
		b.WriteString("## Proof of Concept\n\n")
		writeEvidence(&b, f)
	}

	b.WriteString("## Impact\n\n")
	if strings.TrimSpace(f.Impact) != "" {
		fmt.Fprintf(&b, "%s\n\n", f.Impact)
	} else {
		b.WriteString("_Jelaskan dampak konkret (data terekspos, aksi yang bisa dilakukan penyerang) sebelum submit._\n\n")
	}

	if len(f.References) > 0 {
		b.WriteString("## Supporting Material / References\n\n")
		for _, ref := range f.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportBugcrowd(f *finding.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", f.Title)
	fmt.Fprintf(&b, "<!-- %s -->\n\n", draftNote)

	b.WriteString("**Metadata (isi ke form Bugcrowd):**\n\n")
	fmt.Fprintf(&b, "- **Target:** %s\n", assetOf(f))
	fmt.Fprintf(&b, "- **Priority:** %s\n", bugcrowdPriority(f.Severity))
	fmt.Fprintf(&b, "- **Bug type (petakan ke VRT):** %s\n", f.Type)
	if f.OWASP != "" {
		fmt.Fprintf(&b, "- **OWASP (2021):** %s\n", f.OWASP.Label())
	}
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
	}
	if f.CVSS != nil && f.CVSS.Vector != "" {
		fmt.Fprintf(&b, "- **CVSS:** %.1f `%s`\n", f.CVSS.Score, f.CVSS.Vector)
	}
	b.WriteString("\n")

	b.WriteString("**Vulnerability Details**\n\n")
	if f.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", f.Description)
	} else {
		fmt.Fprintf(&b, "%s pada `%s`.\n\n", f.Type, assetOf(f))
	}

	b.WriteString("**Steps to Reproduce**\n\n")
	writeSteps(&b, f)
	b.WriteString("\n")

	if f.Evidence != nil {
		b.WriteString("**Proof of Concept**\n\n")
		writeEvidence(&b, f)
	}

	b.WriteString("**Impact**\n\n")
	if strings.TrimSpace(f.Impact) != "" {
		fmt.Fprintf(&b, "%s\n\n", f.Impact)
	} else {
		b.WriteString("_Jelaskan dampak konkret sebelum submit._\n\n")
	}

	b.WriteString("**Remediation**\n\n")
	if len(f.References) > 0 {
		for _, ref := range f.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
	} else {
		b.WriteString("_Tambahkan rekomendasi perbaikan._\n")
	}
	b.WriteString("\n")
	return b.String()
}
