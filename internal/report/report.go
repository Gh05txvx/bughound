// Package report menyusun draft report dari temuan TERKONFIRMASI.
//
// Prinsip bughound: report selalu berakhir sebagai draft — tidak ada auto-submit.
// Paket ini hanya menghasilkan teks/struktur; pengiriman ke platform dilakukan
// manual oleh pengguna setelah verifikasi.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"bughound/internal/finding"
)

// SevCount adalah jumlah temuan per severity (untuk ringkasan).
type SevCount struct {
	Severity finding.Severity
	Count    int
}

// Report adalah draft report satu program.
type Report struct {
	Program     string
	Title       string
	GeneratedAt time.Time
	Items       []*finding.Finding // temuan terkonfirmasi, terurut severity
	BySeverity  []SevCount
	Markdown    string
}

// Build menyusun draft dari temuan yang statusnya confirmed. Input boleh berisi
// status lain; non-confirmed diabaikan. now dipakai sebagai waktu pembuatan.
func Build(program string, findings []*finding.Finding, now time.Time) Report {
	var items []*finding.Finding
	for _, f := range findings {
		if f.Status == finding.StatusConfirmed {
			items = append(items, f)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := rank(items[i].Severity), rank(items[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return items[i].CreatedAt.Time.After(items[j].CreatedAt.Time)
	})

	r := Report{
		Program:     program,
		Title:       "Laporan — " + program,
		GeneratedAt: now.UTC(),
		Items:       items,
		BySeverity:  breakdown(items),
	}
	r.Markdown = renderMarkdown(r)
	return r
}

func breakdown(items []*finding.Finding) []SevCount {
	order := []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeverityInfo,
	}
	counts := map[finding.Severity]int{}
	for _, f := range items {
		counts[f.Severity]++
	}
	var out []SevCount
	for _, s := range order {
		if counts[s] > 0 {
			out = append(out, SevCount{Severity: s, Count: counts[s]})
		}
	}
	return out
}

func rank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 5
	case finding.SeverityHigh:
		return 4
	case finding.SeverityMedium:
		return 3
	case finding.SeverityLow:
		return 2
	case finding.SeverityInfo:
		return 1
	}
	return 0
}

func renderMarkdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", r.Title)
	fmt.Fprintf(&b, "_Dihasilkan %s · %d temuan terkonfirmasi · **DRAFT** (verifikasi manual sebelum submit; tanpa auto-submit)_\n\n",
		r.GeneratedAt.Format("2006-01-02 15:04 MST"), len(r.Items))

	b.WriteString("## Ringkasan\n\n")
	if len(r.Items) == 0 {
		b.WriteString("_Belum ada temuan terkonfirmasi._\n")
		return b.String()
	}
	for _, sc := range r.BySeverity {
		fmt.Fprintf(&b, "- %s: %d\n", strings.ToUpper(string(sc.Severity)), sc.Count)
	}

	b.WriteString("\n## Temuan\n\n")
	for i, f := range r.Items {
		fmt.Fprintf(&b, "### %d. %s `%s`\n\n", i+1, f.Title, f.Severity)
		fmt.Fprintf(&b, "- **Type:** %s\n", f.Type)
		fmt.Fprintf(&b, "- **Target:** %s\n", f.Target)
		loc := f.Location.URL
		if f.Location.Parameter != "" {
			loc += " (param: " + f.Location.Parameter + ")"
		}
		fmt.Fprintf(&b, "- **Lokasi:** %s\n", loc)
		if f.CVSS != nil {
			fmt.Fprintf(&b, "- **CVSS:** %.1f `%s`\n", f.CVSS.Score, f.CVSS.Vector)
		}
		if len(f.CWE) > 0 {
			fmt.Fprintf(&b, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
		}
		if f.VerifiedBy != "" {
			fmt.Fprintf(&b, "- **Diverifikasi oleh:** %s\n", f.VerifiedBy)
		}
		b.WriteString("\n")

		if f.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Description)
		}
		if len(f.Reproduction) > 0 {
			b.WriteString("**Langkah reproduksi:**\n\n")
			for j, step := range f.Reproduction {
				fmt.Fprintf(&b, "%d. %s\n", j+1, step)
			}
			b.WriteString("\n")
		}
		if f.Evidence != nil {
			b.WriteString("**Bukti:**\n\n")
			if f.Evidence.Request != "" {
				fmt.Fprintf(&b, "Request:\n\n```\n%s\n```\n\n", f.Evidence.Request)
			}
			if f.Evidence.ResponseExcerpt != "" {
				fmt.Fprintf(&b, "Response:\n\n```\n%s\n```\n\n", f.Evidence.ResponseExcerpt)
			}
			if f.Evidence.Payload != "" {
				fmt.Fprintf(&b, "Payload: `%s`\n\n", f.Evidence.Payload)
			}
		}
		if len(f.References) > 0 {
			b.WriteString("**Referensi:**\n\n")
			for _, ref := range f.References {
				fmt.Fprintf(&b, "- %s\n", ref)
			}
			b.WriteString("\n")
		}
		b.WriteString("---\n\n")
	}
	return b.String()
}
