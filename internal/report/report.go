// Package report builds a draft report from CONFIRMED findings.
//
// bughound principle: a report always ends as a draft, with no auto-submit.
// This package only produces text/structure; the user sends it to the platform
// manually after verification.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"bughound/internal/finding"
)

// SevCount is the number of findings per severity (for the summary).
type SevCount struct {
	Severity finding.Severity
	Count    int
}

// Report is the draft report for one program.
type Report struct {
	Program     string
	Title       string
	GeneratedAt time.Time
	Items       []*finding.Finding // confirmed findings, sorted by severity
	BySeverity  []SevCount
	Caveats     []Caveat // local triage hints (likely FPs, coverage gaps)
	Markdown    string
}

// Build puts the draft together from findings whose status is confirmed. The
// input may contain other statuses; non-confirmed findings are ignored. now is
// used as the creation time.
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
		Title:       "Report: " + program,
		GeneratedAt: now.UTC(),
		Items:       items,
		BySeverity:  breakdown(items),
		Caveats:     Caveats(items),
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
	fmt.Fprintf(&b, "_Generated %s · %d confirmed finding(s) · **DRAFT** (verify manually before submitting; no auto-submit)_\n\n",
		r.GeneratedAt.Format("2006-01-02 15:04 MST"), len(r.Items))

	b.WriteString("## Summary\n\n")
	if len(r.Items) == 0 {
		b.WriteString("_No confirmed findings yet._\n")
		return b.String()
	}
	for _, sc := range r.BySeverity {
		fmt.Fprintf(&b, "- %s: %d\n", strings.ToUpper(string(sc.Severity)), sc.Count)
	}

	if len(r.Caveats) > 0 {
		b.WriteString("\n## Caveats & coverage\n\n")
		b.WriteString("_Heuristic triage hints (verify manually). Computed locally; nothing is sent anywhere._\n\n")
		for _, c := range r.Caveats {
			tag := "FP?"
			if c.Kind == "coverage" {
				tag = "COVERAGE"
			}
			fmt.Fprintf(&b, "- **[%s]** %s\n  %s\n", tag, c.Title, c.Detail)
		}
	}

	b.WriteString("\n## Findings\n\n")
	for i, f := range r.Items {
		fmt.Fprintf(&b, "### %d. %s `%s`\n\n", i+1, f.Title, f.Severity)
		fmt.Fprintf(&b, "- **Type:** %s\n", f.Type)
		if f.OWASP != "" {
			fmt.Fprintf(&b, "- **OWASP:** %s\n", f.OWASP.Label())
		}
		fmt.Fprintf(&b, "- **Target:** %s\n", f.Target)
		loc := f.Location.URL
		if f.Location.Parameter != "" {
			loc += " (param: " + f.Location.Parameter + ")"
		}
		fmt.Fprintf(&b, "- **Location:** %s\n", loc)
		if f.CVSS != nil {
			fmt.Fprintf(&b, "- **CVSS:** %.1f `%s`\n", f.CVSS.Score, f.CVSS.Vector)
		}
		if len(f.CWE) > 0 {
			fmt.Fprintf(&b, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
		}
		if f.VerifiedBy != "" {
			fmt.Fprintf(&b, "- **Verified by:** %s\n", f.VerifiedBy)
		}
		b.WriteString("\n")

		if f.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Description)
		}
		if len(f.Reproduction) > 0 {
			b.WriteString("**Reproduction steps:**\n\n")
			for j, step := range f.Reproduction {
				fmt.Fprintf(&b, "%d. %s\n", j+1, step)
			}
			b.WriteString("\n")
		}
		if f.Evidence != nil {
			b.WriteString("**Evidence:**\n\n")
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
		if strings.TrimSpace(f.Impact) != "" {
			fmt.Fprintf(&b, "**Impact:**\n\n%s\n\n", f.Impact)
		}
		if len(f.References) > 0 {
			b.WriteString("**References:**\n\n")
			for _, ref := range f.References {
				fmt.Fprintf(&b, "- %s\n", ref)
			}
			b.WriteString("\n")
		}
		b.WriteString("---\n\n")
	}
	return b.String()
}
