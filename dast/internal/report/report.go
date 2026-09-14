// Package report renders findings into machine- and human-readable formats:
// JSON, JSONL, SARIF 2.1.0, Markdown and a self-contained HTML report modeled
// on the security-harness deliverable.
package report

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

// Report bundles run metadata with findings.
type Report struct {
	Tool         string            `json:"tool"`
	Version      string            `json:"version"`
	Target       string            `json:"target"`
	SpecTitle    string            `json:"spec_title"`
	GeneratedAt  time.Time         `json:"generated_at"`
	TotalTests   int               `json:"total_tests"`
	TriageSource string            `json:"triage_source"`
	Summary      Summary           `json:"summary"`
	Findings     []*detect.Finding `json:"findings"`
}

// Summary aggregates finding counts.
type Summary struct {
	BySeverity map[string]int `json:"by_severity"`
	ByVerdict  map[string]int `json:"by_verdict"`
	ByClass    map[string]int `json:"by_class"`
	Total      int            `json:"total"`
}

const (
	toolName = "offat-ai-dast"
	version  = "1.0.0"
)

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
var verdictRank = map[string]int{"confirmed": 0, "likely": 1, "inconclusive": 2, "false_positive": 3, "": 4}

// Build assembles a Report, sorting findings by verdict then severity then
// confidence, and computing summary counts.
func Build(target, specTitle string, totalTests int, triageSource string, findings []*detect.Finding) *Report {
	sort.SliceStable(findings, func(i, j int) bool {
		fi, fj := findings[i], findings[j]
		vi, vj := verdictOf(fi), verdictOf(fj)
		if verdictRank[vi] != verdictRank[vj] {
			return verdictRank[vi] < verdictRank[vj]
		}
		if severityRank[fi.Severity] != severityRank[fj.Severity] {
			return severityRank[fi.Severity] < severityRank[fj.Severity]
		}
		return fi.Confidence > fj.Confidence
	})

	sum := Summary{BySeverity: map[string]int{}, ByVerdict: map[string]int{}, ByClass: map[string]int{}, Total: len(findings)}
	for _, f := range findings {
		sum.BySeverity[f.Severity]++
		sum.ByVerdict[verdictOf(f)]++
		sum.ByClass[f.Class]++
	}
	return &Report{
		Tool:         toolName,
		Version:      version,
		Target:       target,
		SpecTitle:    specTitle,
		GeneratedAt:  time.Now().UTC(),
		TotalTests:   totalTests,
		TriageSource: triageSource,
		Summary:      sum,
		Findings:     findings,
	}
}

func verdictOf(f *detect.Finding) string {
	if f.Triage != nil {
		return f.Triage.Verdict
	}
	return ""
}

// WriteJSON writes the full report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteJSONL writes one finding per line.
func WriteJSONL(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	for _, f := range r.Findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// titleCase upper-cases the first rune of a lowercase word (replacement for the
// deprecated strings.Title for our simple single-word severity/verdict labels).
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
