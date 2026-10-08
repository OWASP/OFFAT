package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

func sampleFindings() []*detect.Finding {
	return []*detect.Finding{
		{
			ID: "1", VectorID: "sqli-error", Class: "sqli", Title: "SQL injection",
			Severity: "high", CWE: "CWE-89", OWASP: "API8:2023",
			Endpoint: "GET /search", Param: "q", Confidence: 0.9,
			Evidence: detect.Evidence{RequestMethod: "GET", StatusCode: 500},
			Triage:   &detect.Triage{Verdict: "confirmed", CVSS: 8.1, Source: "heuristic"},
		},
		{
			ID: "2", VectorID: "xss-reflected", Class: "xss", Title: "Reflected XSS",
			Severity: "medium", CWE: "CWE-79", OWASP: "API3:2023",
			Endpoint: "GET /echo", Param: "msg", Confidence: 0.6,
			Evidence: detect.Evidence{RequestMethod: "GET", StatusCode: 200},
			Triage:   &detect.Triage{Verdict: "false_positive", Source: "heuristic"},
		},
		{
			ID: "3", VectorID: "bola", Class: "bola", Title: "Broken object level auth",
			Severity: "critical", CWE: "CWE-639", OWASP: "API1:2023",
			Endpoint: "GET /users/{id}", Confidence: 0.8,
			Evidence: detect.Evidence{RequestMethod: "GET", StatusCode: 200},
			Triage:   &detect.Triage{Verdict: "likely", CVSS: 9.1, Source: "ai"},
		},
	}
}

func TestBuildSortsAndSummarizes(t *testing.T) {
	r := Build("https://t.example", "Shop API", 42, "heuristic", sampleFindings())
	if r.Summary.Total != 3 {
		t.Fatalf("total = %d, want 3", r.Summary.Total)
	}
	// confirmed (rank 0) sorts before likely (rank 1) before false_positive.
	if r.Findings[0].Triage.Verdict != "confirmed" {
		t.Errorf("first verdict = %q, want confirmed", r.Findings[0].Triage.Verdict)
	}
	if r.Findings[len(r.Findings)-1].Triage.Verdict != "false_positive" {
		t.Errorf("last verdict = %q, want false_positive", r.Findings[len(r.Findings)-1].Triage.Verdict)
	}
	if r.Summary.BySeverity["critical"] != 1 || r.Summary.BySeverity["high"] != 1 {
		t.Errorf("severity summary wrong: %+v", r.Summary.BySeverity)
	}
	if r.Summary.ByVerdict["confirmed"] != 1 || r.Summary.ByVerdict["false_positive"] != 1 {
		t.Errorf("verdict summary wrong: %+v", r.Summary.ByVerdict)
	}
}

func TestCountAtOrAbove(t *testing.T) {
	r := Build("t", "", 0, "heuristic", sampleFindings())
	// critical + high actionable = 2; the medium one is a false positive.
	if n := CountAtOrAbove(r, "high"); n != 2 {
		t.Errorf("CountAtOrAbove(high) = %d, want 2", n)
	}
	if n := CountAtOrAbove(r, "critical"); n != 1 {
		t.Errorf("CountAtOrAbove(critical) = %d, want 1", n)
	}
	// medium threshold would include the medium finding, but it is a false
	// positive, so it does not count.
	if n := CountAtOrAbove(r, "medium"); n != 2 {
		t.Errorf("CountAtOrAbove(medium) = %d, want 2", n)
	}
	if n := CountAtOrAbove(r, ""); n != 0 {
		t.Errorf("CountAtOrAbove(empty) = %d, want 0", n)
	}
	if n := CountAtOrAbove(r, "bogus"); n != 0 {
		t.Errorf("CountAtOrAbove(bogus) = %d, want 0", n)
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	r := Build("t", "", 1, "heuristic", sampleFindings())
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if back.Summary.Total != 3 {
		t.Errorf("round-trip total = %d, want 3", back.Summary.Total)
	}
}

func TestWriteJSONLOneLinePerFinding(t *testing.T) {
	r := Build("t", "", 1, "heuristic", sampleFindings())
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, r); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	for i, ln := range lines {
		var f detect.Finding
		if err := json.Unmarshal([]byte(ln), &f); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestWriteSARIFValid(t *testing.T) {
	r := Build("t", "", 1, "heuristic", sampleFindings())
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %v", doc["runs"])
	}
}

func TestWriteJUnitValid(t *testing.T) {
	r := Build("t", "", 1, "heuristic", sampleFindings())
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JUnit not valid XML: %v", err)
	}
	if doc.Tests != 3 {
		t.Errorf("tests = %d, want 3", doc.Tests)
	}
	// Two actionable findings (confirmed + likely); the false positive is not.
	if doc.Failures != 2 {
		t.Errorf("failures = %d, want 2", doc.Failures)
	}
	if len(doc.Suites) != 1 || len(doc.Suites[0].Cases) != 3 {
		t.Fatalf("expected 1 suite with 3 cases, got %+v", doc.Suites)
	}
	var failed int
	for _, c := range doc.Suites[0].Cases {
		if c.Failure != nil {
			failed++
		}
	}
	if failed != 2 {
		t.Errorf("failure elements = %d, want 2", failed)
	}
}

func TestWriteMarkdownAndHTMLNonEmpty(t *testing.T) {
	r := Build("t", "Shop API", 1, "heuristic", sampleFindings())
	var md bytes.Buffer
	if err := WriteMarkdown(&md, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "SQL injection") {
		t.Error("markdown missing a finding title")
	}
	var h bytes.Buffer
	if err := WriteHTML(&h, r); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(h.String()), "<!doctype html>") {
		t.Error("HTML report missing doctype")
	}
}
