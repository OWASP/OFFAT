package report

import (
	"encoding/json"
	"io"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

// WriteSARIF emits SARIF 2.1.0 so findings can be consumed by GitHub code
// scanning and other tooling.
func WriteSARIF(w io.Writer, r *Report) error {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := rules[f.VectorID]; !ok {
			rules[f.VectorID] = sarifRule{
				ID:   f.VectorID,
				Name: f.Class,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Description},
				HelpURI:          firstRef(f.References),
				Properties:       map[string]any{"cwe": f.CWE, "owasp": f.OWASP, "security-severity": cvssString(f)},
			}
		}
		results = append(results, sarifResult{
			RuleID:  f.VectorID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: sarifMessage(f)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Method + " " + f.Path},
					Region:           sarifRegion{StartLine: 1},
				},
			}},
			Properties: map[string]any{
				"confidence": f.Confidence,
				"verdict":    verdictOf(f),
				"param":      f.Param,
			},
		})
	}
	var ruleList []sarifRule
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				Version:        version,
				InformationURI: "https://github.com/dmdhrumilmistry/offat-ai",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifMessage(f *detect.Finding) string {
	m := f.Title + " on " + f.Method + " " + f.Path
	if f.Param != "" {
		m += " (parameter: " + f.Param + ")"
	}
	if f.Triage != nil {
		m += " — verdict: " + f.Triage.Verdict
	}
	return m
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func firstRef(refs []string) string {
	if len(refs) > 0 {
		return refs[0]
	}
	return ""
}

func cvssString(f *detect.Finding) string {
	if f.Triage != nil && f.Triage.CVSS > 0 {
		return jsonNumber(f.Triage.CVSS)
	}
	return ""
}

func jsonNumber(v float64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ---- SARIF types ----

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}
type sarifText struct {
	Text string `json:"text"`
}
