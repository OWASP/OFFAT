// Package triage validates candidate findings and enriches them with a
// verdict, CVSS score and remediation. It offers a deterministic heuristic
// triager (always available, no network) and an AI triager backed by the
// Anthropic Messages API. The AI triager falls back to the heuristic on any
// error so a run never fails because of triage.
package triage

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

// Triager assigns a verdict to a finding.
type Triager interface {
	Name() string
	Triage(ctx context.Context, f *detect.Finding) error
}

// Run applies a triager to every finding with bounded concurrency.
func Run(ctx context.Context, t Triager, findings []*detect.Finding, concurrency int) {
	if concurrency <= 0 {
		concurrency = 4
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, f := range findings {
		wg.Add(1)
		sem <- struct{}{}
		go func(f *detect.Finding) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := t.Triage(ctx, f); err != nil && f.Triage == nil {
				// Guarantee every finding ends up triaged.
				_ = Heuristic{}.Triage(ctx, f)
			}
		}(f)
	}
	wg.Wait()
}

// Heuristic is a deterministic, offline triager.
type Heuristic struct{}

func (Heuristic) Name() string { return "heuristic" }

func (Heuristic) Triage(_ context.Context, f *detect.Finding) error {
	verdict := verdictFromConfidence(f.Confidence)
	// Structural, ownership-dependent classes cannot be blindly confirmed.
	if f.Class == "access_control" || f.Class == "mass_assignment" {
		if verdict == "confirmed" {
			verdict = "likely"
		}
	}
	f.Triage = &detect.Triage{
		Verdict:     verdict,
		Confidence:  f.Confidence,
		CVSS:        cvssFor(f.Severity),
		Severity:    f.Severity,
		Rationale:   rationale(f),
		Remediation: remediationFor(f.Class),
		Source:      "heuristic",
	}
	return nil
}

func verdictFromConfidence(c float64) string {
	switch {
	case c >= 0.8:
		return "confirmed"
	case c >= 0.6:
		return "likely"
	case c >= 0.4:
		return "inconclusive"
	default:
		return "false_positive"
	}
}

func rationale(f *detect.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Detected via %s on %s parameter %q. ", f.Technique, f.Location, f.Param)
	if f.Evidence.MatchedSignature != "" {
		fmt.Fprintf(&b, "Matched signal: %s. ", f.Evidence.MatchedSignature)
	}
	if f.Evidence.Notes != "" {
		b.WriteString(f.Evidence.Notes)
	}
	return strings.TrimSpace(b.String())
}

func cvssFor(sev string) float64 {
	switch strings.ToLower(sev) {
	case "critical":
		return 9.3
	case "high":
		return 7.5
	case "medium":
		return 5.3
	case "low":
		return 3.1
	default:
		return 0
	}
}

var remediation = map[string]string{
	"sqli":              "Use parameterized queries / prepared statements; never concatenate untrusted input into SQL. Apply least-privilege DB accounts.",
	"nosqli":            "Validate and type-check inputs; reject query operators in user data; use an ODM with strict schemas.",
	"command_injection": "Avoid shell invocation; use exec APIs with argument arrays and an allowlist; never pass untrusted input to a shell.",
	"ssti":              "Do not render user input as templates; use logic-less templates and context-aware escaping; sandbox the engine.",
	"ldap_injection":    "Escape LDAP special characters and use parameterized directory queries.",
	"xss":               "Context-aware output encoding, a strict Content-Security-Policy, and input validation.",
	"path_traversal":    "Canonicalize paths and enforce an allowlisted base directory; reject '..' and absolute paths.",
	"ssrf":              "Allowlist outbound hosts, resolve and validate targets, block link-local/metadata ranges, disable unused URL schemes.",
	"open_redirect":     "Use an allowlist of redirect targets or relative paths only; never redirect to raw user input.",
	"xxe":               "Disable external entity resolution and DTD processing in the XML parser.",
	"access_control":    "Enforce object-level authorization on every request server-side; scope queries to the authenticated principal.",
	"mass_assignment":   "Bind only explicitly-allowed properties (allowlist DTOs); never bind request bodies directly to models.",
	"broken_auth":       "Enforce authentication server-side on every protected route; verify JWT signatures with a fixed algorithm allowlist.",
	"security_misconfig":"Restrict HTTP methods, configure CORS with a strict origin allowlist, and enforce rate limiting.",
	"data_exposure":     "Return only the fields a client needs (response DTOs); never serialize secrets or credentials.",
}

func remediationFor(class string) string {
	if r, ok := remediation[class]; ok {
		return r
	}
	return "Validate and sanitize all untrusted input; enforce authorization and least privilege."
}
