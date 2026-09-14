package report

import (
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

var severities = []string{"critical", "high", "medium", "low", "info"}

// WriteMarkdown renders a security-harness-style Markdown report.
func WriteMarkdown(w io.Writer, r *Report) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("# OFFAT-AI DAST Report\n\n")
	p("- **Target:** `%s`\n", r.Target)
	if r.SpecTitle != "" {
		p("- **API:** %s\n", r.SpecTitle)
	}
	p("- **Generated:** %s\n", r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	p("- **Tests executed:** %d\n", r.TotalTests)
	p("- **Triage:** %s\n\n", r.TriageSource)

	p("## Summary\n\n")
	p("| Severity | Count |\n|---|---|\n")
	for _, s := range severities {
		if c := r.Summary.BySeverity[s]; c > 0 {
			p("| %s | %d |\n", titleCase(s), c)
		}
	}
	p("\n| Verdict | Count |\n|---|---|\n")
	for _, v := range []string{"confirmed", "likely", "inconclusive", "false_positive"} {
		if c := r.Summary.ByVerdict[v]; c > 0 {
			p("| %s | %d |\n", v, c)
		}
	}
	p("\n**Total findings:** %d\n\n", r.Summary.Total)

	p("## Findings\n\n")
	if len(r.Findings) == 0 {
		p("_No findings._\n")
		return nil
	}
	for i, f := range r.Findings {
		p("### %d. %s\n\n", i+1, f.Title)
		p("- **Severity:** %s", titleCase(f.Severity))
		if f.Triage != nil {
			p("  |  **Verdict:** %s  |  **Confidence:** %.0f%%  |  **CVSS:** %.1f", f.Triage.Verdict, f.Triage.Confidence*100, f.Triage.CVSS)
		}
		p("\n- **Endpoint:** `%s`\n", f.Endpoint)
		if f.Param != "" {
			p("- **Parameter:** `%s` (in %s)\n", f.Param, f.Location)
		}
		p("- **Class:** %s  |  **CWE:** %s  |  **OWASP:** %s\n", f.Class, f.CWE, f.OWASP)
		if f.Technique != "" {
			p("- **Technique:** %s\n", f.Technique)
		}
		if f.Payload != "" {
			p("- **Payload:** `%s`\n", oneLine(f.Payload))
		}
		p("\n%s\n\n", f.Description)
		p("**Evidence**\n\n")
		p("- Request: `%s` → status `%d`", f.Evidence.RequestMethod, f.Evidence.StatusCode)
		if f.Evidence.BaselineStatus != 0 {
			p(" (baseline `%d`)", f.Evidence.BaselineStatus)
		}
		p("\n")
		if f.Evidence.LatencyMs > 0 {
			p("- Latency: %dms", f.Evidence.LatencyMs)
			if f.Evidence.BaselineLatencyMs > 0 {
				p(" (baseline %dms)", f.Evidence.BaselineLatencyMs)
			}
			p("\n")
		}
		if f.Evidence.MatchedSignature != "" {
			p("- Matched signal: `%s`\n", oneLine(f.Evidence.MatchedSignature))
		}
		if f.Evidence.Notes != "" {
			p("- Notes: %s\n", f.Evidence.Notes)
		}
		if f.Evidence.Snippet != "" {
			p("\n```\n%s\n```\n", truncate(f.Evidence.Snippet, 600))
		}
		if f.Triage != nil {
			if f.Triage.Rationale != "" {
				p("\n**Triage rationale:** %s\n", f.Triage.Rationale)
			}
			if f.Triage.Remediation != "" {
				p("\n**Remediation:** %s\n", f.Triage.Remediation)
			}
		}
		if len(f.References) > 0 {
			p("\n**References:**\n")
			for _, ref := range f.References {
				p("- %s\n", ref)
			}
		}
		p("\n---\n\n")
	}
	return nil
}

// WriteHTML renders a self-contained HTML report.
func WriteHTML(w io.Writer, r *Report) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	p(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	p("<title>OFFAT-AI DAST Report</title>")
	p("<style>%s</style></head><body>", reportCSS)
	p(`<div class="wrap">`)
	p("<h1>OFFAT-AI DAST Report</h1>")
	p(`<div class="meta">`)
	p("<div><b>Target</b><span>%s</span></div>", html.EscapeString(r.Target))
	p("<div><b>API</b><span>%s</span></div>", html.EscapeString(r.SpecTitle))
	p("<div><b>Generated</b><span>%s</span></div>", r.GeneratedAt.Format("2006-01-02 15:04 UTC"))
	p("<div><b>Tests</b><span>%d</span></div>", r.TotalTests)
	p("<div><b>Triage</b><span>%s</span></div>", html.EscapeString(r.TriageSource))
	p("</div>")

	p(`<div class="cards">`)
	for _, s := range severities {
		if c := r.Summary.BySeverity[s]; c > 0 {
			p(`<div class="card sev-%s"><span class="n">%d</span><span class="l">%s</span></div>`, s, c, titleCase(s))
		}
	}
	p("</div>")

	for i, f := range r.Findings {
		verdict := ""
		conf := 0.0
		cvss := 0.0
		if f.Triage != nil {
			verdict = f.Triage.Verdict
			conf = f.Triage.Confidence
			cvss = f.Triage.CVSS
		}
		p(`<div class="finding sev-border-%s">`, f.Severity)
		p(`<h2><span class="pill sev-%s">%s</span> %d. %s</h2>`, f.Severity, titleCase(f.Severity), i+1, html.EscapeString(f.Title))
		p(`<div class="tags">`)
		p(`<span class="tag">%s</span>`, html.EscapeString(f.Endpoint))
		if f.Param != "" {
			p(`<span class="tag">param: %s (%s)</span>`, html.EscapeString(f.Param), html.EscapeString(f.Location))
		}
		p(`<span class="tag">%s</span><span class="tag">%s</span>`, html.EscapeString(f.CWE), html.EscapeString(f.OWASP))
		if verdict != "" {
			p(`<span class="tag verdict-%s">%s · %.0f%% · CVSS %.1f</span>`, verdict, verdict, conf*100, cvss)
		}
		p("</div>")
		p(`<p>%s</p>`, html.EscapeString(f.Description))
		if f.Payload != "" {
			p(`<p><b>Payload:</b> <code>%s</code></p>`, html.EscapeString(oneLine(f.Payload)))
		}
		p(`<p><b>Evidence:</b> %s → status %d`, html.EscapeString(f.Evidence.RequestMethod), f.Evidence.StatusCode)
		if f.Evidence.BaselineStatus != 0 {
			p(` (baseline %d)`, f.Evidence.BaselineStatus)
		}
		if f.Evidence.Notes != "" {
			p(` — %s`, html.EscapeString(f.Evidence.Notes))
		}
		p("</p>")
		if f.Evidence.Snippet != "" {
			p(`<pre>%s</pre>`, html.EscapeString(truncate(f.Evidence.Snippet, 600)))
		}
		if f.Triage != nil {
			if f.Triage.Rationale != "" {
				p(`<p><b>Triage:</b> %s</p>`, html.EscapeString(f.Triage.Rationale))
			}
			if f.Triage.Remediation != "" {
				p(`<p class="rem"><b>Remediation:</b> %s</p>`, html.EscapeString(f.Triage.Remediation))
			}
		}
		p("</div>")
	}
	p("</div></body></html>")
	return nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var _ = detect.Finding{}

const reportCSS = `
:root{--bg:#0e1116;--panel:#171b22;--fg:#e6e6e6;--muted:#9aa4b2;--line:#2a3038}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 16px}
.meta{display:flex;flex-wrap:wrap;gap:16px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-bottom:18px}
.meta div{display:flex;flex-direction:column}.meta b{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.card{flex:1;min-width:110px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;text-align:center}
.card .n{display:block;font-size:26px;font-weight:700}.card .l{color:var(--muted);font-size:12px;text-transform:uppercase}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:16px 18px;margin-bottom:16px}
.finding h2{font-size:17px;margin:0 0 10px}
.tags{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.tag{background:#20262f;border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:12px;color:var(--muted)}
.pill{border-radius:6px;padding:2px 8px;font-size:12px;color:#fff;margin-right:6px}
code,pre{background:#0b0e13;border:1px solid var(--line);border-radius:6px}
code{padding:1px 6px}pre{padding:12px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}
.rem{color:#8fd19e}
.sev-critical{background:#7b1e1e}.sev-high{background:#a3421c}.sev-medium{background:#8a6d1a}.sev-low{background:#3b5566}.sev-info{background:#3a3f47}
.sev-border-critical{border-left-color:#e5484d}.sev-border-high{border-left-color:#f0883e}.sev-border-medium{border-left-color:#e3b341}.sev-border-low{border-left-color:#539bf5}.sev-border-info{border-left-color:#6a737d}
.verdict-confirmed{color:#e5484d;border-color:#e5484d}.verdict-likely{color:#f0883e}.verdict-inconclusive{color:#9aa4b2}.verdict-false_positive{color:#6a737d}
`
