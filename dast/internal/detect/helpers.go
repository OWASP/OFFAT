package detect

import (
	"regexp"
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/engine"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/kb"
)

func newFinding(r *engine.Result, v *kb.Vector, conf float64, tech kb.Technique, ev Evidence) *Finding {
	ep := r.Case.Endpoint
	technique := string(tech)
	if technique == "" {
		technique = string(r.Case.Technique)
	}
	return &Finding{
		ID:          r.Case.ID,
		VectorID:    v.ID,
		Class:       v.Class,
		Title:       v.Title,
		Severity:    strings.ToLower(v.Severity),
		CWE:         v.CWE,
		OWASP:       v.OWASP,
		Method:      ep.Method,
		Path:        ep.Path,
		Endpoint:    ep.ID(),
		Param:       r.Case.TargetParam,
		Location:    r.Case.TargetIn,
		Technique:   technique,
		Payload:     r.Case.Meta["payload"],
		Description: v.Description,
		References:  v.References,
		Confidence:  conf,
		Evidence:    ev,
	}
}

func evidenceWith(r, base *engine.Result, sig, snip string) Evidence {
	ev := Evidence{
		RequestMethod:    r.Case.Request.Method,
		StatusCode:       r.StatusCode,
		LatencyMs:        r.LatencyMs,
		MatchedSignature: sig,
		Snippet:          snip,
	}
	if base != nil {
		ev.BaselineStatus = base.StatusCode
		ev.BaselineLatencyMs = base.LatencyMs
	}
	return ev
}

func bodyOf(r *engine.Result) []byte {
	if r == nil {
		return nil
	}
	return r.Body
}

// matchBodyRegex returns the first regex match present in body but absent in
// baseline (to avoid flagging pre-existing content). An empty baseline disables
// the suppression.
func matchBodyRegex(patterns []string, body, baseline string) string {
	for _, p := range patterns {
		re := compile(p)
		if re == nil {
			continue
		}
		m := re.FindString(body)
		if m == "" {
			continue
		}
		if baseline != "" && re.MatchString(baseline) {
			continue
		}
		return m
	}
	return ""
}

var detectReCache = map[string]*regexp.Regexp{}

func compile(p string) *regexp.Regexp {
	if re, ok := detectReCache[p]; ok {
		return re
	}
	re, err := regexp.Compile(p)
	if err != nil {
		detectReCache[p] = nil
		return nil
	}
	detectReCache[p] = re
	return re
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}

func snippetAround(body, needle string) string {
	idx := strings.Index(strings.ToLower(body), strings.ToLower(needle))
	if idx < 0 {
		return snippet(body)
	}
	start := idx - 80
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + 80
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

func looksHTML(r *engine.Result) bool {
	ct := ""
	if r.Headers != nil {
		ct = strings.ToLower(r.Headers.Get("Content-Type"))
	}
	if strings.Contains(ct, "html") {
		return true
	}
	// Reflected into a non-HTML JSON string is generally not exploitable XSS;
	// require an HTML-ish content type or an html tag in the body.
	return strings.Contains(strings.ToLower(string(r.Body)), "<html") || ct == ""
}

func looksLikeObject(body []byte) bool {
	t := strings.TrimSpace(string(body))
	return strings.HasPrefix(t, "{") && strings.Contains(t, ":")
}

func is2xx(code int) bool { return code >= 200 && code < 300 }

func intIn(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func similarLen(a, b int) bool {
	if a == b {
		return true
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	larger := a
	if b > a {
		larger = b
	}
	if larger == 0 {
		return true
	}
	return float64(diff)/float64(larger) < 0.05
}
