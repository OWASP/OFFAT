package detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/engine"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/kb"
)

// Detect analyzes results and returns candidate findings.
func Detect(results []*engine.Result) []*Finding {
	baselines := map[string]*engine.Result{}
	for _, r := range results {
		if r.Case.Kind == "baseline" {
			baselines[r.Case.ID] = r
		}
	}

	var findings []*Finding
	seen := map[string]bool{}
	add := func(f *Finding) {
		if f == nil {
			return
		}
		key := f.Endpoint + "|" + f.VectorID + "|" + f.Param + "|" + f.Technique
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, f)
	}

	// Group inject results for boolean comparison.
	boolGroups := map[string][]*engine.Result{}

	for _, r := range results {
		tc := r.Case
		if tc.Kind == "baseline" || r.Err != "" && r.StatusCode == 0 {
			// still consider connection errors for time/cmdi? skip pure errors
			if tc.Kind == "baseline" {
				continue
			}
		}
		base := baselines[tc.BaselineID]

		switch tc.Kind {
		case "inject":
			if tc.Technique == kb.TechBoolean {
				gk := tc.Endpoint.ID() + "|" + tc.Vector.ID + "|" + tc.TargetParam
				boolGroups[gk] = append(boolGroups[gk], r)
				continue
			}
			add(detectInject(r, base))
		case "bola":
			add(detectBOLA(r, base))
		case "bfla", "auth_bypass":
			add(detectAuth(r))
		case "jwt_none":
			add(detectJWTNone(r))
		case "mass_assignment":
			add(detectMassAssignment(r))
		case "method_tamper":
			add(detectMethodTamper(r))
		case "rate_limit":
			add(detectRateLimit(r))
		case "cors":
			add(detectCORS(r))
		case "data_exposure":
			add(detectDataExposure(r))
		}
	}

	for _, group := range boolGroups {
		add(detectBoolean(group))
	}
	return findings
}

// detectInject handles error/reflection/time/status/diff techniques on an
// injected payload, comparing against the endpoint baseline.
func detectInject(r *engine.Result, base *engine.Result) *Finding {
	v := r.Case.Vector
	body := strings.ToLower(string(r.Body))
	baseBody := ""
	if base != nil {
		baseBody = strings.ToLower(string(base.Body))
	}

	// Error signatures fire for any technique (a DB/engine error is strong).
	for _, sig := range v.Detection.ErrorSignatures {
		s := strings.ToLower(sig)
		if s == "" {
			continue
		}
		if strings.Contains(body, s) && !strings.Contains(baseBody, s) {
			return newFinding(r, v, 0.85, kb.TechError, evidenceWith(r, base, sig, snippetAround(string(r.Body), sig)))
		}
	}

	switch r.Case.Technique {
	case kb.TechReflection:
		if v.Detection.ReflectMarker {
			pl := r.Case.Meta["payload"]
			if pl != "" && strings.Contains(string(r.Body), pl) && looksHTML(r) {
				return newFinding(r, v, 0.7, kb.TechReflection, evidenceWith(r, base, pl, snippetAround(string(r.Body), pl)))
			}
		}
		if m := matchBodyRegex(v.Detection.BodyRegex, string(r.Body), string(bodyOf(base))); m != "" {
			return newFinding(r, v, 0.9, kb.TechReflection, evidenceWith(r, base, m, snippetAround(string(r.Body), m)))
		}
	case kb.TechTime:
		th := int64(v.Detection.TimeThresholdMs)
		if th > 0 && r.LatencyMs >= th && (base == nil || r.LatencyMs >= base.LatencyMs+th-500) {
			ev := evidenceWith(r, base, "", "")
			ev.Notes = fmt.Sprintf("response delayed %dms (threshold %dms)", r.LatencyMs, th)
			return newFinding(r, v, 0.75, kb.TechTime, ev)
		}
	case kb.TechStatus:
		if intIn(r.StatusCode, v.Detection.StatusCodes) {
			if m := matchBodyRegex(v.Detection.BodyRegex, string(r.Body), ""); m != "" || len(v.Detection.BodyRegex) == 0 {
				return newFinding(r, v, 0.8, kb.TechStatus, evidenceWith(r, base, m, ""))
			}
		}
	case kb.TechDiff:
		if m := matchBodyRegex(v.Detection.BodyRegex, string(r.Body), baseBody); m != "" {
			return newFinding(r, v, 0.6, kb.TechDiff, evidenceWith(r, base, m, snippetAround(string(r.Body), m)))
		}
	}
	// Generic body_regex fallback for any technique.
	if m := matchBodyRegex(v.Detection.BodyRegex, string(r.Body), baseBody); m != "" {
		return newFinding(r, v, 0.7, r.Case.Technique, evidenceWith(r, base, m, snippetAround(string(r.Body), m)))
	}
	return nil
}

func detectBoolean(group []*engine.Result) *Finding {
	var tr, fa *engine.Result
	for _, r := range group {
		note := ""
		if r.Case.Payload != nil {
			note = r.Case.Payload.Note
		}
		switch note {
		case "true":
			tr = r
		case "false":
			fa = r
		}
	}
	if tr == nil || fa == nil {
		return nil
	}
	// A stable, meaningful difference between the true/false conditions.
	if tr.StatusCode == fa.StatusCode && similarLen(len(tr.Body), len(fa.Body)) {
		return nil
	}
	v := tr.Case.Vector
	ev := Evidence{
		RequestMethod: tr.Case.Request.Method,
		StatusCode:    tr.StatusCode,
		Notes: fmt.Sprintf("boolean differential: true=%d/%dB vs false=%d/%dB",
			tr.StatusCode, len(tr.Body), fa.StatusCode, len(fa.Body)),
	}
	return newFinding(tr, v, 0.7, kb.TechBoolean, ev)
}

// ---- structural detectors -------------------------------------------------

func detectBOLA(r *engine.Result, _ *engine.Result) *Finding {
	if !is2xx(r.StatusCode) || len(r.Body) == 0 {
		return nil
	}
	conf := 0.45
	if looksLikeObject(r.Body) {
		conf = 0.55
	}
	ev := evidenceWith(r, nil, "", snippet(string(r.Body)))
	ev.Notes = "endpoint returned 2xx for a foreign/guessed object identifier; verify ownership"
	return newFinding(r, r.Case.Vector, conf, "", ev)
}

func detectAuth(r *engine.Result) *Finding {
	if !is2xx(r.StatusCode) {
		return nil
	}
	ev := evidenceWith(r, nil, "", snippet(string(r.Body)))
	ev.Notes = "protected operation returned 2xx without valid credentials"
	return newFinding(r, r.Case.Vector, 0.75, "", ev)
}

func detectJWTNone(r *engine.Result) *Finding {
	if !is2xx(r.StatusCode) {
		return nil
	}
	ev := evidenceWith(r, nil, "", snippet(string(r.Body)))
	ev.Notes = "request accepted with an alg=none forged JWT"
	return newFinding(r, r.Case.Vector, 0.8, "", ev)
}

func detectMassAssignment(r *engine.Result) *Finding {
	if !is2xx(r.StatusCode) {
		return nil
	}
	body := strings.ToLower(string(r.Body))
	conf := 0.45
	note := "write accepted extra sensitive properties (verify effect on stored object)"
	for _, marker := range []string{"\"role\":\"admin\"", "\"is_admin\":true", "\"isadmin\":true", "\"admin\":true"} {
		if strings.Contains(strings.ReplaceAll(body, " ", ""), marker) {
			conf = 0.8
			note = "response reflects the injected privileged property: " + marker
			break
		}
	}
	ev := evidenceWith(r, nil, "", snippet(string(r.Body)))
	ev.Notes = note
	return newFinding(r, r.Case.Vector, conf, "", ev)
}

func detectMethodTamper(r *engine.Result) *Finding {
	if !is2xx(r.StatusCode) {
		return nil
	}
	ev := evidenceWith(r, nil, "", "")
	ev.Notes = fmt.Sprintf("undocumented method %s accepted (2xx)", r.Case.Request.Method)
	return newFinding(r, r.Case.Vector, 0.5, "", ev)
}

func detectRateLimit(r *engine.Result) *Finding {
	if len(r.RepeatStatuses) == 0 {
		return nil
	}
	for _, s := range r.RepeatStatuses {
		if s == 429 || s == 503 {
			return nil // throttling observed
		}
	}
	ev := evidenceWith(r, nil, "", "")
	ev.Notes = fmt.Sprintf("%d rapid requests, no 429/503 throttling observed", len(r.RepeatStatuses))
	return newFinding(r, r.Case.Vector, 0.5, "", ev)
}

func detectCORS(r *engine.Result) *Finding {
	if r.Headers == nil {
		return nil
	}
	acao := r.Headers.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(r.Headers.Get("Access-Control-Allow-Credentials"))
	if (acao == "https://offat-evil.example" || acao == "*") && acac == "true" {
		ev := evidenceWith(r, nil, acao, "")
		ev.Notes = "reflected/again-wildcard ACAO with credentials allowed"
		return newFinding(r, r.Case.Vector, 0.85, "", ev)
	}
	return nil
}

var sensitiveField = regexp.MustCompile(`(?i)"(password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|ssn|social_?security|credit_?card|card_?number|cvv|auth|session)"\s*:`)

func detectDataExposure(r *engine.Result) *Finding {
	if len(r.Body) == 0 {
		return nil
	}
	if m := sensitiveField.FindString(string(r.Body)); m != "" {
		ev := evidenceWith(r, nil, m, snippetAround(string(r.Body), strings.Trim(m, `":`)))
		ev.Notes = "response body exposes a sensitive-looking field: " + m
		return newFinding(r, r.Case.Vector, 0.6, "", ev)
	}
	return nil
}
