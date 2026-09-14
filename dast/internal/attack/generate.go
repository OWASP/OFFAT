// Package attack turns a parsed API, its dataflow graph and the knowledge base
// into concrete test cases. Payload vectors are expanded per applicable
// injection point; structural vectors (BOLA, mass assignment, auth bypass, ...)
// are expanded by dedicated builders that use the request structure and graph.
package attack

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/graph"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/kb"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

// Options tunes generation.
type Options struct {
	MaxPayloadsPerVector int // 0 = unlimited
}

// Generate produces the full set of test cases for an API.
func Generate(api *spec.API, g *graph.Graph, k *kb.KB, opts Options) []*TestCase {
	var cases []*TestCase
	order := g.Order
	if len(order) == 0 {
		order = api.Endpoints
	}
	for _, ep := range order {
		base := buildBaseline(ep)

		// 1. Baseline request (establishes normal behavior for diff/boolean).
		baseID := fmt.Sprintf("%s|%s|baseline", ep.Method, ep.Path)
		cases = append(cases, &TestCase{
			ID:       baseID,
			Endpoint: ep,
			Kind:     "baseline",
			Request:  base.spec("", "", ""),
		})

		pts := base.points()
		for _, v := range k.Vectors {
			if v.Structural != "" {
				cases = append(cases, buildStructural(ep, base, v, g)...)
				continue
			}
			for _, pt := range pts {
				if !applies(v, ep, pt) {
					continue
				}
				cases = append(cases, buildInjections(ep, base, v, pt, baseID, opts)...)
			}
		}
	}
	return cases
}

// applies reports whether a payload vector targets a given injection point.
func applies(v *kb.Vector, ep *spec.Endpoint, pt injectionPoint) bool {
	a := v.AppliesTo
	if !containsFold(a.Locations, pt.in) {
		return false
	}
	if len(a.Types) > 0 && !containsFold(a.Types, pt.typ) && !containsFold(a.Types, "any") {
		return false
	}
	if len(a.Methods) > 0 && !containsFold(a.Methods, ep.Method) {
		return false
	}
	if len(a.NamePatterns) > 0 && !matchesAny(a.NamePatterns, pt.name) {
		return false
	}
	return true
}

func buildInjections(ep *spec.Endpoint, base baseVals, v *kb.Vector, pt injectionPoint, baseID string, opts Options) []*TestCase {
	var out []*TestCase
	for i, pl := range v.Payloads {
		if opts.MaxPayloadsPerVector > 0 && i >= opts.MaxPayloadsPerVector {
			break
		}
		value := encodePayload(pl)
		tc := &TestCase{
			ID:          fmt.Sprintf("%s|%s|%s|%s|%s|%d", ep.Method, ep.Path, v.ID, pt.in, pt.name, i),
			Endpoint:    ep,
			Kind:        "inject",
			Vector:      v,
			Payload:     &v.Payloads[i],
			Technique:   pl.Technique,
			TargetParam: pt.name,
			TargetIn:    pt.in,
			BaselineID:  baseID,
			Request:     base.spec(pt.in, pt.name, value),
		}
		tc.setMeta("payload", value)
		out = append(out, tc)
	}
	return out
}

func encodePayload(pl kb.Payload) string {
	switch strings.ToLower(pl.Encoding) {
	case "url":
		return url.QueryEscape(pl.Value)
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(pl.Value))
	default:
		return pl.Value
	}
}

// ---------------------------------------------------------------------------
// Structural attack builders
// ---------------------------------------------------------------------------

func buildStructural(ep *spec.Endpoint, base baseVals, v *kb.Vector, g *graph.Graph) []*TestCase {
	switch v.Structural {
	case "bola":
		return buildBOLA(ep, base, v)
	case "bfla":
		return buildBFLA(ep, base, v)
	case "mass_assignment":
		return buildMassAssignment(ep, base, v)
	case "auth_bypass":
		return buildAuthBypass(ep, base, v)
	case "jwt_none":
		return buildJWTNone(ep, base, v)
	case "method_tamper":
		return buildMethodTamper(ep, base, v)
	case "rate_limit":
		return buildRateLimit(ep, base, v)
	case "cors":
		return buildCORS(ep, base, v)
	case "data_exposure":
		return buildDataExposure(ep, base, v)
	}
	return nil
}

// buildBOLA probes object-level authorization by seeding a foreign identifier
// into each id-like path/query parameter.
func buildBOLA(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	var out []*TestCase
	for name, hint := range base.seed {
		rs := base.spec("", "", "")
		fh := hint
		fh.Foreign = true
		rs.SeedParams[name] = fh
		out = append(out, &TestCase{
			ID:          fmt.Sprintf("%s|%s|bola|%s", ep.Method, ep.Path, name),
			Endpoint:    ep,
			Kind:        "bola",
			Vector:      v,
			TargetParam: name,
			TargetIn:    hint.In,
			Request:     rs,
		})
	}
	return out
}

func buildBFLA(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	// Only for endpoints whose path looks privileged.
	if !matchesAny(v.AppliesTo.NamePatterns, ep.Path) {
		return nil
	}
	rs := base.spec("", "", "")
	rs.OmitAuth = true // unauthenticated / low-priv attempt at a privileged op
	return []*TestCase{{
		ID:       fmt.Sprintf("%s|%s|bfla", ep.Method, ep.Path),
		Endpoint: ep, Kind: "bfla", Vector: v, TargetIn: "path", Request: rs,
	}}
}

func buildMassAssignment(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	if base.ep.Body == nil || !base.bodyIsObj {
		return nil
	}
	sensitive := []string{"role", "is_admin", "isAdmin", "admin", "verified", "is_verified",
		"active", "status", "balance", "credit", "permissions", "scopes", "owner", "user_id", "id"}
	src, _ := base.body.(map[string]any)
	dst := map[string]any{}
	for k, val := range src {
		dst[k] = val
	}
	for _, s := range sensitive {
		if _, exists := dst[s]; !exists {
			dst[s] = massValue(s)
		}
	}
	body, ct := marshalBody(base.contentType, dst)
	rs := base.spec("", "", "")
	rs.Body, rs.ContentType = body, ct
	return []*TestCase{{
		ID:       fmt.Sprintf("%s|%s|mass_assignment", ep.Method, ep.Path),
		Endpoint: ep, Kind: "mass_assignment", Vector: v, TargetIn: "body",
		Request: rs,
	}}
}

func massValue(field string) any {
	switch field {
	case "role", "status":
		return "admin"
	case "is_admin", "isAdmin", "admin", "verified", "is_verified", "active":
		return true
	case "balance", "credit":
		return 999999
	case "permissions", "scopes":
		return []any{"admin", "*"}
	default:
		return "1"
	}
}

func buildAuthBypass(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	// Only meaningful where the operation declares a security requirement.
	if len(ep.Security) == 0 {
		return nil
	}
	rs := base.spec("", "", "")
	rs.OmitAuth = true
	return []*TestCase{{
		ID:       fmt.Sprintf("%s|%s|auth_bypass", ep.Method, ep.Path),
		Endpoint: ep, Kind: "auth_bypass", Vector: v, TargetIn: "header", Request: rs,
	}}
}

func buildJWTNone(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	if len(ep.Security) == 0 {
		return nil
	}
	rs := base.spec("", "", "")
	rs.JWTNone = true
	return []*TestCase{{
		ID:       fmt.Sprintf("%s|%s|jwt_none", ep.Method, ep.Path),
		Endpoint: ep, Kind: "jwt_none", Vector: v, TargetIn: "header", Request: rs,
	}}
}

func buildMethodTamper(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	var out []*TestCase
	alt := map[string][]string{
		"GET":    {"POST", "PUT", "DELETE"},
		"POST":   {"PUT", "PATCH", "GET"},
		"PUT":    {"PATCH", "POST"},
		"DELETE": {"GET", "POST"},
	}
	for _, m := range alt[ep.Method] {
		rs := base.spec("", "", "")
		rs.Method = m
		tc := &TestCase{
			ID:       fmt.Sprintf("%s|%s|method_tamper|%s", ep.Method, ep.Path, m),
			Endpoint: ep, Kind: "method_tamper", Vector: v, TargetIn: "path",
			Request: rs,
		}
		tc.setMeta("original_method", ep.Method)
		out = append(out, tc)
	}
	return out
}

func buildRateLimit(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	rs := base.spec("", "", "")
	rs.Repeat = 25
	return []*TestCase{{
		ID:       fmt.Sprintf("%s|%s|rate_limit", ep.Method, ep.Path),
		Endpoint: ep, Kind: "rate_limit", Vector: v, TargetIn: "path", Request: rs,
	}}
}

func buildCORS(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	rs := base.spec("", "", "")
	rs.Headers["Origin"] = "https://offat-evil.example"
	return []*TestCase{{
		ID:       fmt.Sprintf("%s|%s|cors", ep.Method, ep.Path),
		Endpoint: ep, Kind: "cors", Vector: v, TargetIn: "header", Request: rs,
	}}
}

func buildDataExposure(ep *spec.Endpoint, base baseVals, v *kb.Vector) []*TestCase {
	// Data exposure is judged on the baseline response, but we emit a dedicated
	// case so it is reported per-endpoint.
	rs := base.spec("", "", "")
	return []*TestCase{{
		ID:       fmt.Sprintf("%s|%s|data_exposure", ep.Method, ep.Path),
		Endpoint: ep, Kind: "data_exposure", Vector: v, TargetIn: "body", Request: rs,
	}}
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func containsFold(list []string, want string) bool {
	if len(list) == 0 {
		return true // empty applicability = matches all
	}
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

var reCache = map[string]*regexp.Regexp{}

func matchesAny(patterns []string, s string) bool {
	for _, p := range patterns {
		re, ok := reCache[p]
		if !ok {
			var err error
			re, err = regexp.Compile(p)
			if err != nil {
				reCache[p] = nil
				continue
			}
			reCache[p] = re
		}
		if re != nil && re.MatchString(s) {
			return true
		}
	}
	return false
}
