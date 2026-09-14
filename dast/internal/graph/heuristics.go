package graph

import (
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

// normalizeKey lowercases and strips separators so "user_id", "userId" and
// "UserID" all collapse to "userid".
func normalizeKey(s string) string {
	s = strings.ToLower(s)
	repl := strings.NewReplacer("_", "", "-", "", " ", "", ".", "")
	return repl.Replace(s)
}

// looksIdentifierish reports whether a name/schema pair is plausibly an object
// identifier that could be chained between endpoints.
func looksIdentifierish(name string, s *spec.Schema) bool {
	k := normalizeKey(name)
	if k == "" {
		return false
	}
	if k == "id" || strings.HasSuffix(k, "id") || strings.Contains(k, "uuid") || strings.Contains(k, "guid") {
		return true
	}
	// UUID-formatted fields regardless of name.
	if s != nil && (s.Format == "uuid" || s.Format == "guid") {
		return true
	}
	return false
}

func schemaType(s *spec.Schema) string {
	if s == nil || s.Type == "" {
		return "string"
	}
	return s.Type
}

func isSuccess(status string) bool {
	return strings.HasPrefix(status, "2")
}

// topProperties returns the effective top-level properties of a response or
// body schema, transparently unwrapping array item schemas and common
// envelope fields ("data", "result", "item").
func topProperties(s *spec.Schema) map[string]*spec.Schema {
	out := map[string]*spec.Schema{}
	if s == nil {
		return out
	}
	collect := func(sc *spec.Schema) {
		if sc == nil {
			return
		}
		for k, v := range sc.Properties {
			out[k] = v
		}
	}
	collect(s)
	if s.Items != nil {
		collect(s.Items)
	}
	for _, env := range []string{"data", "result", "results", "item", "items"} {
		if sub, ok := s.Properties[env]; ok {
			collect(sub)
			if sub.Items != nil {
				collect(sub.Items)
			}
		}
	}
	return out
}

// resourceOfPath extracts the (singular) resource a path operates on, ignoring
// version and "api" prefixes. "/api/v1/users/{id}" -> "user".
func resourceOfPath(path string) string {
	segs := pathSegments(path)
	for i := len(segs) - 1; i >= 0; i-- {
		if isTemplate(segs[i]) {
			continue
		}
		if isNoise(segs[i]) {
			continue
		}
		return singular(segs[i])
	}
	return ""
}

// resourceForParam finds the resource a specific path/query param identifies:
// the collection segment immediately preceding its template, else the param
// name with a trailing "id" stripped.
func resourceForParam(path, param string) string {
	segs := pathSegments(path)
	target := "{" + param + "}"
	for i, s := range segs {
		if s == target && i > 0 {
			return singular(segs[i-1])
		}
	}
	k := normalizeKey(param)
	if k != "id" && strings.HasSuffix(k, "id") {
		return singular(strings.TrimSuffix(k, "id"))
	}
	return resourceOfPath(path)
}

func pathSegments(path string) []string {
	var out []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isTemplate(s string) bool { return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") }

func isNoise(s string) bool {
	l := strings.ToLower(s)
	if l == "api" || l == "rest" || l == "v" {
		return true
	}
	// version segments like v1, v2, v10, or 2023-01-01
	if len(l) >= 2 && l[0] == 'v' {
		allDigits := true
		for _, c := range l[1:] {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}

// singular is a small, deliberately naive English singularizer good enough for
// resource-name matching.
func singular(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.HasSuffix(l, "ies") && len(l) > 3:
		return l[:len(l)-3] + "y"
	case strings.HasSuffix(l, "ses") && len(l) > 3:
		return l[:len(l)-2]
	case strings.HasSuffix(l, "s") && !strings.HasSuffix(l, "ss") && len(l) > 1:
		return l[:len(l)-1]
	}
	return l
}
