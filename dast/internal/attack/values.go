package attack

import (
	"fmt"
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

// sampleValue synthesizes a plausible default value for a schema, used to make
// baseline requests reach real business logic. It honors examples, enums and
// common string formats.
func sampleValue(s *spec.Schema) any {
	if s == nil {
		return "offat"
	}
	if s.Example != nil {
		return s.Example
	}
	if len(s.Enum) > 0 {
		return s.Enum[0]
	}
	switch s.Type {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{sampleValue(s.Items)}
	case "object":
		return sampleObject(s)
	default: // string / unknown
		return sampleString(s.Format)
	}
}

func sampleString(format string) string {
	switch strings.ToLower(format) {
	case "email":
		return "offat@example.com"
	case "uuid", "guid":
		return "11111111-1111-4111-8111-111111111111"
	case "date":
		return "2024-01-01"
	case "date-time":
		return "2024-01-01T00:00:00Z"
	case "uri", "url":
		return "https://example.com"
	case "hostname":
		return "example.com"
	case "ipv4":
		return "127.0.0.1"
	case "password":
		return "Offat!Passw0rd"
	case "byte":
		return "b2ZmYXQ="
	default:
		return "offat"
	}
}

func sampleObject(s *spec.Schema) map[string]any {
	obj := map[string]any{}
	if s == nil {
		return obj
	}
	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}
	for name, sub := range s.Properties {
		// Always include required fields; include a bounded number of optional
		// ones so the body is realistic without exploding in size.
		if required[name] || len(obj) < 12 {
			obj[name] = sampleValue(sub)
		}
	}
	return obj
}

// asStringValue renders a sampled value for use in a URL path/query segment.
func asStringValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
