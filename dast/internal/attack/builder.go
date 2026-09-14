package attack

import (
	"encoding/json"
	"net/url"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/graph"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

// injectionPoint is one place a payload can be written.
type injectionPoint struct {
	in     string // path|query|header|cookie|body
	name   string // param name or top-level body field ("$body" for scalar body)
	schema *spec.Schema
	typ    string
}

// baseVals holds the structured baseline request for an endpoint, from which
// concrete (possibly mutated) RequestSpecs are produced.
type baseVals struct {
	ep          *spec.Endpoint
	path        map[string]any
	query       map[string]any
	header      map[string]any
	cookie      map[string]any
	body        any // map[string]any for objects, or a scalar/string
	bodyIsObj   bool
	contentType string
	seed        map[string]seedHint
}

func typeOf(s *spec.Schema) string {
	if s == nil || s.Type == "" {
		return "string"
	}
	return s.Type
}

// buildBaseline assembles default values for every parameter and the body.
func buildBaseline(ep *spec.Endpoint) baseVals {
	b := baseVals{
		ep:     ep,
		path:   map[string]any{},
		query:  map[string]any{},
		header: map[string]any{},
		cookie: map[string]any{},
		seed:   map[string]seedHint{},
	}
	for _, p := range ep.Params {
		val := sampleValue(p.Schema)
		switch p.In {
		case "path":
			b.path[p.Name] = val
			if graph.IsIdentifier(p.Name, p.Schema) {
				b.seed[p.Name] = seedHint{Key: graph.Key(p.Name), Resource: graph.ResourceForParam(ep.Path, p.Name), In: "path"}
			}
		case "query":
			if p.Required || len(b.query) < 6 {
				b.query[p.Name] = val
				if graph.IsIdentifier(p.Name, p.Schema) {
					b.seed[p.Name] = seedHint{Key: graph.Key(p.Name), Resource: graph.ResourceForParam(ep.Path, p.Name), In: "query"}
				}
			}
		case "header":
			b.header[p.Name] = val
		case "cookie":
			b.cookie[p.Name] = val
		}
	}
	if ep.Body != nil && ep.Body.Schema != nil {
		b.contentType = ep.Body.ContentType
		if b.contentType == "" {
			b.contentType = "application/json"
		}
		if ep.Body.Schema.Type == "object" || ep.Body.Schema.Properties != nil {
			b.body = sampleObject(ep.Body.Schema)
			b.bodyIsObj = true
		} else {
			b.body = sampleValue(ep.Body.Schema)
		}
	}
	return b
}

// points returns every injectable point on the endpoint.
func (b baseVals) points() []injectionPoint {
	var pts []injectionPoint
	for _, p := range b.ep.Params {
		pts = append(pts, injectionPoint{in: p.In, name: p.Name, schema: p.Schema, typ: typeOf(p.Schema)})
	}
	if b.ep.Body != nil && b.ep.Body.Schema != nil {
		if b.bodyIsObj {
			for name, sub := range b.ep.Body.Schema.Properties {
				pts = append(pts, injectionPoint{in: "body", name: name, schema: sub, typ: typeOf(sub)})
			}
		} else {
			pts = append(pts, injectionPoint{in: "body", name: "$body", schema: b.ep.Body.Schema, typ: typeOf(b.ep.Body.Schema)})
		}
	}
	return pts
}

// spec builds a RequestSpec, optionally overriding a single point with value.
func (b baseVals) spec(overrideIn, overrideName string, value string) RequestSpec {
	rs := RequestSpec{
		Method:      b.ep.Method,
		PathParams:  map[string]string{},
		Query:       map[string]string{},
		Headers:     map[string]string{},
		Cookies:     map[string]string{},
		ContentType: b.contentType,
		SeedParams:  map[string]seedHint{},
	}
	for k, v := range b.path {
		rs.PathParams[k] = asStringValue(v)
	}
	for k, v := range b.query {
		rs.Query[k] = asStringValue(v)
	}
	for k, v := range b.header {
		rs.Headers[k] = asStringValue(v)
	}
	for k, v := range b.cookie {
		rs.Cookies[k] = asStringValue(v)
	}
	for k, v := range b.seed {
		rs.SeedParams[k] = v
	}

	bodyVal := b.body
	switch overrideIn {
	case "path":
		rs.PathParams[overrideName] = value
		delete(rs.SeedParams, overrideName) // an injected value must not be reseeded
	case "query":
		rs.Query[overrideName] = value
		delete(rs.SeedParams, overrideName)
	case "header":
		rs.Headers[overrideName] = value
	case "cookie":
		rs.Cookies[overrideName] = value
	case "body":
		bodyVal = overrideBody(b, overrideName, value)
	}
	rs.Body, rs.ContentType = marshalBody(rs.ContentType, bodyVal)
	return rs
}

// overrideBody returns a copy of the baseline body with one field replaced.
func overrideBody(b baseVals, field, value string) any {
	if field == "$body" || !b.bodyIsObj {
		return value
	}
	src, _ := b.body.(map[string]any)
	dst := make(map[string]any, len(src)+1)
	for k, v := range src {
		dst[k] = v
	}
	dst[field] = value
	return dst
}

func marshalBody(contentType string, body any) ([]byte, string) {
	if body == nil {
		return nil, contentType
	}
	if contentType == "application/x-www-form-urlencoded" {
		if m, ok := body.(map[string]any); ok {
			vals := url.Values{}
			for k, v := range m {
				vals.Set(k, asStringValue(v))
			}
			return []byte(vals.Encode()), contentType
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, contentType
	}
	if contentType == "" {
		contentType = "application/json"
	}
	return data, contentType
}
