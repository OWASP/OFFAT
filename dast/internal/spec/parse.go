package spec

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFile reads and parses an OpenAPI/Swagger document from disk. Both JSON
// and YAML encodings are accepted (JSON is a subset of YAML).
func LoadFile(path string) (*API, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	return Load(data)
}

// Load parses raw JSON/YAML spec bytes into the normalized API model.
func Load(data []byte) (*API, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("empty spec document")
	}
	p := &parser{doc: doc, expanding: map[string]bool{}}
	switch {
	case asString(doc["openapi"]) != "":
		return p.parseV3()
	case asString(doc["swagger"]) != "":
		return p.parseV2()
	default:
		return nil, fmt.Errorf("unrecognized spec: missing 'openapi' or 'swagger' version field")
	}
}

type parser struct {
	doc       map[string]any
	expanding map[string]bool // ref cycle guard
}

var httpMethods = []string{"get", "post", "put", "patch", "delete", "options", "head"}

// ---------------------------------------------------------------------------
// OpenAPI 3.x
// ---------------------------------------------------------------------------

func (p *parser) parseV3() (*API, error) {
	api := &API{Security: map[string]*SecurityScheme{}}
	if info := asMap(p.doc["info"]); info != nil {
		api.Title = asString(info["title"])
		api.Version = asString(info["version"])
	}
	for _, s := range asSlice(p.doc["servers"]) {
		if m := asMap(s); m != nil {
			if u := asString(m["url"]); u != "" {
				api.Servers = append(api.Servers, u)
			}
		}
	}
	// security schemes
	if comps := asMap(p.doc["components"]); comps != nil {
		for name, raw := range asMap(comps["securitySchemes"]) {
			if sm := asMap(raw); sm != nil {
				api.Security[name] = p.parseSecurityScheme(name, sm)
			}
		}
	}
	api.GlobalSecurity = parseSecurityRequirement(p.doc["security"])

	paths := asMap(p.doc["paths"])
	for path, rawItem := range paths {
		item := asMap(rawItem)
		if item == nil {
			continue
		}
		sharedParams := p.parseParams(asSlice(item["parameters"]), false)
		for _, method := range httpMethods {
			op := asMap(item[method])
			if op == nil {
				continue
			}
			ep := &Endpoint{
				Method:      strings.ToUpper(method),
				Path:        path,
				OperationID: asString(op["operationId"]),
				Summary:     asString(op["summary"]),
			}
			ep.Tags = asStringSlice(op["tags"])
			ep.Params = append(append([]*Param{}, sharedParams...), p.parseParams(asSlice(op["parameters"]), false)...)
			ep.Body = p.parseRequestBodyV3(asMap(op["requestBody"]))
			ep.Responses = p.parseResponses(asMap(op["responses"]))
			ep.Security = flattenSecurityNames(parseSecurityRequirement(op["security"]))
			api.Endpoints = append(api.Endpoints, ep)
		}
	}
	return api, nil
}

func (p *parser) parseRequestBodyV3(rb map[string]any) *Body {
	if rb == nil {
		return nil
	}
	content := asMap(rb["content"])
	if content == nil {
		return nil
	}
	// Prefer JSON, then form, then whatever is first.
	order := []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}
	for _, ct := range order {
		if mt := asMap(content[ct]); mt != nil {
			return &Body{ContentType: ct, Required: asBool(rb["required"]), Schema: p.parseSchema(asMap(mt["schema"]))}
		}
	}
	for ct, mt := range content {
		if m := asMap(mt); m != nil {
			return &Body{ContentType: ct, Required: asBool(rb["required"]), Schema: p.parseSchema(asMap(m["schema"]))}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Swagger 2.0
// ---------------------------------------------------------------------------

func (p *parser) parseV2() (*API, error) {
	api := &API{Security: map[string]*SecurityScheme{}}
	if info := asMap(p.doc["info"]); info != nil {
		api.Title = asString(info["title"])
		api.Version = asString(info["version"])
	}
	host := asString(p.doc["host"])
	basePath := asString(p.doc["basePath"])
	schemes := asStringSlice(p.doc["schemes"])
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	if host != "" {
		for _, sc := range schemes {
			api.Servers = append(api.Servers, sc+"://"+host+basePath)
		}
	}
	for name, raw := range asMap(p.doc["securityDefinitions"]) {
		if sm := asMap(raw); sm != nil {
			api.Security[name] = p.parseSecurityScheme(name, sm)
		}
	}
	api.GlobalSecurity = parseSecurityRequirement(p.doc["security"])

	for path, rawItem := range asMap(p.doc["paths"]) {
		item := asMap(rawItem)
		if item == nil {
			continue
		}
		sharedParams := p.parseParams(asSlice(item["parameters"]), true)
		for _, method := range httpMethods {
			op := asMap(item[method])
			if op == nil {
				continue
			}
			ep := &Endpoint{
				Method:      strings.ToUpper(method),
				Path:        path,
				OperationID: asString(op["operationId"]),
				Summary:     asString(op["summary"]),
				Tags:        asStringSlice(op["tags"]),
			}
			params := append(append([]*Param{}, sharedParams...), p.parseParams(asSlice(op["parameters"]), true)...)
			// In v2 the body/formData live inside parameters; split them out.
			ep.Params, ep.Body = p.splitV2Params(params, asSlice(op["parameters"]), asSlice(item["parameters"]))
			ep.Responses = p.parseResponses(asMap(op["responses"]))
			ep.Security = flattenSecurityNames(parseSecurityRequirement(op["security"]))
			api.Endpoints = append(api.Endpoints, ep)
		}
	}
	return api, nil
}

// splitV2Params separates ordinary params from the special body/formData
// parameters used by Swagger 2.0.
func (p *parser) splitV2Params(_ []*Param, opParams, sharedRaw []any) ([]*Param, *Body) {
	var params []*Param
	var body *Body
	form := map[string]*Schema{}
	var formRequired []string
	handle := func(raws []any) {
		for _, raw := range raws {
			m := asMap(raw)
			if m == nil {
				continue
			}
			if m["$ref"] != nil {
				m = p.deref(asString(m["$ref"]))
			}
			in := asString(m["in"])
			name := asString(m["name"])
			switch in {
			case "body":
				body = &Body{ContentType: "application/json", Required: asBool(m["required"]), Schema: p.parseSchema(asMap(m["schema"]))}
			case "formData":
				form[name] = p.schemaFromInline(m)
				if asBool(m["required"]) {
					formRequired = append(formRequired, name)
				}
			default:
				params = append(params, &Param{
					Name:     name,
					In:       in,
					Required: asBool(m["required"]),
					Schema:   p.schemaFromInline(m),
					Example:  m["example"],
				})
			}
		}
	}
	handle(sharedRaw)
	handle(opParams)
	if body == nil && len(form) > 0 {
		body = &Body{
			ContentType: "application/x-www-form-urlencoded",
			Schema:      &Schema{Type: "object", Properties: form, Required: formRequired},
		}
	}
	return params, body
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func (p *parser) parseParams(raws []any, _ bool) []*Param {
	var out []*Param
	for _, raw := range raws {
		m := asMap(raw)
		if m == nil {
			continue
		}
		if m["$ref"] != nil {
			m = p.deref(asString(m["$ref"]))
		}
		in := asString(m["in"])
		if in == "body" || in == "formData" {
			continue // handled elsewhere for v2
		}
		var sch *Schema
		if s := asMap(m["schema"]); s != nil {
			sch = p.parseSchema(s)
		} else {
			sch = p.schemaFromInline(m)
		}
		out = append(out, &Param{
			Name:     asString(m["name"]),
			In:       in,
			Required: asBool(m["required"]),
			Schema:   sch,
			Example:  m["example"],
		})
	}
	return out
}

func (p *parser) parseResponses(m map[string]any) []*Response {
	var out []*Response
	for status, raw := range m {
		rm := asMap(raw)
		if rm == nil {
			continue
		}
		if rm["$ref"] != nil {
			rm = p.deref(asString(rm["$ref"]))
		}
		r := &Response{Status: status, Description: asString(rm["description"])}
		// OAS3: content.*.schema ; v2: schema
		if content := asMap(rm["content"]); content != nil {
			for _, mt := range content {
				if mm := asMap(mt); mm != nil {
					if s := asMap(mm["schema"]); s != nil {
						r.Schema = p.parseSchema(s)
						break
					}
				}
			}
		} else if s := asMap(rm["schema"]); s != nil {
			r.Schema = p.parseSchema(s)
		}
		out = append(out, r)
	}
	return out
}

// schemaFromInline builds a Schema from a parameter node that carries type
// info inline (Swagger 2.0 non-body params).
func (p *parser) schemaFromInline(m map[string]any) *Schema {
	s := &Schema{
		Type:    asString(m["type"]),
		Format:  asString(m["format"]),
		Example: m["example"],
	}
	if items := asMap(m["items"]); items != nil {
		s.Items = p.schemaFromInline(items)
	}
	if enum := asSlice(m["enum"]); enum != nil {
		s.Enum = enum
	}
	return s
}

// parseSchema resolves $refs and recursively normalizes a schema node, with a
// cycle guard to survive self-referential definitions.
func (p *parser) parseSchema(m map[string]any) *Schema {
	if m == nil {
		return nil
	}
	name := ""
	if ref := asString(m["$ref"]); ref != "" {
		name = refName(ref)
		if p.expanding[ref] {
			// Break the cycle: return a shallow object placeholder.
			return &Schema{Name: name, Type: "object", Ref: ref}
		}
		p.expanding[ref] = true
		defer delete(p.expanding, ref)
		m = p.deref(ref)
		if m == nil {
			return &Schema{Name: name, Type: "object", Ref: ref}
		}
	}
	s := &Schema{
		Name:    name,
		Type:    asString(m["type"]),
		Format:  asString(m["format"]),
		Example: m["example"],
		Ref:     asString(m["$ref"]),
	}
	// allOf/oneOf/anyOf: merge properties best-effort.
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		for _, sub := range asSlice(m[key]) {
			if ss := p.parseSchema(asMap(sub)); ss != nil {
				mergeSchema(s, ss)
			}
		}
	}
	if props := asMap(m["properties"]); props != nil {
		if s.Properties == nil {
			s.Properties = map[string]*Schema{}
		}
		if s.Type == "" {
			s.Type = "object"
		}
		for pname, praw := range props {
			s.Properties[pname] = p.parseSchema(asMap(praw))
		}
	}
	if items := asMap(m["items"]); items != nil {
		s.Items = p.parseSchema(items)
		if s.Type == "" {
			s.Type = "array"
		}
	}
	s.Required = append(s.Required, asStringSlice(m["required"])...)
	if enum := asSlice(m["enum"]); enum != nil {
		s.Enum = enum
	}
	if s.Type == "" && s.Properties != nil {
		s.Type = "object"
	}
	return s
}

func mergeSchema(dst, src *Schema) {
	if dst.Type == "" {
		dst.Type = src.Type
	}
	if src.Properties != nil {
		if dst.Properties == nil {
			dst.Properties = map[string]*Schema{}
		}
		for k, v := range src.Properties {
			dst.Properties[k] = v
		}
	}
	dst.Required = append(dst.Required, src.Required...)
}

func (p *parser) parseSecurityScheme(name string, m map[string]any) *SecurityScheme {
	return &SecurityScheme{
		Name:      name,
		Type:      asString(m["type"]),
		In:        asString(m["in"]),
		ParamName: asString(m["name"]),
		Scheme:    asString(m["scheme"]),
	}
}

// deref navigates a local JSON pointer such as
// "#/components/schemas/User" or "#/definitions/User".
func (p *parser) deref(ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	cur := any(p.doc)
	for _, part := range parts {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m := asMap(cur)
		if m == nil {
			return nil
		}
		cur = m[part]
	}
	return asMap(cur)
}

func refName(ref string) string {
	i := strings.LastIndex(ref, "/")
	if i < 0 {
		return ref
	}
	return ref[i+1:]
}

// parseSecurityRequirement returns, for each requirement object, the list of
// scheme names it references.
func parseSecurityRequirement(raw any) []string {
	var names []string
	for _, req := range asSlice(raw) {
		for name := range asMap(req) {
			names = append(names, name)
		}
	}
	return names
}

func flattenSecurityNames(names []string) []string { return names }
