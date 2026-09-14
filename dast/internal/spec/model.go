// Package spec provides a normalized, version-agnostic model of an OpenAPI /
// Swagger document. It parses both Swagger 2.0 and OpenAPI 3.x into a single
// in-memory representation that the rest of the DAST engine consumes, so the
// downstream graph/attack/engine packages never have to reason about which
// spec version produced an endpoint.
package spec

// API is the normalized description of an entire API surface.
type API struct {
	Title    string
	Version  string
	Servers  []string // fully qualified base URLs, most-preferred first
	Endpoints []*Endpoint
	// Security holds the named security schemes declared by the document.
	Security map[string]*SecurityScheme
	// GlobalSecurity lists scheme names that apply to every operation unless
	// overridden at the operation level.
	GlobalSecurity []string
}

// Endpoint is a single operation (method + path).
type Endpoint struct {
	Method      string // upper-case: GET, POST, ...
	Path        string // templated, e.g. /users/{id}
	OperationID string
	Summary     string
	Tags        []string
	Params      []*Param
	Body        *Body
	Responses   []*Response
	// Security lists the names of security schemes required for this
	// operation. Empty means "inherit GlobalSecurity".
	Security []string
}

// ID returns a stable identifier for the endpoint.
func (e *Endpoint) ID() string { return e.Method + " " + e.Path }

// Param is a single request parameter.
type Param struct {
	Name     string
	In       string // path | query | header | cookie
	Required bool
	Schema   *Schema
	Example  any
}

// Body describes a request body (OAS3 requestBody or Swagger body param).
type Body struct {
	ContentType string
	Required    bool
	Schema      *Schema
}

// Response describes a single documented response.
type Response struct {
	Status      string // e.g. "200", "default"
	Description string
	Schema      *Schema
}

// Schema is a reduced JSON-Schema node covering the subset the engine needs.
type Schema struct {
	Name       string // component name when this schema came from a $ref
	Type       string // object|array|string|integer|number|boolean
	Format     string // int64, uuid, email, date-time, ...
	Properties map[string]*Schema
	Required   []string
	Items      *Schema
	Enum       []any
	Example    any
	// Ref is retained for diagnostics; it is resolved during parsing.
	Ref string
}

// SecurityScheme describes how an operation is authenticated.
type SecurityScheme struct {
	Name      string
	Type      string // apiKey | http | oauth2 | openIdConnect | basic
	In        string // header | query | cookie (apiKey)
	ParamName string // header/query/cookie name for apiKey
	Scheme    string // bearer | basic (http)
}
