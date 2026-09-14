package attack

import (
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/kb"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

// TestCase is a single concrete request the engine will send, together with
// the metadata needed to detect a hit and to explain it in a report.
type TestCase struct {
	ID       string
	Endpoint *spec.Endpoint

	// Kind is "baseline", "inject", or a structural attack name
	// (bola, bfla, mass_assignment, auth_bypass, jwt_none, method_tamper,
	// rate_limit, cors, data_exposure).
	Kind string

	Vector    *kb.Vector  // nil for baseline
	Payload   *kb.Payload // nil for baseline / structural
	Technique kb.Technique

	TargetParam string // parameter/body field under test
	TargetIn    string // path|query|header|cookie|body

	// BaselineID links an injection case to its clean baseline for
	// boolean/diff detection.
	BaselineID string

	Request RequestSpec

	Meta map[string]string
}

// RequestSpec is a resolved-but-abstract HTTP request. The engine finalizes it
// (base URL, auth injection, graph-seeded identifiers) before sending.
type RequestSpec struct {
	Method      string
	PathParams  map[string]string // {name} -> value
	Query       map[string]string
	Headers     map[string]string
	Cookies     map[string]string
	Body        []byte
	ContentType string

	// OmitAuth tells the engine not to attach configured credentials.
	OmitAuth bool
	// JWTNone tells the engine to re-forge the bearer token with alg=none.
	JWTNone bool
	// SeedParams lists path/query params that should be filled from the
	// runtime value store (graph chaining) when a value is available.
	SeedParams map[string]seedHint
	// Repeat sends the request N times (rate-limit probing).
	Repeat int
}

// seedHint tells the engine how to resolve a chained/identifier value.
type seedHint struct {
	Key      string // normalized name key
	Resource string
	In       string // path|query
	// Foreign requests a value belonging to a *different* object than the one
	// the current principal owns (BOLA probing).
	Foreign bool
}

func (t *TestCase) setMeta(k, v string) {
	if t.Meta == nil {
		t.Meta = map[string]string{}
	}
	t.Meta[k] = v
}
