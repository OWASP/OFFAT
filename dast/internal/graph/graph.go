// Package graph builds a parameter/dataflow graph across an API surface.
//
// The graph answers two questions the DAST engine needs:
//
//  1. Which endpoints *produce* values (e.g. POST /users returns an "id") and
//     which endpoints *consume* them (e.g. GET /users/{id})? Linking these lets
//     the engine seed real, valid identifiers so requests reach business logic
//     instead of bouncing off 404s — a prerequisite for meaningful testing.
//
//  2. What is a reasonable execution order so producers run before consumers?
//
// The links are also what make BOLA/IDOR testing possible: once we know
// endpoint X consumes an object id produced by endpoint Y, we can swap in an id
// belonging to a different object and watch for unauthorized access.
package graph

import (
	"sort"
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

// Graph is the resolved dataflow graph for an API.
type Graph struct {
	Producers []*Producer
	Consumers []*Consumer
	Edges     []*Edge
	// Order is a producer-before-consumer ordering of endpoints.
	Order []*spec.Endpoint
}

// Producer is a value emitted in an endpoint response (or implied by a create).
type Producer struct {
	Endpoint *spec.Endpoint
	Field    string // JSON field name, e.g. "id"
	Key      string // normalized match key
	Type     string
	Resource string // resource the producing endpoint operates on
}

// Consumer is a request input that expects an externally-produced value.
type Consumer struct {
	Endpoint  *spec.Endpoint
	Param     *spec.Param // set for path/query/header/cookie inputs
	BodyField string      // set for top-level request-body object fields
	Key       string      // normalized match key
	Type      string
	Resource  string // resource the consumer refers to (for id-style inputs)
}

// Name returns a human label for the consumer input.
func (c *Consumer) Name() string {
	if c.Param != nil {
		return c.Param.Name
	}
	return c.BodyField
}

// Edge links a producer to a consumer that likely accepts its value.
type Edge struct {
	From       *Producer
	To         *Consumer
	Confidence float64
	Reason     string
}

// Build constructs the dataflow graph from a parsed API.
func Build(api *spec.API) *Graph {
	g := &Graph{}
	for _, ep := range api.Endpoints {
		g.collectProducers(ep)
		g.collectConsumers(ep)
	}
	g.link()
	g.order(api)
	return g
}

func (g *Graph) collectProducers(ep *spec.Endpoint) {
	resource := resourceOfPath(ep.Path)
	seen := map[string]bool{}
	add := func(field, typ string) {
		key := normalizeKey(field)
		if key == "" || seen[field] {
			return
		}
		seen[field] = true
		g.Producers = append(g.Producers, &Producer{
			Endpoint: ep, Field: field, Key: key, Type: typ, Resource: resource,
		})
	}
	for _, resp := range ep.Responses {
		if !isSuccess(resp.Status) || resp.Schema == nil {
			continue
		}
		for name, sub := range topProperties(resp.Schema) {
			if looksIdentifierish(name, sub) {
				add(name, schemaType(sub))
			}
		}
	}
	// A create/replace on a collection implicitly produces an id for the
	// resource even when the response body is undocumented.
	if (ep.Method == "POST" || ep.Method == "PUT") && resource != "" {
		add(resource+"Id", "string")
		add("id", "string")
	}
}

func (g *Graph) collectConsumers(ep *spec.Endpoint) {
	for _, p := range ep.Params {
		if p.In != "path" && p.In != "query" {
			continue
		}
		if !looksIdentifierish(p.Name, p.Schema) {
			continue
		}
		g.Consumers = append(g.Consumers, &Consumer{
			Endpoint: ep, Param: p, Key: normalizeKey(p.Name),
			Type: schemaType(p.Schema), Resource: resourceForParam(ep.Path, p.Name),
		})
	}
	if ep.Body != nil && ep.Body.Schema != nil {
		for name, sub := range topProperties(ep.Body.Schema) {
			if looksIdentifierish(name, sub) {
				g.Consumers = append(g.Consumers, &Consumer{
					Endpoint: ep, BodyField: name, Key: normalizeKey(name),
					Type: schemaType(sub), Resource: singular(strings.TrimSuffix(normalizeKey(name), "id")),
				})
			}
		}
	}
}

func (g *Graph) link() {
	for _, c := range g.Consumers {
		var best *Edge
		for _, p := range g.Producers {
			if p.Endpoint == c.Endpoint {
				continue // don't link an endpoint to itself
			}
			conf, reason := score(p, c)
			if conf <= 0 {
				continue
			}
			if best == nil || conf > best.Confidence {
				best = &Edge{From: p, To: c, Confidence: conf, Reason: reason}
			}
		}
		if best != nil {
			g.Edges = append(g.Edges, best)
		}
	}
}

// score rates how likely a producer feeds a consumer.
func score(p *Producer, c *Consumer) (float64, string) {
	switch {
	case p.Key == c.Key && p.Key != "":
		return 0.95, "exact name match: " + p.Key
	case c.Resource != "" && c.Resource == p.Resource:
		// e.g. GET /users/{id} consuming the id produced by POST /users
		return 0.8, "resource match: " + c.Resource
	case p.Key == "id" && c.Resource != "" && strings.Contains(p.Resource, c.Resource):
		return 0.6, "generic id under resource: " + c.Resource
	}
	return 0, ""
}

// order produces a producer-before-consumer ordering. Endpoints that mutate
// (POST/PUT/PATCH) sort ahead of readers/deleters so seed values exist.
func (g *Graph) order(api *spec.API) {
	eps := append([]*spec.Endpoint{}, api.Endpoints...)
	rank := map[string]int{"POST": 0, "PUT": 1, "PATCH": 2, "GET": 3, "HEAD": 3, "OPTIONS": 4, "DELETE": 5}
	sort.SliceStable(eps, func(i, j int) bool {
		ri, rj := rank[eps[i].Method], rank[eps[j].Method]
		if ri != rj {
			return ri < rj
		}
		// Shorter (collection) paths before longer (item) paths.
		return len(eps[i].Path) < len(eps[j].Path)
	})
	g.Order = eps
}

// EdgesFor returns edges whose consumer belongs to the given endpoint.
func (g *Graph) EdgesFor(ep *spec.Endpoint) []*Edge {
	var out []*Edge
	for _, e := range g.Edges {
		if e.To.Endpoint == ep {
			out = append(out, e)
		}
	}
	return out
}
