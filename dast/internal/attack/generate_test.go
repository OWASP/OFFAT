package attack

import (
	"strings"
	"testing"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/graph"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/kb"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

func testAPI() *spec.API {
	return &spec.API{
		Endpoints: []*spec.Endpoint{
			{
				Method: "GET", Path: "/search",
				Params: []*spec.Param{{Name: "q", In: "query", Schema: &spec.Schema{Type: "string"}}},
			},
			{
				Method: "POST", Path: "/users", Security: []string{"bearer"},
				Body: &spec.Body{ContentType: "application/json", Schema: &spec.Schema{
					Type: "object", Properties: map[string]*spec.Schema{"email": {Type: "string"}},
				}},
			},
		},
	}
}

func TestGenerateProducesBaselineAndInjections(t *testing.T) {
	api := testAPI()
	g := graph.Build(api)
	k, err := kb.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	cases := Generate(api, g, k, Options{})
	var baseline, inject, structural int
	sawSQLiOnQ := false
	for _, c := range cases {
		switch c.Kind {
		case "baseline":
			baseline++
		case "inject":
			inject++
			if c.Vector.Class == "sqli" && c.TargetParam == "q" {
				sawSQLiOnQ = true
			}
		default:
			structural++
		}
	}
	if baseline != 2 {
		t.Errorf("want 2 baselines, got %d", baseline)
	}
	if inject == 0 {
		t.Error("no injection cases generated")
	}
	if structural == 0 {
		t.Error("no structural cases generated")
	}
	if !sawSQLiOnQ {
		t.Error("expected SQLi injection on query param q")
	}
}

func TestMassAssignmentInjectsSensitiveFields(t *testing.T) {
	api := testAPI()
	g := graph.Build(api)
	k, _ := kb.LoadDefault()
	cases := Generate(api, g, k, Options{})
	var found bool
	for _, c := range cases {
		if c.Kind == "mass_assignment" {
			found = true
			if !strings.Contains(string(c.Request.Body), "role") {
				t.Errorf("mass assignment body missing role: %s", c.Request.Body)
			}
		}
	}
	if !found {
		t.Error("no mass_assignment case for POST body endpoint")
	}
}

func TestAppliesRespectsLocationAndType(t *testing.T) {
	v := &kb.Vector{AppliesTo: kb.Applicability{Locations: []string{"query"}, Types: []string{"string"}}}
	ep := &spec.Endpoint{Method: "GET", Path: "/x"}
	if !applies(v, ep, injectionPoint{in: "query", typ: "string"}) {
		t.Error("should apply to query/string")
	}
	if applies(v, ep, injectionPoint{in: "path", typ: "string"}) {
		t.Error("should not apply to path")
	}
}
