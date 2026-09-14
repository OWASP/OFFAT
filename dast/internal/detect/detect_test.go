package detect

import (
	"testing"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/attack"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/engine"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/kb"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

func TestDetectErrorBasedSQLi(t *testing.T) {
	ep := &spec.Endpoint{Method: "GET", Path: "/search"}
	v := &kb.Vector{
		ID: "sqli-error", Class: "sqli", Title: "SQLi", Severity: "high",
		Detection: kb.Detection{ErrorSignatures: []string{"you have an error in your sql syntax"}},
	}
	baseID := "GET|/search|baseline"
	base := &engine.Result{
		Case:       &attack.TestCase{ID: baseID, Endpoint: ep, Kind: "baseline"},
		StatusCode: 200, Body: []byte(`{"ok":true}`),
	}
	inj := &engine.Result{
		Case: &attack.TestCase{
			ID: "c1", Endpoint: ep, Kind: "inject", Vector: v, Technique: kb.TechError,
			TargetParam: "q", TargetIn: "query", BaselineID: baseID,
			Payload: &kb.Payload{Value: "'"}, Meta: map[string]string{"payload": "'"},
		},
		StatusCode: 500, Body: []byte("You have an error in your SQL syntax near '''"),
	}
	findings := Detect([]*engine.Result{base, inj})
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Class != "sqli" || findings[0].Confidence < 0.8 {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestErrorSignatureSuppressedWhenInBaseline(t *testing.T) {
	ep := &spec.Endpoint{Method: "GET", Path: "/search"}
	v := &kb.Vector{ID: "sqli-error", Class: "sqli", Severity: "high",
		Detection: kb.Detection{ErrorSignatures: []string{"sql syntax"}}}
	baseID := "b"
	base := &engine.Result{Case: &attack.TestCase{ID: baseID, Endpoint: ep, Kind: "baseline"},
		StatusCode: 200, Body: []byte("sql syntax help page")}
	inj := &engine.Result{Case: &attack.TestCase{ID: "c", Endpoint: ep, Kind: "inject", Vector: v,
		Technique: kb.TechError, BaselineID: baseID, Meta: map[string]string{}},
		StatusCode: 200, Body: []byte("sql syntax help page")}
	if got := Detect([]*engine.Result{base, inj}); len(got) != 0 {
		t.Fatalf("expected suppression, got %d findings", len(got))
	}
}

func TestDetectDataExposure(t *testing.T) {
	ep := &spec.Endpoint{Method: "GET", Path: "/users/{id}"}
	v := &kb.Vector{ID: "excessive-data-exposure", Class: "data_exposure", Severity: "medium"}
	r := &engine.Result{
		Case:       &attack.TestCase{ID: "d", Endpoint: ep, Kind: "data_exposure", Vector: v, Request: attack.RequestSpec{Method: "GET"}},
		StatusCode: 200, Body: []byte(`{"id":"1","password":"x","email":"a@b.c"}`),
	}
	findings := Detect([]*engine.Result{r})
	if len(findings) != 1 || findings[0].Class != "data_exposure" {
		t.Fatalf("expected data_exposure finding, got %+v", findings)
	}
}
