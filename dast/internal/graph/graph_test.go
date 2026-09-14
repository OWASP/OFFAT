package graph

import (
	"testing"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
)

func TestBuildLinksProducerToConsumer(t *testing.T) {
	api := &spec.API{
		Endpoints: []*spec.Endpoint{
			{
				Method: "POST", Path: "/users",
				Responses: []*spec.Response{{Status: "201", Schema: &spec.Schema{
					Type: "object", Properties: map[string]*spec.Schema{"id": {Type: "string"}},
				}}},
			},
			{
				Method: "GET", Path: "/users/{id}",
				Params: []*spec.Param{{Name: "id", In: "path", Schema: &spec.Schema{Type: "string"}}},
			},
		},
	}
	g := Build(api)
	if len(g.Edges) == 0 {
		t.Fatal("expected at least one dataflow edge")
	}
	e := g.Edges[0]
	if e.From.Endpoint.Method != "POST" || e.To.Endpoint.Method != "GET" {
		t.Fatalf("unexpected edge direction: %s -> %s", e.From.Endpoint.ID(), e.To.Endpoint.ID())
	}
	if e.Confidence < 0.5 {
		t.Fatalf("low confidence edge: %.2f", e.Confidence)
	}
}

func TestResourceHeuristics(t *testing.T) {
	cases := map[string]string{
		"/api/v1/users/{id}":             "user",
		"/users/{userId}/posts/{postId}": "post",
		"/categories":                    "category",
	}
	for path, want := range cases {
		if got := resourceOfPath(path); got != want {
			t.Errorf("resourceOfPath(%q)=%q want %q", path, got, want)
		}
	}
	if got := resourceForParam("/users/{userId}/posts/{postId}", "userId"); got != "user" {
		t.Errorf("resourceForParam userId = %q want user", got)
	}
}

func TestNormalizeKey(t *testing.T) {
	for _, in := range []string{"user_id", "userId", "User-ID", "user.id"} {
		if got := normalizeKey(in); got != "userid" {
			t.Errorf("normalizeKey(%q)=%q", in, got)
		}
	}
}
