package spec

import "testing"

const oas3 = `
openapi: 3.0.0
info: { title: T, version: "1" }
servers: [{ url: "https://api.example.com/v1" }]
paths:
  /users/{id}:
    get:
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
        - { name: verbose, in: query, schema: { type: boolean } }
      responses:
        "200":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/User" }
  /users:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/User" }
      responses: { "201": { description: ok } }
components:
  schemas:
    User:
      type: object
      required: [email]
      properties:
        id: { type: string, format: uuid }
        email: { type: string }
`

func TestParseV3(t *testing.T) {
	api, err := Load([]byte(oas3))
	if err != nil {
		t.Fatal(err)
	}
	if len(api.Endpoints) != 2 {
		t.Fatalf("want 2 endpoints, got %d", len(api.Endpoints))
	}
	if len(api.Servers) != 1 || api.Servers[0] != "https://api.example.com/v1" {
		t.Fatalf("bad servers: %v", api.Servers)
	}
	var post *Endpoint
	for _, e := range api.Endpoints {
		if e.Method == "POST" {
			post = e
		}
	}
	if post == nil || post.Body == nil || post.Body.Schema == nil {
		t.Fatal("POST body not parsed")
	}
	if post.Body.Schema.Properties["email"] == nil {
		t.Fatal("ref not resolved for body schema")
	}
}

const swagger2 = `
swagger: "2.0"
info: { title: T, version: "1" }
host: api.example.com
basePath: /v2
schemes: [https]
paths:
  /pets:
    post:
      parameters:
        - name: body
          in: body
          required: true
          schema: { $ref: "#/definitions/Pet" }
        - { name: q, in: query, type: string }
      responses: { "200": { description: ok } }
definitions:
  Pet:
    type: object
    properties:
      id: { type: integer }
      name: { type: string }
`

func TestParseV2(t *testing.T) {
	api, err := Load([]byte(swagger2))
	if err != nil {
		t.Fatal(err)
	}
	if len(api.Servers) != 1 || api.Servers[0] != "https://api.example.com/v2" {
		t.Fatalf("bad servers: %v", api.Servers)
	}
	ep := api.Endpoints[0]
	if ep.Body == nil || ep.Body.Schema.Properties["name"] == nil {
		t.Fatal("v2 body param not split/resolved")
	}
	var haveQ bool
	for _, p := range ep.Params {
		if p.Name == "q" && p.In == "query" {
			haveQ = true
		}
	}
	if !haveQ {
		t.Fatal("v2 query param missing")
	}
}
