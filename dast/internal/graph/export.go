package graph

import "github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"

// Exported wrappers so the attack generator and execution engine can reuse the
// same normalization/resource heuristics used to build the graph.

// Key normalizes a parameter or field name to its match key.
func Key(name string) string { return normalizeKey(name) }

// ResourceOf returns the singular resource a path operates on.
func ResourceOf(path string) string { return resourceOfPath(path) }

// ResourceForParam returns the resource a path/query param identifies.
func ResourceForParam(path, param string) string { return resourceForParam(path, param) }

// IsIdentifier reports whether a name/schema pair is an object identifier.
func IsIdentifier(name string, s *spec.Schema) bool { return looksIdentifierish(name, s) }
