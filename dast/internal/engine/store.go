package engine

import (
	"encoding/json"
	"strconv"
	"sync"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/graph"
)

// valueStore accumulates identifier-like values observed in responses so they
// can be replayed into later requests (dataflow chaining). It is safe for
// concurrent use.
type valueStore struct {
	mu       sync.RWMutex
	byKey    map[string][]string // normalized field name -> distinct values
	byResrc  map[string][]string // resource -> distinct values
}

func newValueStore() *valueStore {
	return &valueStore{byKey: map[string][]string{}, byResrc: map[string][]string{}}
}

func (s *valueStore) addDistinct(m map[string][]string, key, val string) {
	if key == "" || val == "" {
		return
	}
	for _, v := range m[key] {
		if v == val {
			return
		}
	}
	if len(m[key]) < 8 {
		m[key] = append(m[key], val)
	}
}

// harvest walks a JSON response body and records identifier-like fields.
func (s *valueStore) harvest(body []byte, resource string) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.walk(v, resource, 0)
}

func (s *valueStore) walk(v any, resource string, depth int) {
	if depth > 4 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isScalar(val) && graph.IsIdentifier(k, nil) {
				str := scalarString(val)
				s.addDistinct(s.byKey, graph.Key(k), str)
				if resource != "" {
					s.addDistinct(s.byResrc, resource, str)
				}
			}
			s.walk(val, resource, depth+1)
		}
	case []any:
		for _, e := range t {
			s.walk(e, resource, depth+1)
		}
	}
}

// lookup returns a usable value for a seed key/resource. When foreign is true it
// prefers a value distinct from the first-seen (owned) one, enabling BOLA tests.
func (s *valueStore) lookup(key, resource string, foreign bool) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pick := func(vals []string) (string, bool) {
		if len(vals) == 0 {
			return "", false
		}
		if foreign && len(vals) > 1 {
			return vals[1], true
		}
		return vals[0], true
	}
	if v, ok := pick(s.byKey[key]); ok {
		return v, true
	}
	if v, ok := pick(s.byResrc[resource]); ok {
		return v, true
	}
	return "", false
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, float64, int, int64, bool:
		return true
	}
	return false
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// JSON numbers decode as float64; render integers without a point.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
