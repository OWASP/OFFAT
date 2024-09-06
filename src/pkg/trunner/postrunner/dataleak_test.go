package postrunner_test

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/OWASP/OFFAT/src/pkg/trunner/postrunner"
	"github.com/dmdhrumilmistry/fasthttpclient/client"

	"github.com/dlclark/regexp2"
)

// Mock utility function for FindAllString
var mockFindAllString = func(re *regexp2.Regexp, target string) []string {
	return []string{}
}

// Test cases for UpdateDataLeakResult
func TestUpdateDataLeakResult(t *testing.T) {
	// Setup patterns
	patterns := tgen.DataLeakPatterns{
		Patterns: []tgen.DataLeakPattern{
			{Name: "Test Pattern", Regex: "test", Confidence: "high"},
			{Name: "Test2 Pattern", Regex: "test2", Confidence: "low"},
		},
	}

	apiTests := []*tgen.ApiTest{
		{
			// mock response with an error
			Response: &client.ConcurrentResponse{
				Error: fmt.Errorf("Dummy error"),
			},
		},
		{
			// Mock response body with no data leak
			Response: &client.ConcurrentResponse{
				Response: &client.Response{
					Body: []byte("no match here"),
				},
			},
		},
		// ApiTest with valid data leak
		{
			Response: &client.ConcurrentResponse{
				Response: &client.Response{
					Body: []byte("match here"),
				},
			},
			IsDataLeak: true,
			DataLeakMatches: []tgen.DataLeakPatternMatch{
				{
					Matches: []string{"match here"},
				},
			},
		},
	}

	t.Run("Empty apiTests", func(t *testing.T) {
		// Call the function with empty data
		var emptyApiTests []*tgen.ApiTest
		postrunner.UpdateDataLeakResult(&emptyApiTests, patterns)

		// Ensure that nothing crashes and no data leaks are found
		if len(emptyApiTests) != 0 {
			t.Errorf("Expected no API tests, got %d", len(emptyApiTests))
		}
	})

	t.Run("ApiTest with error in response", func(t *testing.T) {
		postrunner.UpdateDataLeakResult(&apiTests, patterns)

		if apiTests[0].IsDataLeak {
			t.Errorf("Expected no data leak, got IsDataLeak=true")
		}
	})

	t.Run("ApiTest with no error but no data leak", func(t *testing.T) {
		postrunner.UpdateDataLeakResult(&apiTests, patterns)

		if apiTests[1].IsDataLeak {
			t.Errorf("Expected no data leak, got IsDataLeak=true")
		}
	})

	t.Run("ApiTest with valid data leak", func(t *testing.T) {
		postrunner.UpdateDataLeakResult(&apiTests, patterns)

		// Check if IsDataLeak is true
		if !apiTests[2].IsDataLeak {
			t.Errorf("Expected data leak, got IsDataLeak=false")
		}

		// Check if DataLeakMatches is correctly populated
		if len(apiTests[2].DataLeakMatches) == 0 {
			t.Errorf("Expected data leak matches, got none")
		}
	})
}

// Test cases for IsDataLeak
func TestIsDataLeak(t *testing.T) {
	// Setup patterns
	patterns := tgen.DataLeakPatterns{
		Patterns: []tgen.DataLeakPattern{
			{Name: "Test Pattern", Regex: "test", Confidence: "high"},
			{Name: "Sensitive Info", Regex: "password", Confidence: "high"},
		},
	}

	t.Run("No matches", func(t *testing.T) {
		target := []byte("nothing here to match")
		matches := postrunner.IsDataLeak(target, patterns)

		if len(matches) != 0 {
			t.Errorf("Expected no matches, got %d", len(matches))
		}
	})

	t.Run("One match", func(t *testing.T) {
		target := []byte("this is a test")
		matches := postrunner.IsDataLeak(target, patterns)

		if len(matches) != 1 {
			t.Errorf("Expected 1 match, got %d", len(matches))
		}

		if matches[0].DataLeakPattern.Name != "Test Pattern" {
			t.Errorf("Expected pattern 'Test Pattern', got '%s'", matches[0].DataLeakPattern.Name)
		}
	})

	t.Run("Multiple matches", func(t *testing.T) {
		target := []byte("this is a test password")
		matches := postrunner.IsDataLeak(target, patterns)

		if len(matches) != 2 {
			t.Errorf("Expected 2 matches, got %d", len(matches))
		}

		expected := []string{"test", "password"}
		var found []string
		for _, match := range matches {
			found = append(found, match.Matches...)
		}

		// Sort both slices and compare
		sort.Strings(found)
		sort.Strings(expected)

		if !reflect.DeepEqual(found, expected) {
			t.Errorf("Expected matches %v, got %v", expected, found)
		}
	})
}
