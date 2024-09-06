package tgen

import (
	"github.com/dmdhrumilmistry/fasthttpclient/client"
)

// Holds data related for API testing
type ApiTest struct {
	// Fields to be populated before making HTTP request
	TestName       string          `json:"test_name"`
	Request        *client.Request `json:"request"`
	Path           string          `json:"path"`
	PathWithParams string          `json:"path_with_params"`
	MatchRegex     string          `json:"match_regex"` // regex used in post processing for detecting injection

	// Fields to be populated after making HTTP request
	IsVulnerable bool                       `json:"is_vulnerable"`
	IsDataLeak   bool                       `json:"is_data_leak"`
	Response     *client.ConcurrentResponse `json:"concurrent_response"`

	// Post Request Process
	VulnerableResponseCodes []int                  `json:"vulnerable_response_codes"`
	ImmuneResponseCodes     []int                  `json:"immune_response_codes"`
	DataLeakMatches         []DataLeakPatternMatch `json:"data_leak_matches"`
}

type InjectionConfig struct {
	InPath   bool
	InQuery  bool
	InBody   bool
	InHeader bool
	InCookie bool
	Payloads []Payload

	// for vulnerable ssrf endpoint inject endpoint in query param
	// example: https://ssrf-website.com?offat_test_endpoint=/api/v1/users
	InjectUriInQuery bool
}

// Struct used for injecting payloads while generating tests
type Payload struct {
	InjText string // text to be injected

	// Post Processors
	VulnerableResponseCodes []int  // status code indicating API endpoint is vulnerable
	ImmuneResponseCodes     []int  // status code indicating API endpoint is not vulnerable
	Regex                   string // regex to be used for post processing
}

// For Post runner
type DataLeakPattern struct {
	Name       string `json:"name" yaml:"name"`
	Regex      string `json:"regex" yaml:"regex"`
	Confidence string `json:"confidence" yaml:"confidence"`
}

type DataLeakPatterns struct {
	Patterns []DataLeakPattern `json:"patterns" yaml:"patterns"`
}

type DataLeakPatternMatch struct {
	DataLeakPattern

	Matches []string
}
