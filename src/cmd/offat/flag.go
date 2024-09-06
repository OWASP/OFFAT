package main

import (
	"fmt"
	"strings"
)

type FlagConfig struct {
	// OFFAT metadata
	Version *bool

	// Parser config
	DocPath                         *string
	IsExternalRefsAllowed           *bool
	DisableExamplesValidation       *bool
	DisableSchemaDefaultsValidation *bool
	DisableSchemaPatternValidation  *bool
	BaseUrl                         *string

	// HTTP
	RequestsPerSecond   *int
	SkipTlsVerification *bool
	Headers             KeyValueMap
	QueryParams         KeyValueMap
	Proxy               *string

	// API test filter
	PathRegex *string

	// SSRF Test
	SsrfUrl *string

	// Data Leak Test
	DataLeakPatternFile *string

	// Report
	AvoidImmuneFilter *bool
	OutputFilePath    *string
}

// Custom type for headers
type KeyValueMap map[string]string

// Implement the String method for headers
func (h *KeyValueMap) String() string {
	var keyValueList []string
	for k, v := range *h {
		keyValueList = append(keyValueList, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(keyValueList, ", ")
}

// Implement the Set method for headers
func (h *KeyValueMap) Set(value string) error {
	if *h == nil {
		*h = make(KeyValueMap)
	}

	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid key value format, expected key=value but got %s", value)
	}
	(*h)[parts[0]] = parts[1]
	return nil
}

func (h *KeyValueMap) ToMap() map[string]string {
	return *h
}
