package tgen

import (
	"github.com/dmdhrumilmistry/fasthttpclient/client"
)

// Holds data related for API testing
type ApiTest struct {
	// Fields to be populated before making HTTP request
	TestName string          `json:"test_name"`
	Request  *client.Request `json:"request"`

	// Fields to be populated after making HTTP request
	IsVulnerable bool                       `json:"is_vulnerable"`
	IsDataLeak   bool                       `json:"is_data_leak"`
	Response     *client.ConcurrentResponse `json:"response"`
}
