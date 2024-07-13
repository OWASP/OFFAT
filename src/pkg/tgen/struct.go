package tgen

import "github.com/dmdhrumilmistry/fasthttpclient/client"

// Holds data related for API testing
type ApiTests struct {
	// Fields to be populated before making HTTP request
	TestName string
	Request  *client.Request

	// Fields to be populated after making HTTP request
	IsVulnerable bool
	IsDataLeak   bool
	Response     *client.Response
}
