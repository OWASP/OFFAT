package utils

import (
	"net/url"
)

// ValidateURL checks if the provided URL is valid.
// Note it doesn't make request to the server.
func ValidateURL(u string) bool {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return false
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return false
	}
	return true
}
