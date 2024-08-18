package tgen

import "github.com/OWASP/OFFAT/src/pkg/parser"

// generates very basic SSRF API tests by injecting provided URL
func BasicSsrfTest(ssrfUrl, baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string, injectionConfig InjectionConfig) []*ApiTest {
	testName := "Basic SSRF Test"
	vulnResponseCodes := []int{500}
	immuneResponseCodes := []int{}
	payloads := []string{ssrfUrl}

	injectionConfig.Payloads = payloads

	tests := injectParamIntoApiTest(baseUrl, docParams, queryParams, headers, testName, vulnResponseCodes, immuneResponseCodes, injectionConfig)

	return tests
}
