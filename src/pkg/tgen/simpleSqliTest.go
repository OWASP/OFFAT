package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
)

// generates very basic sqli API tests
func SimpleSQLiTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string) []*ApiTest {
	testName := "Basic SQLI Test"
	vulnResponseCodes := []int{500}
	immuneResponseCodes := []int{}
	payloads := []string{
		"' OR 1=1 ;--",
		"' UNION SELECT 1,2,3 -- -",
		"' OR '1'='1--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
		"' AND SLEEP(5) --",
	}

	tests := injectParamIntoApiTest(baseUrl, docParams, queryParams, headers, testName, vulnResponseCodes, immuneResponseCodes, payloads)

	return tests
}
