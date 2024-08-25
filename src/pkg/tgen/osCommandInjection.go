package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
)

func BasicOsCommandInjectionTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string, injectionConfig InjectionConfig) []*ApiTest {
	testName := "Basic OS Command Injection Test"

	// TODO: implement injection in both keys and values
	payloads := []Payload{
		{InjText: "cat /etc/passwd", Regex: "root:.*"},
		{InjText: "cat /etc/shadow", Regex: "root:.*"},
		{InjText: "ls -la", Regex: "total\\s\\d+"},
	}

	injectionConfig.Payloads = payloads

	tests := injectParamIntoApiTest(baseUrl, docParams, queryParams, headers, testName, injectionConfig)

	return tests
}
