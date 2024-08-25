package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
)

func BasicXssHtmlInjectionTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string, injectionConfig InjectionConfig) []*ApiTest {
	testName := "Basic XSS/HTML Injection Test"

	// TODO: implement injection in both keys and values
	payloads := []Payload{
		{InjText: "<script>confirm(1)</script>", Regex: `<script[^>]*>.*<\/script>`},
		{InjText: "<script>alert(1)</script>", Regex: `<script[^>]*>.*<\/script>`},
		{InjText: "<img src=x onerror='javascript:confirm(1),>", Regex: `<img[^>]*>`},
	}

	injectionConfig.Payloads = payloads

	tests := injectParamIntoApiTest(baseUrl, docParams, queryParams, headers, testName, injectionConfig)

	return tests
}
