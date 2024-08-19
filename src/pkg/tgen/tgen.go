package tgen

import (
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/rs/zerolog/log"
)

type TGenHandler struct {
	Doc                []*parser.DocHttpParams
	DefaultQueryParams map[string]string
	DefaultHeaders     map[string]string
	BaseUrl            string

	// Register all tests using bool values below
	RunUnrestrictedHttpMethodTest bool
	RunBasicSQLiTest              bool
	RunBasicSSRFTest              bool

	// SSRF Test related data
	SsrfUrl string
}

func (t *TGenHandler) GenerateTests() []*ApiTest {
	tests := []*ApiTest{}
	if t.RunUnrestrictedHttpMethodTest {
		newTests := UnrestrictedHttpMethods(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Unrestricted HTTP Methods/Verbs", len(newTests))
	}

	// Basic SQLI Test
	if t.RunBasicSQLiTest {
		injectionConfig := InjectionConfig{
			InBody:   true,
			InCookie: true,
			InHeader: true,
			InPath:   true,
			InQuery:  true,
		}
		newTests := BasicSqliTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders, injectionConfig)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Basic SQLI", len(newTests))
	}

	if t.RunBasicSSRFTest && utils.ValidateURL(t.SsrfUrl) {
		injectionConfig := InjectionConfig{
			InBody:   true,
			InCookie: true,
			InHeader: true,
			InPath:   true,
			InQuery:  true,

			InjectUriInQuery: true,
		}
		newTests := BasicSsrfTest(t.SsrfUrl, t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders, injectionConfig)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Basic SSRF", len(newTests))
	}

	return tests
}
