package tgen

import (
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/rs/zerolog/log"
)

type TGenHandler struct {
	RunUnrestrictedHttpMethodTest bool
	RunSimpleSQLiTest             bool

	Doc                []*parser.DocHttpParams
	DefaultQueryParams map[string]string
	DefaultHeaders     map[string]string
	BaseUrl            string
}

func (t *TGenHandler) GenerateTests() []*ApiTest {
	tests := []*ApiTest{}
	if t.RunUnrestrictedHttpMethodTest {
		newTests := UnrestrictedHttpMethods(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Unrestricted HTTP Methods/Verbs", len(newTests))
	}

	if t.RunSimpleSQLiTest {
		injectionConfig := InjectionConfig{
			InBody:   true,
			InCookie: true,
			InHeader: false,
			InPath:   true,
			InQuery:  true,
		}
		newTests := SimpleSQLiTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders, injectionConfig)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Simple SQLI", len(newTests))
	}

	return tests
}
