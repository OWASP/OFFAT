package tgen

import (
	"regexp"

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
	RunUnrestrictedHttpMethodTest    bool
	RunBasicSQLiTest                 bool
	RunBasicSSRFTest                 bool
	RunOsCommandInjectionTest        bool
	RunXssHtmlInjectionTest          bool
	RunSstiInjectionTest             bool
	RunBolaTest                      bool
	RunBolaTrailingPathTest          bool
	RunMissingAuthImplementationTest bool

	// SSRF Test related data
	SsrfUrl string
}

func (t *TGenHandler) FilterTests(apiTests []*ApiTest, pathRegex string) []*ApiTest {
	var filteredTests []*ApiTest
	for _, apiTest := range apiTests {
		match, err := regexp.MatchString(pathRegex, apiTest.Path)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to match %v regex with endpoint path %v", pathRegex, apiTest.Path)
			continue
		}

		if match {
			filteredTests = append(filteredTests, apiTest)
		}
	}

	return filteredTests
}

func (t *TGenHandler) GenerateTests() []*ApiTest {
	tests := []*ApiTest{}

	// Unrestricted HTTP Method/Verbs
	if t.RunUnrestrictedHttpMethodTest {
		newTests := UnrestrictedHttpMethods(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Unrestricted HTTP Methods/Verbs", len(newTests))
	}

	// BOLA Test
	if t.RunBolaTest {
		newTests := BolaTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for BOLA", len(newTests))
	}

	// BOLA Trailing Path Test
	if t.RunBolaTest {
		newTests := BolaTrailingPathTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for BOLA Trailing Path", len(newTests))
	}

	// Missing Auth Implementation Test
	if t.RunMissingAuthImplementationTest {
		newTests := MissingAuthTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Missing Auth Implementation", len(newTests))
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

	// Basic OS Command Injection Test
	if t.RunOsCommandInjectionTest {
		injectionConfig := InjectionConfig{
			InBody:   true,
			InCookie: true,
			InHeader: true,
			InPath:   true,
			InQuery:  true,
		}
		newTests := BasicOsCommandInjectionTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders, injectionConfig)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Basic OS Command Injection", len(newTests))
	}

	// Basic XSS/HTML Injection Test
	if t.RunXssHtmlInjectionTest {
		injectionConfig := InjectionConfig{
			InBody:   true,
			InCookie: true,
			InHeader: true,
			InPath:   true,
			InQuery:  true,
		}
		newTests := BasicXssHtmlInjectionTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders, injectionConfig)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Basic XSS/HTML Injection", len(newTests))
	}

	// Basic SSTI Command Injection Test
	if t.RunSstiInjectionTest {
		injectionConfig := InjectionConfig{
			InBody:   true,
			InCookie: true,
			InHeader: true,
			InPath:   true,
			InQuery:  true,
		}
		newTests := BasicSstiInjectionTest(t.BaseUrl, t.Doc, t.DefaultQueryParams, t.DefaultHeaders, injectionConfig)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Basic OS Command Injection", len(newTests))
	}

	// SSRF Test
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
