package tgen

import (
	"fmt"

	"github.com/OWASP/OFFAT/src/pkg/http"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
)

type TGenHandler struct {
	RunUnrestrictedHttpMethodTest bool

	Doc                []*parser.DocHttpParams
	DefaultQueryParams map[string]string
	DefaultHeaders     map[string]string
}

func (t *TGenHandler) GenerateTests() []*ApiTests {
	tests := []*ApiTests{}
	if t.RunUnrestrictedHttpMethodTest {
		newTests := UnrestrictedHttpMethods(t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Unrestricted HTTP Methods/Verbs", len(newTests))
	}

	return tests
}

func (t *TGenHandler) RunApiTests(hc *http.Http, client c.ClientInterface, apiTests []*ApiTests) {
	// generate requests
	for _, apiTest := range apiTests {
		hc.Requests = append(hc.Requests, apiTest.Request)
	}

	// make requests to the server concurrently
	hc.Responses = c.MakeConcurrentRequests(hc.Requests, client)
	fmt.Print("\n")
}
