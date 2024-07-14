package tgen

import (
	"fmt"
	"os"
	"sync"

	"github.com/k0kubun/go-ansi"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/term"

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

func (t *TGenHandler) GenerateTests() []*ApiTest {
	tests := []*ApiTest{}
	if t.RunUnrestrictedHttpMethodTest {
		newTests := UnrestrictedHttpMethods(t.Doc, t.DefaultQueryParams, t.DefaultHeaders)
		tests = append(tests, newTests...)

		log.Info().Msgf("%d tests generated for Unrestricted HTTP Methods/Verbs", len(newTests))
	}

	return tests
}

func (t *TGenHandler) RunApiTests(hc *http.Http, client c.ClientInterface, apiTests []*ApiTest) {
	var wg sync.WaitGroup

	// Get the terminal size
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		width = 80 // Default width
	}

	// Adjust the progress bar width based on terminal size
	barWidth := width - 40 // Subtract 40 to account for other UI elements

	bar := progressbar.NewOptions(
		len(apiTests),
		progressbar.OptionSetWriter(ansi.NewAnsiStdout()),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetWidth(barWidth),
		progressbar.OptionSetTheme(
			progressbar.Theme{
				Saucer:        "[green]█[reset]",
				SaucerHead:    "[green]▓[reset]",
				SaucerPadding: "░",
				BarStart:      "╢",
				BarEnd:        "╟",
			},
		),
	)

	for _, apiTest := range apiTests {
		wg.Add(1)
		go func(apiTest *ApiTest) {
			defer wg.Done()
			defer bar.Add(1)

			resp, err := client.Do(apiTest.Request.Uri, apiTest.Request.Method, apiTest.Request.QueryParams, apiTest.Request.Headers, apiTest.Request.Body)
			apiTest.Response = c.NewConcurrentResponse(resp, err)
		}(apiTest)
	}

	wg.Wait()
	fmt.Println()
}
