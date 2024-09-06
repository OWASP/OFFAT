package trunner

import (
	"fmt"
	"os"
	"sync"

	"github.com/OWASP/OFFAT/src/pkg/http"
	"github.com/OWASP/OFFAT/src/pkg/tgen"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/k0kubun/go-ansi"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/term"
)

// Runs API Tests
func RunApiTests(t *tgen.TGenHandler, hc *http.Http, client c.ClientInterface, apiTests []*tgen.ApiTest) {
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
				BarStart:      "╢|",
				BarEnd:        "|╟",
			},
		),
	)

	for _, apiTest := range apiTests {
		wg.Add(1)
		go func(apiTest *tgen.ApiTest) {
			defer wg.Done()
			defer bar.Add(1)

			resp, err := client.Do(apiTest.Request.Uri, apiTest.Request.Method, apiTest.Request.QueryParams, apiTest.Request.Headers, apiTest.Request.Body)
			apiTest.Response = c.NewConcurrentResponse(resp, err)
		}(apiTest)
	}

	wg.Wait()
	fmt.Println()

}
