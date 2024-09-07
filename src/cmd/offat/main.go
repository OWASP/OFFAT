package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/OWASP/OFFAT/src/pkg/http"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/report"
	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/OWASP/OFFAT/src/pkg/trunner"
	"github.com/OWASP/OFFAT/src/pkg/trunner/postrunner"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

const Version = "v0.20.0"

func banner() {
	fmt.Print(`
      _/|       |\_
     /  |       |  \
    |    \     /    |
    |  \ /     \ /  |
    | \  |     |  / |
    | \ _\_/^\_/_ / |
    |    --\//--    |
     \_  \     /  _/
       \__  |  __/
          \ _ /
         _/   \_
        / _/|\_ \
         /  |  \
          / v \
          OFFAT

`)
}

func main() {
	banner()

	// Parse CLI args
	config := FlagConfig{}

	config.Version = flag.Bool("v", false, "print version of OWASP OFFAT binary and exit")

	config.DocPath = flag.String("f", "", "OAS/Swagger Doc file path or URL")
	config.BaseUrl = flag.String("b", "", "base api path url. example: http://localhost:8000/api") // if not provided then parsed from documentation
	config.IsExternalRefsAllowed = flag.Bool("er", false, "enables visiting other files")
	config.DisableExamplesValidation = flag.Bool("de", false, "disable example validation for OAS files")
	config.DisableSchemaDefaultsValidation = flag.Bool("ds", false, "disable schema defaults validation for OAS files")
	config.DisableSchemaPatternValidation = flag.Bool("dp", false, "disable schema patterns validation for OAS files")

	config.PathRegex = flag.String("pr", "", "run tests for paths matching given regex pattern")

	config.SsrfUrl = flag.String("ssrf", "", "injects user defined SSRF url payload in http request components")
	config.DataLeakPatternFile = flag.String("dl", "", "data leak pattern YAML/JSON file url/path. It should be a simple GET request.")

	config.RequestsPerSecond = flag.Int("r", 60, "number of requests per second")
	config.SkipTlsVerification = flag.Bool("ns", false, "disable TLS/SSL Verfication")
	config.Proxy = flag.String("p", "", "specify proxy for capturing requests, supports http and socks urls. example: http://localhost:8080")
	flag.Var(&config.Headers, "H", "HTTP headers in the format key=value")
	flag.Var(&config.QueryParams, "q", "HTTP query parameter in the format key=value")

	config.OutputFilePath = flag.String("o", "output.json", "JSON report output file path. default: output.json")
	config.AvoidImmuneFilter = flag.Bool("ai", true, "does not filter immune endpoint from results if used. usage: -ai=true/false")

	flag.Parse()

	// Start Timer
	now := time.Now()

	if *config.Version {
		log.Info().Msg(Version)
		os.Exit(0)
	}

	if *config.DocPath == "" {
		log.Error().Msg("-f is required. Use --help for more information.")
		os.Exit(1)
	}

	// parse documentation
	parser := parser.NewParser(
		*config.IsExternalRefsAllowed,
		*config.DisableExamplesValidation,
		*config.DisableSchemaDefaultsValidation,
		*config.DisableSchemaPatternValidation,
	)

	if err := parser.Parse(*config.DocPath, utils.ValidateURL(*config.DocPath)); err != nil {
		log.Error().Stack().Err(err).Msg("failed to parse API documentation file")
		os.Exit(1)
	}

	err := parser.Doc.SetBaseUrl(*config.BaseUrl)
	if err != nil {
		log.Error().Err(err).Msg("failed to set baseUrl")
	}

	// set struct DocHttpParams
	if err := parser.Doc.SetDocHttpParams(); err != nil {
		log.Error().Stack().Err(err).Msg("failed while fetching doc http params")
	}

	log.Info().Msg("fuzzing doc http params")
	parser.FuzzDocHttpParams()

	// Create http client and config
	httpCfg := http.NewConfig(config.RequestsPerSecond, config.SkipTlsVerification, config.Proxy)
	hc := http.NewHttp(httpCfg)

	// Test server connectivity
	url := *parser.Doc.GetBaseUrl()
	resp, err := hc.Client.FHClient.Do(url, fasthttp.MethodGet, nil, nil, nil)
	if err != nil {
		log.Error().Stack().Err(err).Msg("cannot connect to server")
		os.Exit(1)
	}

	successCodes := []int{200, 301, 302, 400, 404, 405}
	if !utils.SearchInSlice(successCodes, resp.StatusCode) {
		log.Error().Msgf("server returned %v instead of one of the values %v", resp.StatusCode, successCodes)
	}

	log.Info().Msgf("successfully connected to %v", url)

	// Validate data leak pattern file
	var patterns tgen.DataLeakPatterns
	var contentType string

	if *config.DataLeakPatternFile != "" {
		contentType, err = utils.InferContentTypeByPath(*config.DataLeakPatternFile)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("failed to infer data leak pattern file content type by path: %s", *config.DataLeakPatternFile)
		} else if err := utils.LoadJsonYamlFromFile(*config.DataLeakPatternFile, &patterns, contentType); err != nil {
			log.Error().Stack().Err(err).Msgf("failed to load data leak pattern file by path: %s", *config.DataLeakPatternFile)
		}
	} else {
		log.Warn().Msg("Data leak tests will be skipped due to invalid -dl flag")
	}

	// generate and run tests
	apiTestHandler := tgen.TGenHandler{
		BaseUrl:            url,
		Doc:                parser.Doc.GetDocHttpParams(),
		DefaultHeaders:     config.Headers.ToMap(),
		DefaultQueryParams: config.QueryParams.ToMap(),

		// Tests
		RunUnrestrictedHttpMethodTest:    true,
		RunBasicSQLiTest:                 true,
		RunBasicSSRFTest:                 true,
		RunOsCommandInjectionTest:        true,
		RunXssHtmlInjectionTest:          true,
		RunSstiInjectionTest:             true,
		RunBolaTest:                      true,
		RunBolaTrailingPathTest:          true,
		RunMissingAuthImplementationTest: true,

		// SSRF Test
		SsrfUrl: *config.SsrfUrl,
	}

	// generate api tests
	apiTests := apiTestHandler.GenerateTests()

	// filter api tests
	if *config.PathRegex != "" {
		apiTests = apiTestHandler.FilterTests(apiTests, *config.PathRegex)
	}

	// run api tests
	trunner.RunApiTests(&apiTestHandler, hc, hc.Client.FHClient, apiTests)
	log.Info().Msgf("Total Requests: %d", len(apiTests))

	// **## Run Post Tests processors ##**
	// scan for data leaks before any filtering
	// below function
	if len(patterns.Patterns) > 0 {
		postrunner.UpdateDataLeakResult(&apiTests, patterns)
	}

	// update results based on http status codes
	postrunner.UpdateStatusCodeBasedResult(&apiTests)

	// filter immune api from results
	postrunner.FilterImmuneResults(&apiTests, config.AvoidImmuneFilter)

	// write/print report for api tests
	log.Info().Msgf("Generating and writing report to output file: %v", *config.OutputFilePath)
	reportData, err := report.Report(apiTests, utils.JSON)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate report")
	}

	if err := utils.WriteFile(*config.OutputFilePath, reportData); err != nil {
		log.Error().Stack().Err(err).Msgf("failed to write json output file %v", *config.OutputFilePath)
	}

	log.Info().Msg("Generating Output Table")
	report.Table(apiTests)

	// print elapsed time
	elapsed := time.Since(now)
	log.Info().Msgf("Base URL: %v", url)
	log.Info().Msgf("Overall Time: %v", elapsed)
}

// command:
// go run cmd/offat/
