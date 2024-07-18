package main

import (
	"flag"
	"os"
	"time"

	"github.com/OWASP/OFFAT/src/pkg/http"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/OWASP/OFFAT/src/pkg/trunner"
	"github.com/OWASP/OFFAT/src/pkg/trunner/postrunner"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/OWASP/OFFAT/src/report"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type FlagConfig struct {
	// Parser config
	Filename                        *string
	DocUrl                          *string
	IsExternalRefsAllowed           *bool
	DisableExamplesValidation       *bool
	DisableSchemaDefaultsValidation *bool
	DisableSchemaPatternValidation  *bool
	BaseUrl                         *string

	// HTTP
	RequestsPerSecond  *int
	SkipTlsVerfication *bool

	// Report
	AvoidImmuneFilter *bool
	OutputFilePath    *string
}

func main() {

	// Parse CLI args
	config := FlagConfig{}

	config.Filename = flag.String("f", "", "OAS/Swagger Doc file path")
	config.DocUrl = flag.String("u", "", "OAS/Swagger Doc URL")
	config.BaseUrl = flag.String("b", "", "base api path url. example: http://localhost:8000/api") // if not provided then parsed from documentation
	config.IsExternalRefsAllowed = flag.Bool("er", false, "enables visiting other files")
	config.DisableExamplesValidation = flag.Bool("de", false, "disable example validation for OAS files")
	config.DisableSchemaDefaultsValidation = flag.Bool("ds", false, "disable schema defaults validation for OAS files")
	config.DisableSchemaPatternValidation = flag.Bool("dp", false, "disable schema patterns validation for OAS files")

	config.RequestsPerSecond = flag.Int("r", 60, "number of requests per second")
	config.SkipTlsVerfication = flag.Bool("ns", false, "disable TLS/SSL Verfication")

	config.OutputFilePath = flag.String("o", "output.json", "JSON report output file path. default: output.json")
	config.AvoidImmuneFilter = flag.Bool("ai", true, "does not filter immune endpoint from results if used")

	flag.Parse()

	// Start Timer
	now := time.Now()

	if *config.DocUrl == "" && *config.Filename == "" {
		log.Error().Msg("-f or -u param is required. Use --help for more information.")
		os.Exit(1)
	}

	parserUri := config.Filename
	isUrl := false
	if utils.ValidateURL(*config.DocUrl) {
		parserUri = config.DocUrl
		isUrl = true
	}

	// parse documentation
	parser := parser.NewParser(
		*config.IsExternalRefsAllowed,
		*config.DisableExamplesValidation,
		*config.DisableSchemaDefaultsValidation,
		*config.DisableSchemaPatternValidation,
	)

	if err := parser.Parse(*parserUri, isUrl); err != nil {
		log.Error().Stack().Err(err).Msg("failed to parse API documentation file")
		os.Exit(1)
	}

	err := parser.Doc.SetBaseUrl(*config.BaseUrl)
	if err != nil {
		log.Error().Err(err).Msg("failed to set baseUrl")
	}

	if err := parser.Doc.SetDocHttpParams(); err != nil {
		log.Error().Stack().Err(err).Msg("failed while fetching doc http params")
	}

	log.Info().Msg("fuzzing doc http params")
	parser.FuzzDocHttpParams()
	// log.Info().Msgf("%v", parser.Doc.GetDocHttpParams())

	// http client
	httpCfg := http.NewConfig(config.RequestsPerSecond, config.SkipTlsVerfication)
	hc := http.NewHttp(httpCfg)

	url := *parser.Doc.GetBaseUrl()
	resp, err := hc.Client.FHClient.Do(url, fasthttp.MethodGet, nil, nil, nil)
	if err != nil {
		log.Error().Stack().Err(err).Msg("cannot connect to server")
	}

	successCodes := []int{200, 301, 302, 400, 404, 405}
	if !utils.SearchInSlice(successCodes, resp.StatusCode) {
		log.Fatal().Msgf("server returned %v instead of one of the values %v", resp.StatusCode, successCodes)
	}

	log.Info().Msgf("successfully connected to %v", url)

	// generate and run tests
	apiTestHandler := tgen.TGenHandler{
		Doc: parser.Doc.GetDocHttpParams(),

		// Tests
		RunUnrestrictedHttpMethodTest: true,
	}

	// generate and run api tests
	apiTests := apiTestHandler.GenerateTests()
	trunner.RunApiTests(&apiTestHandler, hc, hc.Client.FHClient, apiTests)
	log.Info().Msgf("Total Requests: %d", len(apiTests))

	// filter immune api from results
	postrunner.FilterImmuneResults(&apiTests, config.AvoidImmuneFilter)

	// write/print report for api tests
	log.Info().Msgf("Generating and writing report to output file: %v", *config.OutputFilePath)
	reportData, err := report.Report(apiTests, report.JSON)
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
