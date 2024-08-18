package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
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

type FlagConfig struct {
	// OFFAT metadata
	Version *bool

	// Parser config
	Filename                        *string
	DocUrl                          *string
	IsExternalRefsAllowed           *bool
	DisableExamplesValidation       *bool
	DisableSchemaDefaultsValidation *bool
	DisableSchemaPatternValidation  *bool
	BaseUrl                         *string

	// HTTP
	RequestsPerSecond   *int
	SkipTlsVerification *bool
	Headers             KeyValueMap
	QueryParams         KeyValueMap

	// Report
	AvoidImmuneFilter *bool
	OutputFilePath    *string
}

// Custom type for headers
type KeyValueMap map[string]string

// Implement the String method for headers
func (h *KeyValueMap) String() string {
	var keyValueList []string
	for k, v := range *h {
		keyValueList = append(keyValueList, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(keyValueList, ", ")
}

// Implement the Set method for headers
func (h *KeyValueMap) Set(value string) error {
	if *h == nil {
		*h = make(KeyValueMap)
	}

	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid key value format, expected key=value but got %s", value)
	}
	(*h)[parts[0]] = parts[1]
	return nil
}

func (h *KeyValueMap) ToMap() map[string]string {
	return *h
}

func main() {

	// Parse CLI args
	config := FlagConfig{}

	config.Version = flag.Bool("version", false, "print version of OWASP OFFAT binary and exit")

	config.Filename = flag.String("f", "", "OAS/Swagger Doc file path")
	config.DocUrl = flag.String("u", "", "OAS/Swagger Doc URL")
	config.BaseUrl = flag.String("b", "", "base api path url. example: http://localhost:8000/api") // if not provided then parsed from documentation
	config.IsExternalRefsAllowed = flag.Bool("er", false, "enables visiting other files")
	config.DisableExamplesValidation = flag.Bool("de", false, "disable example validation for OAS files")
	config.DisableSchemaDefaultsValidation = flag.Bool("ds", false, "disable schema defaults validation for OAS files")
	config.DisableSchemaPatternValidation = flag.Bool("dp", false, "disable schema patterns validation for OAS files")

	config.RequestsPerSecond = flag.Int("r", 60, "number of requests per second")
	config.SkipTlsVerification = flag.Bool("ns", false, "disable TLS/SSL Verfication")
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
	httpCfg := http.NewConfig(config.RequestsPerSecond, config.SkipTlsVerification)
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
		BaseUrl:            url,
		Doc:                parser.Doc.GetDocHttpParams(),
		DefaultHeaders:     config.Headers.ToMap(),
		DefaultQueryParams: config.QueryParams.ToMap(),

		// Tests
		RunUnrestrictedHttpMethodTest: true,
		RunSimpleSQLiTest:             true,
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
