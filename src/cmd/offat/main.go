package main

import (
	"flag"
	"os"
	"time"

	"github.com/OWASP/OFFAT/src/pkg/http"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/OWASP/OFFAT/src/report"
	"github.com/rs/zerolog/log"
)

type CliConfig struct {
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
	OutputFilePath *string
}

func main() {

	// Parse CLI args
	config := CliConfig{}

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
	client := hc.Client.FHClient

	// TODO: check whether host is up
	url := *parser.Doc.GetBaseUrl()
	log.Info().Msg(url)

	// generate and run tests
	apiTestHandler := tgen.TGenHandler{
		Doc: parser.Doc.GetDocHttpParams(),

		// Tests
		RunUnrestrictedHttpMethodTest: true,
	}

	apiTests := apiTestHandler.GenerateTests()

	apiTestHandler.RunApiTests(hc, client, apiTests)
	log.Info().Msgf("Total Requests: %d", len(apiTests))

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

	elapsed := time.Since(now)
	log.Info().Msgf("Overall Time: %v", elapsed)
}
