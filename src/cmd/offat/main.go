package main

import (
	"flag"
	"os"
	"time"

	"github.com/OWASP/OFFAT/src/pkg/http"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"

	"github.com/valyala/fasthttp"
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

	if err := parser.Doc.SetDocHttpParams(); err != nil {
		log.Error().Stack().Err(err).Msg("failed while fetching doc http params")
	}

	log.Info().Msg("fuzzing doc http params")
	parser.FuzzDocHttpParams()
	log.Info().Msgf("%v", parser.Doc.GetDocHttpParams())

	// http client
	httpCfg := http.NewConfig(config.RequestsPerSecond, config.SkipTlsVerfication)
	hc := http.NewHttp(httpCfg)
	client := hc.Client.FHClient

	err := parser.Doc.SetBaseUrl(*config.BaseUrl)
	if err != nil {
		log.Error().Err(err).Msg("failed to set baseUrl")
	}

	url := *parser.Doc.GetBaseUrl()
	log.Info().Msg(url)

	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))

	hc.Responses = c.MakeConcurrentRequests(hc.Requests, client)
	for _, connResp := range hc.Responses {
		if connResp.Error != nil {
			log.Error().Stack().Err(connResp.Error).Msg("request failed")
		} else {
			log.Info().Msgf("Status Code: %v - Time: %v", connResp.Response.StatusCode, connResp.Response.TimeElapsed)
		}
	}
	elapsed := time.Since(now)
	log.Info().Msgf("Time: %v", elapsed)
}
