package main

import (
	"flag"
	"os"
	"time"

	"github.com/OWASP/OFFAT/src/pkg/http"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"

	"github.com/valyala/fasthttp"
)

type CliConfig struct {
	// Parser config
	Filename *string

	RequestsPerSecond *int

	IsExternalRefsAllowed           *bool
	DisableExamplesValidation       *bool
	DisableSchemaDefaultsValidation *bool
	DisableSchemaPatternValidation  *bool
}

func main() {

	// Parse CLI args
	config := CliConfig{}

	config.Filename = flag.String("f", "", "OAS/Swagger Doc file path")
	config.IsExternalRefsAllowed = flag.Bool("er", false, "enables visiting other files")
	config.DisableExamplesValidation = flag.Bool("de", false, "disable example validation for OAS files")
	config.DisableSchemaDefaultsValidation = flag.Bool("ds", false, "disable schema defaults validation for OAS files")
	config.DisableSchemaPatternValidation = flag.Bool("dp", false, "disable schema patterns validation for OAS files")
	config.RequestsPerSecond = flag.Int("r", 60, "number of requests per second")
	flag.Parse()

	// parse documentation
	parser, err := parser.NewParser(
		*config.Filename,
		*config.IsExternalRefsAllowed,
		*config.DisableExamplesValidation,
		*config.DisableSchemaDefaultsValidation,
		*config.DisableSchemaPatternValidation,
	)

	if err != nil {
		log.Error().Err(err).Msg("unable to parse file")
	}

	if err := parser.Parse(*config.Filename); err != nil {
		log.Error().Stack().Err(err).Msg("failed to parse API documentation file")
		os.Exit(1)
	}

	if err := parser.Doc.SetDocHttpParams(); err != nil {
		log.Error().Stack().Err(err).Msg("failed while fetching doc http params")
	}
	log.Info().Msgf("%v", parser.Doc.GetDocHttpParams())

	// http client
	httpCfg := http.NewConfig(config.RequestsPerSecond)
	hc := http.NewHttp(httpCfg)
	client := hc.Client.FHClient

	url := "https://example.com"
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))

	hc.Responses = c.MakeConcurrentRequests(hc.Requests, client)
	now := time.Now()
	for _, connResp := range hc.Responses {

		if connResp.Error != nil {
			log.Error().Msg(connResp.Error.Error())
		}
	}
	elapsed := time.Since(now)
	log.Info().Msgf("Time: %v", elapsed)
}
