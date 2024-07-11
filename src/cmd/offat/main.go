package main

import (
	"flag"
	"time"

	"github.com/OWASP/OFFAT/src/pkg/http"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/valyala/fasthttp"
)

type Config struct {
	Filename              *string
	IsExternalRefsAllowed *bool
	RequestsPerSecond     *int
}

func main() {
	// setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Cli config
	config := Config{}

	config.Filename = flag.String("f", "", "OAS/Swagger Doc file path")
	config.IsExternalRefsAllowed = flag.Bool("er", false, "enables visiting other files")
	config.RequestsPerSecond = flag.Int("r", 60, "number of requests per second")
	flag.Parse()

	// parse documentation
	parser := parser.Parser{
		Filename:              *config.Filename,
		IsExternalRefsAllowed: *config.IsExternalRefsAllowed,
	}
	parser.Parse(*config.Filename)
	if err := parser.Doc.SetDocHttpParams(); err != nil {
		log.Error().Stack().Err(err).Msg("failed while fetching doc http params")
	}
	log.Print(parser.Doc.GetDocHttpParams())

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
