package main

import (
	"flag"
	"log"
	"time"

	"github.com/OWASP/OFFAT/src/pkg/http"
	"github.com/OWASP/OFFAT/src/pkg/openapi"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/valyala/fasthttp"
)

type Config struct {
	Filename              *string
	IsExternalRefsAllowed *bool
	RequestsPerSecond     *int
}

func main() {
	config := Config{}

	config.Filename = flag.String("f", "", "OAS/Swagger Doc file path")
	config.IsExternalRefsAllowed = flag.Bool("er", false, "enables visiting other files")
	config.RequestsPerSecond = flag.Int("r", 60, "number of requests per second")
	flag.Parse()

	parser := openapi.Parser{
		Filename:              *config.Filename,
		IsExternalRefsAllowed: *config.IsExternalRefsAllowed,
	}
	parser.Parse(*config.Filename)

	if parser.IsOpenApi {
		log.Println(parser.OpenApiDoc.Paths)
	} else {
		log.Println(parser.SwaggerDoc.Paths)
	}

	// http client
	httpCfg := http.NewConfig(config.RequestsPerSecond)
	hc := http.NewHttp(httpCfg)

	log.Println(*hc.Config.RequestsPerSecond)

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
			log.Fatalln(connResp.Error)
		}
		log.Println(connResp.Response.StatusCode)
		log.Println(connResp.Response.Headers)
		log.Println(string(connResp.Response.Body))
	}
	elapsed := time.Since(now)
	log.Println("Time:", elapsed)
}
