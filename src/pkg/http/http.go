package http

import (
	"time"

	fhc "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/valyala/fasthttp"
)

func NewConfig(requestsPerSecond *int) *Config {
	fhc := &fasthttp.Client{
		Name:                     "OWASP-OFFAT",
		MaxConnsPerHost:          10000,
		ReadTimeout:              time.Second * 5,
		WriteTimeout:             time.Second * 5,
		MaxIdleConnDuration:      time.Second * 60,
		NoDefaultUserAgentHeader: true,
		Dial: (&fasthttp.TCPDialer{
			Concurrency:      4096,
			DNSCacheDuration: time.Hour,
		}).Dial,
	}

	return &Config{
		RequestsPerSecond: requestsPerSecond,
		HttpClient:        fhc,
	}
}

func NewHttp(config *Config) *Http {
	rlc := fhc.NewRateLimitedClient(*config.RequestsPerSecond, 1, config.HttpClient)

	return &Http{
		Requests:  []*fhc.Request{},
		Responses: []*fhc.ConcurrentResponse{},
		Config:    config,
		Client:    rlc,
	}
}
