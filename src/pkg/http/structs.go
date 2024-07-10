package http

import (
	"github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/valyala/fasthttp"
)

type Config struct {
	HttpClient        *fasthttp.Client
	RequestsPerSecond *int
}

type Http struct {
	Requests  []*client.Request
	Responses []*client.ConcurrentResponse
	Config    *Config
	Client    *client.RateLimitedClient
}
