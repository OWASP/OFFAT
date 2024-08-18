package http_test

import (
	"testing"

	"github.com/OWASP/OFFAT/src/pkg/http"

	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/valyala/fasthttp"
)

func TestHttpClient(t *testing.T) {
	// http client
	requestsPerSecond := 10
	skipTlsVerification := false
	proxy := ""
	httpCfg := http.NewConfig(&requestsPerSecond, &skipTlsVerification, &proxy)
	hc := http.NewHttp(httpCfg)
	client := hc.Client.FHClient

	url := "https://example.com"
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))
	hc.Requests = append(hc.Requests, c.NewRequest(url, fasthttp.MethodGet, nil, nil, nil))

	t.Run("Concurrent Requests Test", func(t *testing.T) {
		hc.Responses = c.MakeConcurrentRequests(hc.Requests, client)

		for _, connResp := range hc.Responses {
			if connResp.Error != nil {
				t.Fatalf("failed to make concurrent request: %v\n", connResp.Error)
			}
		}
	})

}
