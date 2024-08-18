package http

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	fhc "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

var emptyStr string = ""
var HttpDefaultRateLimit = 60
var HttpDefaultTlsVerification = true
var HttpDefaultConfig = NewConfig(&HttpDefaultRateLimit, &HttpDefaultTlsVerification, &emptyStr)
var DefaultClient = NewHttp(HttpDefaultConfig) // this won't be proxied

func NewConfig(requestsPerSecond *int, skipTlsVerification *bool, proxy *string) *Config {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *skipTlsVerification,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_AES_128_GCM_SHA256,       // TLS 1.3
			tls.TLS_AES_256_GCM_SHA384,       // TLS 1.3
			tls.TLS_CHACHA20_POLY1305_SHA256, // TLS 1.3
		},
		PreferServerCipherSuites: true,
	}

	dial, err := CreateProxiedDialer(*proxy)
	if err != nil {
		log.Error().Stack().Err(err).Msg("failed to create proxy dialer, falling back to default dailer!")
		dial, _ = CreateProxiedDialer("")
	}

	// create fasthttpclient
	fhc := &fasthttp.Client{
		Name:                     "OWASP-OFFAT",
		MaxConnsPerHost:          10000,
		ReadTimeout:              time.Second * 5,
		WriteTimeout:             time.Second * 5,
		MaxIdleConnDuration:      time.Second * 60,
		NoDefaultUserAgentHeader: true,
		Dial:                     dial,
		TLSConfig:                tlsConfig,
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

// CreateDialer returns a dialer function based on the given proxy URL and type.
// returns non proxied dialer if empty string is passed.
func CreateProxiedDialer(proxyURL string) (fasthttp.DialFunc, error) {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	if strings.HasPrefix(parsedURL.Scheme, "http") {
		newStr := strings.Replace(strings.Replace(proxyURL, "https://", "", 1), "http://", "", 1)
		return fasthttpproxy.FasthttpHTTPDialer(newStr), nil
	} else if strings.HasPrefix(parsedURL.Scheme, "socks") {
		return fasthttpproxy.FasthttpSocksDialer(proxyURL), nil
	}

	return (&fasthttp.TCPDialer{
		Concurrency:      4096,
		DNSCacheDuration: time.Hour,
	}).Dial, nil
}
