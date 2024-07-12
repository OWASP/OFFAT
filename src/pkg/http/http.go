package http

import (
	"crypto/tls"
	"time"

	fhc "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/valyala/fasthttp"
)

func NewConfig(requestsPerSecond *int, skipTlsVerification *bool) *Config {
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
		TLSConfig: tlsConfig,
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
