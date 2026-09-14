// Package engine executes generated test cases against a live target. It runs
// baseline/producer requests first (in dataflow order) to populate the value
// store, then fires attack requests concurrently under a rate limit. Responses
// are captured verbatim so the detect package can judge them.
package engine

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/attack"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/graph"
)

// AuthConfig describes how to authenticate requests.
type AuthConfig struct {
	Header      string
	Value       string
	QueryParam  string
	QueryValue  string
	Cookie      string
	CookieValue string
}

// Config controls execution.
type Config struct {
	BaseURL         string
	Concurrency     int
	RateLimitPerSec float64
	Timeout         time.Duration
	Auth            *AuthConfig
	ExtraHeaders    map[string]string
	Proxy           string
	InsecureTLS     bool
	UserAgent       string
	MaxBodyBytes    int64
}

// Result is the captured outcome of one test case.
type Result struct {
	Case       *attack.TestCase
	StatusCode int
	Headers    http.Header
	Body       []byte
	LatencyMs  int64
	Err        string
	// RepeatStatuses holds status codes when Request.Repeat > 1 (rate limiting).
	RepeatStatuses []int
}

// Engine runs test cases.
type Engine struct {
	cfg     Config
	client  *http.Client
	store   *valueStore
	limiter *limiter
}

// New builds an Engine.
func New(cfg Config) (*Engine, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 2 << 20 // 2 MiB
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "offat-ai-dast/1.0"
	}
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: cfg.Concurrency,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureTLS}, //nolint:gosec // opt-in for test targets
	}
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(pu)
	}
	return &Engine{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Do not follow redirects: open-redirect detection needs the 3xx.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		store:   newValueStore(),
		limiter: newLimiter(cfg.RateLimitPerSec),
	}, nil
}

// Run executes all cases and returns their results.
func (e *Engine) Run(ctx context.Context, cases []*attack.TestCase) []*Result {
	var baselines, attacks []*attack.TestCase
	for _, c := range cases {
		if c.Kind == "baseline" {
			baselines = append(baselines, c)
		} else {
			attacks = append(attacks, c)
		}
	}

	results := make([]*Result, 0, len(cases))
	var mu sync.Mutex

	// Phase 1: baselines sequentially, in the order given (producer-first), so
	// identifiers are harvested before consumers/attacks run.
	for _, c := range baselines {
		r := e.exec(ctx, c)
		e.harvest(r)
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	// Phase 2: attacks concurrently.
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for _, c := range attacks {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(tc *attack.TestCase) {
			defer wg.Done()
			defer func() { <-sem }()
			r := e.exec(ctx, tc)
			e.harvest(r)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return results
}

// harvest records identifier values from a successful response.
func (e *Engine) harvest(r *Result) {
	if r == nil || r.StatusCode < 200 || r.StatusCode >= 300 || len(r.Body) == 0 {
		return
	}
	resource := graph.ResourceOf(r.Case.Endpoint.Path)
	e.store.harvest(r.Body, resource)
}

func (e *Engine) exec(ctx context.Context, tc *attack.TestCase) *Result {
	res := &Result{Case: tc}
	repeat := tc.Request.Repeat
	if repeat < 1 {
		repeat = 1
	}
	for i := 0; i < repeat; i++ {
		e.limiter.wait(ctx)
		req, err := e.build(ctx, tc)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		start := time.Now()
		resp, err := e.client.Do(req)
		lat := time.Since(start).Milliseconds()
		if err != nil {
			res.Err = err.Error()
			if repeat > 1 {
				res.RepeatStatuses = append(res.RepeatStatuses, 0)
				continue
			}
			return res
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, e.cfg.MaxBodyBytes))
		resp.Body.Close()
		if repeat > 1 {
			res.RepeatStatuses = append(res.RepeatStatuses, resp.StatusCode)
		}
		// Keep the last (or only) response as the representative result.
		res.StatusCode = resp.StatusCode
		res.Headers = resp.Header
		res.Body = body
		res.LatencyMs = lat
	}
	return res
}

// Store exposes the harvested value store (used in tests/diagnostics).
func (e *Engine) Store() *valueStore { return e.store }
