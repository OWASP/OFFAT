package engine

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/attack"
)

// build turns a resolved RequestSpec into an *http.Request, applying graph seed
// values, authentication and global headers.
func (e *Engine) build(ctx context.Context, tc *attack.TestCase) (*http.Request, error) {
	rs := tc.Request

	// Resolve seed values (dataflow chaining / BOLA) over the defaults.
	pathVals := cloneStr(rs.PathParams)
	queryVals := cloneStr(rs.Query)
	for name, hint := range rs.SeedParams {
		if v, ok := e.store.lookup(hint.Key, hint.Resource, hint.Foreign); ok {
			switch hint.In {
			case "path":
				pathVals[name] = v
			case "query":
				queryVals[name] = v
			}
		}
	}

	// Substitute path template parameters.
	rawPath := tc.Endpoint.Path
	for name, val := range pathVals {
		rawPath = strings.ReplaceAll(rawPath, "{"+name+"}", url.PathEscape(val))
	}

	u := strings.TrimRight(e.cfg.BaseURL, "/") + rawPath
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	q := parsed.Query()
	for k, v := range queryVals {
		q.Set(k, v)
	}

	var body []byte
	if len(rs.Body) > 0 {
		body = rs.Body
	}
	req, err := http.NewRequestWithContext(ctx, rs.Method, parsed.String(), bytesReader(body))
	if err != nil {
		return nil, err
	}
	if len(q) > 0 {
		req.URL.RawQuery = q.Encode()
	}

	if rs.ContentType != "" && len(body) > 0 {
		req.Header.Set("Content-Type", rs.ContentType)
	}
	if e.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", e.cfg.UserAgent)
	}
	for k, v := range e.cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range rs.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range rs.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	if !rs.OmitAuth {
		e.applyAuth(req, rs.JWTNone)
	}
	return req, nil
}

func (e *Engine) applyAuth(req *http.Request, jwtNone bool) {
	a := e.cfg.Auth
	if a == nil {
		return
	}
	if a.Header != "" && a.Value != "" {
		val := a.Value
		if jwtNone {
			val = forgeJWTNone(val)
		}
		req.Header.Set(a.Header, val)
	}
	if a.QueryParam != "" && a.QueryValue != "" {
		q := req.URL.Query()
		q.Set(a.QueryParam, a.QueryValue)
		req.URL.RawQuery = q.Encode()
	}
	if a.Cookie != "" && a.CookieValue != "" {
		req.AddCookie(&http.Cookie{Name: a.Cookie, Value: a.CookieValue})
	}
}

func cloneStr(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func bytesReader(b []byte) *bytes.Reader {
	if b == nil {
		return bytes.NewReader(nil)
	}
	return bytes.NewReader(b)
}
