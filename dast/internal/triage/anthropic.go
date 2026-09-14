package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

// DefaultModel is the model the AI triager uses when OFFAT_AI_MODEL is unset.
// Override with the --ai-model flag or the OFFAT_AI_MODEL environment variable
// to track the latest available model.
const DefaultModel = "claude-sonnet-5"

const anthropicVersion = "2023-06-01"

// Anthropic is an AI triager backed by the Anthropic Messages API. It performs
// adversarial verification of each candidate finding and, on any failure,
// transparently falls back to the heuristic triager.
type Anthropic struct {
	APIKey  string
	Model   string
	BaseURL string
	client  *http.Client
}

// NewAnthropicFromEnv constructs an Anthropic triager from environment
// variables. It returns (nil, false) when no API key is configured.
func NewAnthropicFromEnv() (*Anthropic, bool) {
	key := firstEnv("OFFAT_AI_API_KEY", "ANTHROPIC_API_KEY")
	if key == "" {
		return nil, false
	}
	model := firstEnv("OFFAT_AI_MODEL")
	if model == "" {
		model = DefaultModel
	}
	base := firstEnv("OFFAT_AI_BASE_URL", "ANTHROPIC_BASE_URL")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	return &Anthropic{
		APIKey:  key,
		Model:   model,
		BaseURL: strings.TrimRight(base, "/"),
		client:  &http.Client{Timeout: 60 * time.Second},
	}, true
}

func (a *Anthropic) Name() string { return "ai:" + a.Model }

type apiRequest struct {
	Model     string       `json:"model"`
	MaxTokens int          `json:"max_tokens"`
	System    string       `json:"system"`
	Messages  []apiMessage `json:"messages"`
}

type apiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

const triageSystem = `You are an expert application-security triager verifying candidate API vulnerabilities from a DAST scanner.
Assume the detector may be wrong. Try to REFUTE the finding first, then decide.
Consider the vulnerability class, the payload, the evidence (status codes, latency, matched signatures, response snippet) and whether the evidence genuinely proves exploitability rather than coincidence.
Respond with ONLY a compact JSON object and nothing else, of the form:
{"verdict":"confirmed|likely|inconclusive|false_positive","confidence":0.0-1.0,"cvss":0.0-10.0,"severity":"critical|high|medium|low|info","rationale":"one or two sentences","remediation":"one sentence"}`

func (a *Anthropic) Triage(ctx context.Context, f *detect.Finding) error {
	prompt := buildPrompt(f)
	reqBody, _ := json.Marshal(apiRequest{
		Model:     a.Model,
		MaxTokens: 700,
		System:    triageSystem,
		Messages:  []apiMessage{{Role: "user", Content: prompt}},
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+"/v1/messages", bytes.NewReader(reqBody))
	if err != nil {
		return a.fallback(ctx, f, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.APIKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return a.fallback(ctx, f, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return a.fallback(ctx, f, fmt.Errorf("anthropic status %d: %s", resp.StatusCode, string(data)))
	}
	var ar apiResponse
	if err := json.Unmarshal(data, &ar); err != nil {
		return a.fallback(ctx, f, err)
	}
	if ar.Error != nil {
		return a.fallback(ctx, f, fmt.Errorf("anthropic error: %s", ar.Error.Message))
	}
	text := ""
	for _, c := range ar.Content {
		if c.Type == "text" {
			text += c.Text
		}
	}
	verdict, ok := parseVerdict(text)
	if !ok {
		return a.fallback(ctx, f, fmt.Errorf("could not parse triage JSON"))
	}
	verdict.Source = "ai"
	if verdict.CVSS == 0 {
		verdict.CVSS = cvssFor(verdict.Severity)
	}
	if verdict.Severity == "" {
		verdict.Severity = f.Severity
	}
	f.Triage = verdict
	return nil
}

func (a *Anthropic) fallback(ctx context.Context, f *detect.Finding, cause error) error {
	_ = Heuristic{}.Triage(ctx, f)
	if f.Triage != nil {
		f.Triage.Rationale = f.Triage.Rationale + " (AI triage unavailable: " + trimErr(cause) + ")"
	}
	return nil
}

func buildPrompt(f *detect.Finding) string {
	ev := f.Evidence
	var b strings.Builder
	fmt.Fprintf(&b, "Candidate finding:\n")
	fmt.Fprintf(&b, "- class: %s\n- title: %s\n- cwe: %s\n- owasp: %s\n", f.Class, f.Title, f.CWE, f.OWASP)
	fmt.Fprintf(&b, "- endpoint: %s\n- parameter: %s (in %s)\n- technique: %s\n", f.Endpoint, f.Param, f.Location, f.Technique)
	if f.Payload != "" {
		fmt.Fprintf(&b, "- payload: %s\n", truncate(f.Payload, 300))
	}
	fmt.Fprintf(&b, "- detector confidence: %.2f\n", f.Confidence)
	fmt.Fprintf(&b, "Evidence:\n- request: %s\n- status: %d (baseline %d)\n- latency: %dms (baseline %dms)\n",
		ev.RequestMethod, ev.StatusCode, ev.BaselineStatus, ev.LatencyMs, ev.BaselineLatencyMs)
	if ev.MatchedSignature != "" {
		fmt.Fprintf(&b, "- matched signature: %s\n", ev.MatchedSignature)
	}
	if ev.Notes != "" {
		fmt.Fprintf(&b, "- notes: %s\n", ev.Notes)
	}
	if ev.Snippet != "" {
		fmt.Fprintf(&b, "- response snippet: %s\n", truncate(ev.Snippet, 800))
	}
	return b.String()
}

func parseVerdict(text string) (*detect.Triage, bool) {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, false
	}
	var v detect.Triage
	if err := json.Unmarshal([]byte(text[start:end+1]), &v); err != nil {
		return nil, false
	}
	if v.Verdict == "" {
		return nil, false
	}
	return &v, true
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func trimErr(err error) string {
	if err == nil {
		return ""
	}
	return truncate(err.Error(), 160)
}
