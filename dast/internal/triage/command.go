package triage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

// CommandTriager drives a locally-installed agent CLI (Claude Code or OpenAI
// Codex) to triage findings, instead of a raw API key. The CLI is invoked
// non-interactively and its stdout is parsed for the compact JSON verdict the
// triage prompt requests. Any failure falls back to the heuristic triager.
type CommandTriager struct {
	Label   string   // source label, e.g. "claude-code" / "codex"
	Base    []string // base argv; the prompt is appended as the final arg
	Timeout time.Duration
}

// NewClaudeCode builds a triager backed by the Claude Code CLI (`claude -p`).
// Override the base command with OFFAT_AI_CLAUDE_CMD and set a model with
// OFFAT_AI_CLAUDE_MODEL.
func NewClaudeCode() *CommandTriager {
	return &CommandTriager{
		Label:   "claude-code",
		Base:    cmdFromEnv("OFFAT_AI_CLAUDE_CMD", []string{"claude", "-p"}, "OFFAT_AI_CLAUDE_MODEL", "--model"),
		Timeout: 180 * time.Second,
	}
}

// NewCodex builds a triager backed by the OpenAI Codex CLI (`codex exec`).
// Override with OFFAT_AI_CODEX_CMD and OFFAT_AI_CODEX_MODEL.
func NewCodex() *CommandTriager {
	return &CommandTriager{
		Label:   "codex",
		Base:    cmdFromEnv("OFFAT_AI_CODEX_CMD", []string{"codex", "exec"}, "OFFAT_AI_CODEX_MODEL", "-m"),
		Timeout: 180 * time.Second,
	}
}

func (c *CommandTriager) Name() string { return c.Label }

// Available reports whether the CLI's executable is on PATH.
func (c *CommandTriager) Available() bool {
	if len(c.Base) == 0 {
		return false
	}
	_, err := exec.LookPath(c.Base[0])
	return err == nil
}

func (c *CommandTriager) Triage(ctx context.Context, f *detect.Finding) error {
	prompt := triageSystem + "\n\n" + buildPrompt(f)
	out, err := c.run(ctx, prompt)
	if err == nil {
		if v, ok := parseVerdict(out); ok {
			v.Source = c.Label
			if v.CVSS == 0 {
				v.CVSS = cvssFor(v.Severity)
			}
			if v.Severity == "" {
				v.Severity = f.Severity
			}
			f.Triage = v
			return nil
		}
		err = fmt.Errorf("no JSON verdict in CLI output")
	}
	_ = Heuristic{}.Triage(ctx, f)
	if f.Triage != nil {
		f.Triage.Rationale += " (AI CLI '" + c.Label + "' unavailable: " + trimErr(err) + ")"
	}
	return nil
}

func (c *CommandTriager) run(ctx context.Context, prompt string) (string, error) {
	if len(c.Base) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	args := append(append([]string{}, c.Base[1:]...), prompt)
	cmd := exec.CommandContext(cctx, c.Base[0], args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return "", fmt.Errorf("%v: %s", err, truncate(msg, 160))
	}
	return stdout.String(), nil
}

// cmdFromEnv builds a base argv from an optional whitespace-split override, and
// appends a model flag when the model env var is set.
func cmdFromEnv(cmdEnv string, def []string, modelEnv, modelFlag string) []string {
	base := def
	if override := strings.TrimSpace(os.Getenv(cmdEnv)); override != "" {
		base = strings.Fields(override)
	} else {
		base = append([]string{}, def...)
	}
	if model := strings.TrimSpace(os.Getenv(modelEnv)); model != "" && modelFlag != "" {
		base = append(base, modelFlag, model)
	}
	return base
}

// Select resolves a triager from a provider name (or auto-detection) and
// returns it with its source label. Providers: auto (default), anthropic,
// claude-code, codex, heuristic.
func Select(provider string, noAI bool) (Triager, string) {
	if noAI {
		return Heuristic{}, "heuristic"
	}
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		p = strings.ToLower(strings.TrimSpace(os.Getenv("OFFAT_AI_PROVIDER")))
	}
	switch p {
	case "", "auto":
		if ai, ok := NewAnthropicFromEnv(); ok {
			return ai, ai.Name()
		}
		if cliAvailable("claude") {
			t := NewClaudeCode()
			return t, t.Name()
		}
		if cliAvailable("codex") {
			t := NewCodex()
			return t, t.Name()
		}
		return Heuristic{}, "heuristic"
	case "anthropic", "api", "anthropic-api":
		if ai, ok := NewAnthropicFromEnv(); ok {
			return ai, ai.Name()
		}
		return Heuristic{}, "heuristic"
	case "claude", "claude-code", "claudecode":
		t := NewClaudeCode()
		return t, t.Name()
	case "codex", "openai-codex":
		t := NewCodex()
		return t, t.Name()
	default: // heuristic / none / off / unknown
		return Heuristic{}, "heuristic"
	}
}

func cliAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
