package triage

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

func TestSelectProviders(t *testing.T) {
	// Isolate from ambient env.
	t.Setenv("OFFAT_AI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OFFAT_AI_PROVIDER", "")

	if _, src := Select("heuristic", false); src != "heuristic" {
		t.Errorf("heuristic provider = %s", src)
	}
	if _, src := Select("", true); src != "heuristic" {
		t.Errorf("noAI should force heuristic, got %s", src)
	}
	if tr, src := Select("codex", false); src != "codex" {
		t.Errorf("codex provider = %s", src)
	} else if _, ok := tr.(*CommandTriager); !ok {
		t.Errorf("codex should be a CommandTriager")
	}
	t.Setenv("OFFAT_AI_API_KEY", "sk-test")
	if _, src := Select("anthropic", false); src == "heuristic" {
		t.Errorf("anthropic with key should not be heuristic")
	}
}

func TestCommandTriagerParsesVerdict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "agent.sh")
	script := "#!/bin/sh\n" +
		"echo 'thinking...'\n" +
		`echo '{"verdict":"false_positive","confidence":0.1,"severity":"low","rationale":"reflected into json","remediation":"encode"}'` + "\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ct := &CommandTriager{Label: "stub", Base: []string{"sh", stub}, Timeout: 10e9}
	f := &detect.Finding{Class: "xss", Severity: "medium", Confidence: 0.7}
	if err := ct.Triage(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if f.Triage == nil || f.Triage.Verdict != "false_positive" || f.Triage.Source != "stub" {
		t.Fatalf("verdict not parsed from CLI: %+v", f.Triage)
	}
}

func TestCommandTriagerFallsBackOnFailure(t *testing.T) {
	ct := &CommandTriager{Label: "broken", Base: []string{"definitely-not-a-real-binary-xyz"}, Timeout: 5e9}
	f := &detect.Finding{Class: "sqli", Severity: "high", Confidence: 0.85}
	_ = ct.Triage(context.Background(), f)
	if f.Triage == nil {
		t.Fatal("expected heuristic fallback triage")
	}
	if f.Triage.Source != "heuristic" {
		t.Errorf("fallback source = %s, want heuristic", f.Triage.Source)
	}
}
