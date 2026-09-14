package triage

import (
	"context"
	"testing"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

func TestHeuristicVerdicts(t *testing.T) {
	cases := []struct {
		conf float64
		want string
	}{
		{0.9, "confirmed"},
		{0.65, "likely"},
		{0.45, "inconclusive"},
		{0.2, "false_positive"},
	}
	for _, c := range cases {
		f := &detect.Finding{Class: "sqli", Severity: "high", Confidence: c.conf}
		_ = Heuristic{}.Triage(context.Background(), f)
		if f.Triage == nil || f.Triage.Verdict != c.want {
			t.Errorf("conf %.2f -> %v want %s", c.conf, f.Triage, c.want)
		}
		if f.Triage.Remediation == "" {
			t.Errorf("missing remediation for %.2f", c.conf)
		}
	}
}

func TestStructuralNotBlindlyConfirmed(t *testing.T) {
	f := &detect.Finding{Class: "access_control", Severity: "critical", Confidence: 0.95}
	_ = Heuristic{}.Triage(context.Background(), f)
	if f.Triage.Verdict == "confirmed" {
		t.Error("access_control should not be blindly confirmed by heuristic")
	}
}

func TestRunAlwaysTriages(t *testing.T) {
	findings := []*detect.Finding{{Class: "xss", Severity: "medium", Confidence: 0.7}}
	Run(context.Background(), Heuristic{}, findings, 2)
	if findings[0].Triage == nil {
		t.Fatal("finding not triaged")
	}
}
