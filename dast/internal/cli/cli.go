// Package cli wires the DAST pipeline together behind a flag-based interface:
// load spec -> build dataflow graph -> load knowledge base -> generate tests ->
// execute -> detect -> AI/heuristic triage -> write reports.
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/attack"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/engine"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/graph"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/kb"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/report"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/spec"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/triage"
)

type options struct {
	specPath    string
	baseURL     string
	classes     string
	kbDir       string
	outDir      string
	concurrency int
	rate        float64
	timeout     int
	authHeader  string
	authValue   string
	headers     multiFlag
	proxy       string
	insecure    bool
	noAI        bool
	aiModel     string
	dryRun      bool
	maxPayloads int
	listClasses bool
	printGraph  bool
	iUnderstand bool
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// Run is the program entrypoint. It returns a process exit code.
func Run(args []string) int {
	opt, fs, err := parseFlags(args)
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if opt.aiModel != "" {
		_ = os.Setenv("OFFAT_AI_MODEL", opt.aiModel)
	}

	// Load and merge the knowledge base.
	k, err := kb.LoadDefault()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load knowledge base:", err)
		return 1
	}
	if opt.kbDir != "" {
		if err := k.LoadDir(opt.kbDir); err != nil {
			fmt.Fprintln(os.Stderr, "load kb dir:", err)
			return 1
		}
	}
	if opt.listClasses {
		fmt.Println("Available vulnerability classes:")
		for _, c := range k.Classes() {
			fmt.Println("  -", c)
		}
		return 0
	}
	if classList := splitCSV(opt.classes); len(classList) > 0 {
		k = k.Filter(classList)
	}

	if opt.specPath == "" {
		fmt.Fprintln(os.Stderr, "error: --spec is required")
		fs.Usage()
		return 2
	}

	api, err := spec.LoadFile(opt.specPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse spec:", err)
		return 1
	}
	g := graph.Build(api)
	cases := attack.Generate(api, g, k, attack.Options{MaxPayloadsPerVector: opt.maxPayloads})

	fmt.Printf("Parsed %q: %d endpoints, %d dataflow edges, %d KB vectors -> %d test cases\n",
		api.Title, len(api.Endpoints), len(g.Edges), len(k.Vectors), len(cases))

	if opt.printGraph {
		printGraph(g)
	}

	if opt.dryRun {
		fmt.Println("\n[dry-run] no requests sent. Test plan by class:")
		printPlan(cases)
		return 0
	}

	base := opt.baseURL
	if base == "" && len(api.Servers) > 0 {
		base = api.Servers[0]
	}
	if base == "" {
		fmt.Fprintln(os.Stderr, "error: no target URL. Pass --url or ensure the spec declares a server.")
		return 2
	}
	if !opt.iUnderstand {
		fmt.Fprintf(os.Stderr, "\nWARNING: this will send active attack traffic to %s\n", base)
		fmt.Fprintln(os.Stderr, "Only scan systems you own or are explicitly authorized to test.")
		fmt.Fprintln(os.Stderr, "Re-run with --yes to confirm authorization and proceed.")
		return 3
	}

	eng, err := buildEngine(opt, base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "engine:", err)
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("Scanning %s with %d workers (rate %.0f/s)...\n", base, opt.concurrency, opt.rate)
	start := time.Now()
	results := eng.Run(ctx, cases)
	findings := detect.Detect(results)
	fmt.Printf("Executed %d requests in %s, %d candidate findings\n", len(results), time.Since(start).Round(time.Millisecond), len(findings))

	triageSource := runTriage(ctx, opt, findings)

	rep := report.Build(base, api.Title, len(results), triageSource, findings)
	if err := writeReports(opt.outDir, rep); err != nil {
		fmt.Fprintln(os.Stderr, "write reports:", err)
		return 1
	}
	printSummary(rep, opt.outDir)
	return 0
}

func runTriage(ctx context.Context, opt options, findings []*detect.Finding) string {
	if len(findings) == 0 {
		return "none"
	}
	var t triage.Triager = triage.Heuristic{}
	source := "heuristic"
	if !opt.noAI {
		if ai, ok := triage.NewAnthropicFromEnv(); ok {
			t = ai
			source = ai.Name()
			fmt.Printf("AI triage enabled (%s)\n", source)
		} else {
			fmt.Println("AI triage: no API key found (set OFFAT_AI_API_KEY); using heuristic triager")
		}
	}
	triage.Run(ctx, t, findings, opt.concurrency)
	return source
}

func buildEngine(opt options, base string) (*engine.Engine, error) {
	cfg := engine.Config{
		BaseURL:         base,
		Concurrency:     opt.concurrency,
		RateLimitPerSec: opt.rate,
		Timeout:         time.Duration(opt.timeout) * time.Second,
		Proxy:           opt.proxy,
		InsecureTLS:     opt.insecure,
		ExtraHeaders:    map[string]string{},
	}
	for _, h := range opt.headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			cfg.ExtraHeaders[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if opt.authHeader != "" && opt.authValue != "" {
		cfg.Auth = &engine.AuthConfig{Header: opt.authHeader, Value: opt.authValue}
	}
	return engine.New(cfg)
}

func writeReports(dir string, rep *report.Report) error {
	if dir == "" {
		dir = "offat-report"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	writers := map[string]func(f *os.File) error{
		"report.json":    func(f *os.File) error { return report.WriteJSON(f, rep) },
		"findings.jsonl": func(f *os.File) error { return report.WriteJSONL(f, rep) },
		"results.sarif":  func(f *os.File) error { return report.WriteSARIF(f, rep) },
		"report.md":      func(f *os.File) error { return report.WriteMarkdown(f, rep) },
		"report.html":    func(f *os.File) error { return report.WriteHTML(f, rep) },
	}
	for name, fn := range writers {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if err := fn(f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
