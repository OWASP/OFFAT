package cli

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/attack"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/graph"
	"github.com/dmdhrumilmistry/offat-ai/dast/internal/report"
)

func parseFlags(args []string) (options, *flag.FlagSet, error) {
	var opt options
	fs := flag.NewFlagSet("offat-dast", flag.ContinueOnError)
	fs.StringVar(&opt.specPath, "spec", "", "path to OpenAPI/Swagger spec (JSON or YAML)")
	fs.StringVar(&opt.specPath, "f", "", "shorthand for --spec")
	fs.StringVar(&opt.baseURL, "url", "", "target base URL (overrides the spec server)")
	fs.StringVar(&opt.classes, "classes", "", "comma-separated vuln classes to test (default: all)")
	fs.StringVar(&opt.kbDir, "kb", "", "additional knowledge-base directory to merge")
	fs.StringVar(&opt.outDir, "out", "offat-report", "output directory for reports")
	fs.StringVar(&opt.outDir, "o", "offat-report", "shorthand for --out")
	fs.IntVar(&opt.concurrency, "concurrency", 10, "concurrent requests")
	fs.Float64Var(&opt.rate, "rate", 25, "max requests per second (0 = unlimited)")
	fs.IntVar(&opt.timeout, "timeout", 15, "per-request timeout in seconds")
	fs.StringVar(&opt.authHeader, "auth-header", "Authorization", "auth header name")
	fs.StringVar(&opt.authValue, "auth-value", "", "auth header value, e.g. 'Bearer <token>'")
	fs.Var(&opt.headers, "H", "extra header 'Name: Value' (repeatable)")
	fs.StringVar(&opt.proxy, "proxy", "", "HTTP(S) proxy URL (e.g. for Burp/ZAP)")
	fs.BoolVar(&opt.insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&opt.noAI, "no-ai", false, "disable AI triage (heuristic only)")
	fs.StringVar(&opt.aiProvider, "ai-provider", "", "AI triage backend: auto (default), anthropic, claude-code, codex, heuristic")
	fs.StringVar(&opt.aiModel, "ai-model", "", "AI model id for triage (else OFFAT_AI_MODEL)")
	fs.BoolVar(&opt.dryRun, "dry-run", false, "generate the test plan without sending requests")
	fs.IntVar(&opt.maxPayloads, "max-payloads", 0, "cap payloads per vector (0 = all)")
	fs.BoolVar(&opt.listClasses, "list-classes", false, "list available vuln classes and exit")
	fs.BoolVar(&opt.printGraph, "graph", false, "print the dataflow graph")
	fs.BoolVar(&opt.iUnderstand, "yes", false, "confirm you are authorized to scan the target")
	fs.StringVar(&opt.failOn, "fail-on", "", "exit non-zero if any actionable finding is at/above this severity (critical|high|medium|low|info)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "offat-dast — OpenAPI-driven DAST engine (OFFAT-AI)\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  offat-dast --spec api.yaml --url https://api.example.com --yes\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment:\n")
		fmt.Fprintf(os.Stderr, "  OFFAT_AI_API_KEY / ANTHROPIC_API_KEY  enable the Anthropic-API triager\n")
		fmt.Fprintf(os.Stderr, "  OFFAT_AI_PROVIDER                     auto|anthropic|claude-code|codex|heuristic\n")
		fmt.Fprintf(os.Stderr, "  OFFAT_AI_MODEL                        API model id (default: %s)\n", "claude-sonnet-5")
		fmt.Fprintf(os.Stderr, "  OFFAT_AI_CLAUDE_CMD / OFFAT_AI_CODEX_CMD    override the CLI invocation\n")
		fmt.Fprintf(os.Stderr, "  OFFAT_AI_CLAUDE_MODEL / OFFAT_AI_CODEX_MODEL  CLI model id\n")
		fmt.Fprintf(os.Stderr, "\n  With no API key, --ai-provider claude-code or codex uses a local agent CLI.\n")
	}

	if err := fs.Parse(args); err != nil {
		return opt, fs, err
	}
	return opt, fs, nil
}

func printGraph(g *graph.Graph) {
	fmt.Println("\nDataflow graph (producer -> consumer):")
	if len(g.Edges) == 0 {
		fmt.Println("  (no links inferred)")
		return
	}
	for _, e := range g.Edges {
		fmt.Printf("  %s [%s] --> %s.%s  (%.2f: %s)\n",
			e.From.Endpoint.ID(), e.From.Field, e.To.Endpoint.ID(), e.To.Name(), e.Confidence, e.Reason)
	}
}

func printPlan(cases []*attack.TestCase) {
	byKind := map[string]int{}
	byClass := map[string]int{}
	for _, c := range cases {
		byKind[c.Kind]++
		if c.Vector != nil {
			byClass[c.Vector.Class]++
		}
	}
	printCounts("  by kind", byKind)
	printCounts("  by class", byClass)
}

func printCounts(label string, m map[string]int) {
	fmt.Println(label + ":")
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("    %-18s %d\n", k, m[k])
	}
}

func printSummary(rep *report.Report, dir string) {
	fmt.Println("\n=== Summary ===")
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if c := rep.Summary.BySeverity[s]; c > 0 {
			fmt.Printf("  %-9s %d\n", s, c)
		}
	}
	fmt.Println("  verdicts:")
	for _, v := range []string{"confirmed", "likely", "inconclusive", "false_positive"} {
		if c := rep.Summary.ByVerdict[v]; c > 0 {
			fmt.Printf("    %-15s %d\n", v, c)
		}
	}
	fmt.Printf("\nReports written to %s/ (report.json, findings.jsonl, results.sarif, report.md, report.html, report.junit.xml)\n", dir)
}
