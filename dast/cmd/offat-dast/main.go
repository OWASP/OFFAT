// Command offat-dast is the OpenAPI-driven black-box DAST engine of OFFAT-AI.
// It parses a Swagger/OpenAPI spec, maps parameters into a dataflow graph,
// generates attack vectors dynamically from the knowledge base, executes them
// against a live target, and triages the findings (AI-assisted) into reports.
package main

import (
	"os"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
