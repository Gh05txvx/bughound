package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"bughound/internal/eval"
)

// runEval runs `bughound eval -findings <file> [-baseline juice-shop]
// [-min-recall N] [-json]`: it scores scan output (an export of GET
// /api/v1/findings, or a JSON array of findings) against a ground-truth
// baseline and prints the recall over the DAST-detectable classes. It works
// offline: it does not scan and does not touch the network, scope, egress or
// secrets.
func runEval(args []string) {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	baseline := fs.String("baseline", "juice-shop", "built-in baseline name, or path to a JSON file")
	findingsPath := fs.String("findings", "", "path to a findings JSON file (an array, or a /api/v1/findings response)")
	minRecall := fs.Float64("min-recall", 0, "fail (exit 1) when required recall is below this value [0..1]; 0 = no gate")
	asJSON := fs.Bool("json", false, "print the result as JSON (instead of a text scorecard)")
	_ = fs.Parse(args)

	if *findingsPath == "" {
		log.Fatalf("eval: -findings <file.json> is required (export it from GET /api/v1/findings?program=...).\n  built-in baselines: %s", strings.Join(eval.BuiltinBaselines(), ", "))
	}
	b, err := eval.LoadBaseline(*baseline, os.ReadFile)
	if err != nil {
		log.Fatalf("eval: load baseline %q: %v", *baseline, err)
	}
	data, err := os.ReadFile(*findingsPath)
	if err != nil {
		log.Fatalf("eval: read findings %q: %v", *findingsPath, err)
	}
	findings, err := eval.ParseFindings(data)
	if err != nil {
		log.Fatalf("eval: parse findings: %v", err)
	}
	res := eval.Score(findings, b)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(res); err != nil {
			log.Fatalf("eval: encode JSON: %v", err)
		}
	} else {
		fmt.Print(res.Report())
	}
	if *minRecall > 0 && res.Recall < *minRecall {
		fmt.Fprintf(os.Stderr, "\nGATE FAILED: required recall %.3f < min %.3f\n", res.Recall, *minRecall)
		os.Exit(1)
	}
}
