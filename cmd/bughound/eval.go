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

// runEval menjalankan `bughound eval -findings <file> [-baseline juice-shop]
// [-min-recall N] [-json]`: menilai keluaran scan (ekspor GET /api/v1/findings
// atau array JSON temuan) terhadap baseline ground-truth, lalu mencetak recall
// atas kelas DAST-detectable. Murni offline — tak memindai & tak menyentuh
// jaringan/scope/egress/secret.
func runEval(args []string) {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	baseline := fs.String("baseline", "juice-shop", "nama baseline bawaan atau path berkas JSON")
	findingsPath := fs.String("findings", "", "path berkas JSON temuan (array, atau respons /api/v1/findings)")
	minRecall := fs.Float64("min-recall", 0, "gagal (exit 1) bila recall wajib < nilai ini [0..1]; 0 = tanpa gate")
	asJSON := fs.Bool("json", false, "cetak hasil sebagai JSON (bukan kartu-skor teks)")
	_ = fs.Parse(args)

	if *findingsPath == "" {
		log.Fatalf("eval: butuh -findings <file.json> (ekspor dari GET /api/v1/findings?program=...).\n  baseline bawaan: %s", strings.Join(eval.BuiltinBaselines(), ", "))
	}
	b, err := eval.LoadBaseline(*baseline, os.ReadFile)
	if err != nil {
		log.Fatalf("eval: muat baseline %q: %v", *baseline, err)
	}
	data, err := os.ReadFile(*findingsPath)
	if err != nil {
		log.Fatalf("eval: baca temuan %q: %v", *findingsPath, err)
	}
	findings, err := eval.ParseFindings(data)
	if err != nil {
		log.Fatalf("eval: parse temuan: %v", err)
	}
	res := eval.Score(findings, b)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(res); err != nil {
			log.Fatalf("eval: enkode JSON: %v", err)
		}
	} else {
		fmt.Print(res.Report())
	}
	if *minRecall > 0 && res.Recall < *minRecall {
		fmt.Fprintf(os.Stderr, "\nGATE GAGAL: recall wajib %.3f < min %.3f\n", res.Recall, *minRecall)
		os.Exit(1)
	}
}
