// Command sievelog finds log lines nobody reads, proves it, and emits the collector configuration
// that removes them.
//
//	sievelog analyze -c sievelog.yaml -o out/
//	sievelog emit    -c sievelog.yaml -rules out/rules.json -mode shadow|enforce -o collector.yaml
//	sievelog verify  -c sievelog.yaml -rules out/rules.json [-o revert-rules.json]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/app"
	"github.com/Bisman-Singh/sievelog/internal/emit"
)

const usage = `usage:
  sievelog analyze -c sievelog.yaml -o DIR
  sievelog emit    -c sievelog.yaml -rules RULES.json [-format collector|vector|fluentbit|policy] [-mode shadow|enforce] -o FILE
  sievelog verify  -c sievelog.yaml -rules RULES.json [-o KEEP-RULES.json]
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	code := 0
	switch os.Args[1] {
	case "analyze":
		err = runAnalyze(ctx, os.Args[2:])
	case "emit":
		err = runEmit(os.Args[2:])
	case "verify":
		code, err = runVerify(ctx, os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sievelog:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runAnalyze(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	cfgPath := fs.String("c", "sievelog.yaml", "config file")
	out := fs.String("o", "sievelog-out", "output directory")
	_ = fs.Parse(args)
	cfg, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	rep, err := app.Analyze(ctx, cfg, time.Now())
	if err != nil {
		return err
	}
	if err := app.WriteReport(*out, cfg, rep); err != nil {
		return err
	}
	acted := 0
	for _, r := range rep.Recommendations {
		if r.Action != "none" {
			acted++
		}
	}
	fmt.Printf("%d rules, %d act, %d evidence gaps; wrote %s/report.md, report.json, rules.json\n", len(rep.Recommendations), acted, len(rep.Gaps), *out)
	return nil
}

func runEmit(args []string) error {
	fs := flag.NewFlagSet("emit", flag.ExitOnError)
	cfgPath := fs.String("c", "sievelog.yaml", "config file")
	rulesPath := fs.String("rules", "", "rules.json from analyze")
	mode := fs.String("mode", "shadow", "shadow or enforce (collector format)")
	format := fs.String("format", "collector", "collector (OpenTelemetry Collector config), vector (Vector config), fluentbit (Fluent Bit YAML) or policy (Telemetry Policy JSON)")
	out := fs.String("o", "", "output file (default stdout)")
	_ = fs.Parse(args)
	if *format == "policy" {
		rf, err := app.LoadRules(*rulesPath)
		if err != nil {
			return err
		}
		scratch, err := os.MkdirTemp("", "sievelog-policy")
		if err != nil {
			return err
		}
		defer os.RemoveAll(scratch)
		b, skips, err := app.EmitPolicies(rf, scratch)
		if err != nil {
			return err
		}
		for _, s := range skips {
			fmt.Fprintf(os.Stderr, "not emitted as a policy: %s: %s\n", s.RuleID, s.Reason)
		}
		fmt.Fprintf(os.Stderr, "policies verified against %s\n", emit.PolicyRuntime)
		if *out == "" {
			_, err = os.Stdout.Write(b)
			return err
		}
		return os.WriteFile(*out, b, 0o644)
	}
	if *format != "collector" && *format != "vector" && *format != "fluentbit" {
		return fmt.Errorf("-format must be collector, vector, fluentbit or policy")
	}
	if *mode != string(emit.Shadow) && *mode != string(emit.Enforce) {
		return fmt.Errorf("-mode must be shadow or enforce")
	}
	cfg, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	rf, err := app.LoadRules(*rulesPath)
	if err != nil {
		return err
	}
	emitter := map[string]func(*app.Config, *app.RulesFile, emit.Mode) ([]byte, error){
		"collector": app.EmitCollector, "vector": app.EmitVector, "fluentbit": app.EmitFluentBit}[*format]
	b, err := emitter(cfg, rf, emit.Mode(*mode))
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(*out, b, 0o644)
}

// runVerify exits 3 when any enforced rule is no longer safe.
func runVerify(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cfgPath := fs.String("c", "sievelog.yaml", "config file")
	rulesPath := fs.String("rules", "", "rules.json being enforced")
	out := fs.String("o", "", "write the rules that are still safe here (the revert)")
	_ = fs.Parse(args)
	cfg, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return 0, err
	}
	rf, err := app.LoadRules(*rulesPath)
	if err != nil {
		return 0, err
	}
	res, err := app.Verify(ctx, cfg, rf, time.Now())
	if err != nil {
		return 0, err
	}
	if *out != "" {
		b, _ := json.MarshalIndent(res.Keep, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			return 0, err
		}
	}
	if err := writeStepSummary(res, len(rf.Rules)); err != nil {
		return 0, err
	}
	if len(res.Violations) == 0 {
		fmt.Printf("verify: all %d enforced rules are still safe\n", len(rf.Rules))
		return 0, nil
	}
	for _, v := range res.Violations {
		fmt.Printf("verify: rule %s is no longer safe:\n", v.RuleID)
		for _, r := range v.Reasons {
			fmt.Printf("  - %s\n", r)
		}
	}
	fmt.Printf("verify: %d of %d rules must be reverted; %d remain safe\n", len(res.Violations), len(rf.Rules), len(res.Keep.Rules))
	return 3, nil
}

// writeStepSummary appends the verify result to $GITHUB_STEP_SUMMARY when running in GitHub Actions.
func writeStepSummary(res *app.VerifyResult, total int) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(res.Violations) == 0 {
		_, err = fmt.Fprintf(f, "### sievelog verify\n\nAll %d enforced rules are still safe.\n", total)
		return err
	}
	fmt.Fprintf(f, "### sievelog verify\n\n%d of %d enforced rules are no longer safe.\n\n", len(res.Violations), total)
	for _, v := range res.Violations {
		fmt.Fprintf(f, "- `%s`\n", v.RuleID)
		for _, r := range v.Reasons {
			fmt.Fprintf(f, "  - %s\n", r)
		}
	}
	return nil
}
