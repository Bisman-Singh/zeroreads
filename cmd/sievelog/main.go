// Command sievelog finds log lines nobody reads, proves it, and emits the pipeline configuration
// that removes them.
//
//	sievelog analyze   -c sievelog.yaml -o out/
//	sievelog emit      -c sievelog.yaml -rules out/rules.json -format collector|vector|fluentbit|policy -mode shadow|enforce -o FILE
//	sievelog rewrite   -c sievelog.yaml -rules out/rules.json -o DIR [-apply]
//	sievelog verify    -c sievelog.yaml -rules out/rules.json [-o KEEP.json] [-deployed FILE]
//	sievelog reconcile -c sievelog.yaml -rules out/rules.json -before START,END -after START,END
//	sievelog version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/app"
	"github.com/Bisman-Singh/sievelog/internal/emit"
	"github.com/Bisman-Singh/sievelog/internal/templating"
)

const usage = `usage:
  sievelog analyze -c sievelog.yaml -o DIR
  sievelog emit    -c sievelog.yaml -rules RULES.json [-format collector|vector|fluentbit|policy] [-mode shadow|enforce] [-allow-no-severity-guard] -o FILE
  sievelog verify  -c sievelog.yaml -rules RULES.json [-o KEEP-RULES.json] [-deployed PIPELINE.yaml] [-drift=false] [-json OUT.json]
  sievelog rewrite -c sievelog.yaml -rules RULES.json -o DIR [-apply]
  sievelog reconcile -c sievelog.yaml -rules RULES.json -before START,END -after START,END [-tolerance 0.05] [-o OUT.json]
  sievelog version

exit codes: 0 success, 1 error, 2 usage, 3 verify found a rule no longer safe or the deployed
configuration differs, 4 reconcile found a mismatch, 5 rewrite could not rewrite every object
`

// version is the release version, set when the release is built (-X main.version=...).
var version = "dev"

// versionString names the release and what its rules depend on: rules made by one drain version are
// re-analysed under another.
func versionString() string {
	drain, err := templating.DrainVersion()
	if err != nil {
		drain = "unknown"
	}
	return fmt.Sprintf("sievelog %s (drain processor %s, %s)", version, drain, runtime.Version())
}

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
	case "reconcile":
		code, err = runReconcile(ctx, os.Args[2:])
	case "rewrite":
		code, err = runRewrite(ctx, os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(versionString())
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
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
	unguarded := fs.Bool("allow-no-severity-guard", false, "policy format only: emit although the format cannot keep warning and error records out of a rule")
	_ = fs.Parse(args)
	if *format == "policy" {
		// policy-go 1.12.1 treats a negated matcher on an absent field as no match, and the most
		// restrictive policy wins, so "unless the level is warning or worse" cannot be expressed.
		if !*unguarded {
			return fmt.Errorf("the Telemetry Policy format cannot express the severity guard: a warning or error record in a rule's language would be removed; pass -allow-no-severity-guard to emit anyway")
		}
		rf, err := app.LoadRules(*rulesPath)
		if err != nil {
			return err
		}
		scratch, err := os.MkdirTemp("", "sievelog-policy")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(scratch) }() // a leftover temporary directory is harmless
		b, skips, err := app.EmitPolicies(rf, scratch)
		if err != nil {
			return err
		}
		for _, s := range skips {
			fmt.Fprintf(os.Stderr, "not emitted as a policy: %s: %s\n", s.RuleID, s.Reason)
		}
		fmt.Fprintf(os.Stderr, "policies verified against %s\n", emit.PolicyRuntime)
		return writeOutput(*out, b)
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
	return writeOutput(*out, b)
}

// writeOutput writes an emitted runtime configuration to path, or to stdout when path is empty.
func writeOutput(path string, b []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	return app.WriteFile(path, b, app.PrivateFile)
}

// runRewrite exits 5 when any stored query could not be rewritten.
func runRewrite(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("rewrite", flag.ExitOnError)
	cfgPath := fs.String("c", "sievelog.yaml", "config file")
	rulesPath := fs.String("rules", "", "rules.json from analyze")
	out := fs.String("o", "sievelog-rewrites", "directory for the rewritten objects")
	apply := fs.Bool("apply", false, "write the rewritten objects back to Grafana and the Loki ruler")
	_ = fs.Parse(args)
	cfg, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return 0, err
	}
	rf, err := app.LoadRules(*rulesPath)
	if err != nil {
		return 0, err
	}
	res, err := app.Rewrites(ctx, cfg, rf, *out, *apply, time.Now())
	if err != nil {
		return 0, err
	}
	failed := 0
	for _, r := range res {
		state := "written for review"
		switch {
		case r.Err != "":
			state, failed = "FAILED: "+r.Err, failed+1
		case r.Applied && r.Replaced == 0:
			state = "already rewritten"
		case r.Applied:
			state = "applied"
		}
		queries := "queries"
		if r.Replaced == 1 {
			queries = "query"
		}
		fmt.Printf("rewrite %s %s: %d %s replaced, %s (%s)\n", r.Store, r.Target, r.Replaced, queries, state, r.File)
	}
	if *apply && failed == 0 {
		if err := app.SaveRules(*rulesPath, rf); err != nil {
			return 0, err
		}
		fmt.Printf("rewrite: %d objects applied; recorded in %s\n", len(res), *rulesPath)
	}
	if failed > 0 {
		return 5, nil
	}
	return 0, nil
}

// runVerify exits 3 when any enforced rule is no longer safe.
func runVerify(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cfgPath := fs.String("c", "sievelog.yaml", "config file")
	rulesPath := fs.String("rules", "", "rules.json being enforced")
	out := fs.String("o", "", "write the rules that are still safe here (the revert); - prints them after the report")
	deployed := fs.String("deployed", "", "the pipeline config actually deployed, checked against what emit produces")
	drift := fs.Bool("drift", true, "report template traffic each rule no longer covers")
	jsonOut := fs.String("json", "", "write the full verify result as JSON here")
	_ = fs.Parse(args)
	cfg, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return 0, err
	}
	rf, err := app.LoadRules(*rulesPath)
	if err != nil {
		return 0, err
	}
	opt := app.VerifyOptions{Drift: *drift}
	if *deployed != "" {
		if opt.Deployed, err = os.ReadFile(*deployed); err != nil {
			return 0, err
		}
	}
	res, err := app.Verify(ctx, cfg, rf, time.Now(), opt)
	if err != nil {
		return 0, err
	}
	if *out != "" && *out != "-" {
		if err := app.SaveRules(*out, res.Keep); err != nil {
			return 0, err
		}
	}
	if *jsonOut != "" {
		if err := app.WriteJSON(*jsonOut, res, app.SharedFile); err != nil {
			return 0, err
		}
	}
	if err := writeStepSummary(res, len(rf.Rules)); err != nil {
		return 0, err
	}
	for _, d := range res.Drift {
		if d.Status != "drifting" {
			continue
		}
		example := ""
		if len(d.Examples) > 0 { // the sample can come back empty when lines age out between queries
			example = fmt.Sprintf(", e.g. %q", d.Examples[0])
		}
		fmt.Printf("verify: rule %s drifts: %.0f of %.0f stored lines of its template are outside the rule (re-analyse to cover them)%s\n",
			d.RuleID, d.OutOfRule, d.TemplateLines, example)
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
	if *out == "-" {
		// Printed so a scheduled Job keeps it in its log: emit and deploy these rules to revert.
		b, err := json.MarshalIndent(res.Keep, "", "  ")
		if err != nil {
			return 0, err
		}
		fmt.Printf("verify: rules that remain safe (emit and deploy these to revert):\n%s\n", b)
	}
	return 3, nil
}

// writeStepSummary appends the verify result to $GITHUB_STEP_SUMMARY when running in GitHub Actions.
func writeStepSummary(res *app.VerifyResult, total int) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	var b strings.Builder
	if len(res.Violations) == 0 {
		fmt.Fprintf(&b, "### sievelog verify\n\nAll %d enforced rules are still safe.\n", total)
	} else {
		fmt.Fprintf(&b, "### sievelog verify\n\n%d of %d enforced rules are no longer safe.\n\n", len(res.Violations), total)
		for _, v := range res.Violations {
			fmt.Fprintf(&b, "- `%s`\n", v.RuleID)
			for _, r := range v.Reasons {
				fmt.Fprintf(&b, "  - %s\n", r)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, app.PrivateFile)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close() // the write error is the one to report
		return err
	}
	return f.Close()
}

func parseWindow(s string) (app.Window, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return app.Window{}, fmt.Errorf("window %q: want START,END in RFC3339", s)
	}
	a, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return app.Window{}, err
	}
	b, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil {
		return app.Window{}, err
	}
	if !b.After(a) {
		return app.Window{}, fmt.Errorf("window %q ends before it starts", s)
	}
	return app.Window{Start: a, End: b}, nil
}

// runReconcile exits 4 when stored volume does not match what the enforced rules should leave.
func runReconcile(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("reconcile", flag.ExitOnError)
	cfgPath := fs.String("c", "sievelog.yaml", "config file")
	rulesPath := fs.String("rules", "", "rules.json being enforced")
	beforeS := fs.String("before", "", "START,END of a window before enforcement (RFC3339)")
	afterS := fs.String("after", "", "START,END of a window after enforcement (RFC3339)")
	tol := fs.Float64("tolerance", 0.05, "allowed difference of a sample rule's kept share")
	out := fs.String("o", "", "write the result as JSON here")
	_ = fs.Parse(args)
	cfg, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return 0, err
	}
	rf, err := app.LoadRules(*rulesPath)
	if err != nil {
		return 0, err
	}
	before, err := parseWindow(*beforeS)
	if err != nil {
		return 0, err
	}
	after, err := parseWindow(*afterS)
	if err != nil {
		return 0, err
	}
	res, err := app.Reconcile(ctx, cfg, rf, before, after, *tol)
	if err != nil {
		return 0, err
	}
	if *out != "" {
		if err := app.WriteJSON(*out, res, app.SharedFile); err != nil {
			return 0, err
		}
	}
	for _, r := range res.Rules {
		fmt.Printf("reconcile: %s %s (%s): before %.0f lines, after %.0f lines: %s, %s\n", r.RuleID, r.Service, r.Action, r.BeforeLines, r.AfterLines, r.Status, r.Detail)
	}
	for _, s := range res.Services {
		fmt.Printf("reconcile: service %s stored %.0f B/h before, %.0f B/h after\n", s.Service, s.BeforeBytesRate, s.AfterBytesRate)
	}
	if !res.OK {
		return 4, nil
	}
	return 0, nil
}
