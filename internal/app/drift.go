package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Bisman-Singh/zeroreads/internal/emit"
	"github.com/Bisman-Singh/zeroreads/internal/logql"
	"github.com/Bisman-Singh/zeroreads/internal/templating"
)

// DrainConfigHash identifies everything template identity depends on: the embedded drain version,
// the masking rules and the seed templates. Rules made under one hash are re-analysed under another.
func (c *Config) DrainConfigHash() string {
	v, err := templating.DrainVersion()
	if err != nil {
		v = "unknown (" + err.Error() + ")" // matches no real hash, so verify fails closed
	}
	b, _ := json.Marshal(struct {
		Version string
		Masks   any
		Seeds   []string
	}{v, c.Drain.MaskingRules, c.Drain.SeedTemplates})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// templateLanguage is the whole template as drain matches it: <*> is one token, a mask token is
// anything its mask replaced, every other token is literal. It is wider than any rule on the
// template and is only used to measure what the rule no longer covers.
func (c *Config) templateLanguage(tpl string) string {
	masks := map[string]bool{}
	for _, m := range c.Drain.MaskingRules {
		masks["<"+m.Name+">"] = true
	}
	var b strings.Builder
	b.WriteString(`\A`)
	for i, tok := range strings.Split(tpl, " ") {
		if i > 0 {
			b.WriteString(" ")
		}
		if tok == "<*>" {
			b.WriteString(`\S+`)
			continue
		}
		// Masks replace text inside a token too (ip=<ip>), so every mask token is expanded where it
		// occurs; the rest of the token is literal.
		for tok != "" {
			at, name := firstMask(tok, masks)
			if at < 0 {
				b.WriteString(regexp.QuoteMeta(tok))
				break
			}
			b.WriteString(regexp.QuoteMeta(tok[:at]) + `.+`)
			tok = tok[at+len(name):]
		}
	}
	b.WriteString(`\z`)
	return b.String()
}

// firstMask finds the mask token that starts first in tok, and the longest of those starting at the
// same place, so <ip> never cuts <ipv6> short. at is -1 when tok holds none.
func firstMask(tok string, masks map[string]bool) (at int, name string) {
	at = -1
	for m := range masks {
		j := strings.Index(tok, m)
		if j >= 0 && (at < 0 || j < at || (j == at && len(m) > len(name))) {
			at, name = j, m
		}
	}
	return at, name
}

// RuleDrift is how much of a rule's template traffic now falls outside the rule.
type RuleDrift struct {
	RuleID        string   `json:"rule_id"`
	Service       string   `json:"service"`
	Template      string   `json:"template"`
	TemplateLines float64  `json:"template_lines"`    // stored lines of the template in the window
	OutOfRule     float64  `json:"out_of_rule_lines"` // of those, lines the rule does not remove
	Examples      []string `json:"examples,omitempty"`
	Status        string   `json:"status"` // stable | drifting | no-traffic
}

// Drift measures, per rule, the stored lines of its template that its exact language does not
// cover. Such lines pass through untouched, so drift never makes a rule unsafe; it means the rule
// removes less than it did and the template needs re-analysis.
func (c *Config) Drift(ctx context.Context, rf *RulesFile, now time.Time) ([]RuleDrift, error) {
	lc, err := c.lokiClient()
	if err != nil {
		return nil, err
	}
	w := c.Discovery.Window.Duration
	start := now.Add(-w)
	rng := rangeOf(w)
	var out []RuleDrift
	for _, r := range rf.Rules {
		d := RuleDrift{RuleID: r.ID, Service: r.Service, Template: r.Template}
		tl := c.templateLanguage(r.Template)
		inTpl := c.linesIn(r.Service, r.Field, tl)
		outRule := inTpl + " !~ " + logql.Quote(r.Language)
		if r.Field != "" {
			outRule = inTpl + " | zeroreads_field!~" + logql.Quote(r.Language)
		}
		var err error
		if d.TemplateLines, err = c.scalar(ctx, lc, "sum(count_over_time("+inTpl+" "+rng+"))", now); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if d.OutOfRule, err = c.scalar(ctx, lc, "sum(count_over_time("+outRule+" "+rng+"))", now); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		switch {
		case d.OutOfRule > 0:
			d.Status = "drifting"
			ex, err := lc.Sample(ctx, outRule, start, now, 3)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			for _, e := range ex {
				d.Examples = append(d.Examples, e.Line)
			}
		case d.TemplateLines == 0:
			d.Status = "no-traffic"
		default:
			d.Status = "stable"
		}
		out = append(out, d)
	}
	return out, nil
}

// DeployedDiff compares a deployed pipeline configuration with what emit produces for the rules in
// either mode, and returns the paths that differ from the closer one. Empty means it is exactly an
// emitted configuration.
func DeployedDiff(c *Config, rf *RulesFile, deployed []byte) (mode string, diffs []string, err error) {
	var dep any
	if err := yaml.Unmarshal(deployed, &dep); err != nil {
		return "", nil, fmt.Errorf("deployed config: %w", err)
	}
	best := -1
	for _, m := range []emit.Mode{emit.Enforce, emit.Shadow} {
		var want []byte
		switch c.Runtime {
		case "vector":
			want, err = EmitVector(c, rf, m)
		case "fluentbit":
			want, err = EmitFluentBit(c, rf, m)
		default:
			want, err = EmitCollector(c, rf, m)
		}
		if err != nil {
			return "", nil, err
		}
		var w any
		if err := yaml.Unmarshal(want, &w); err != nil {
			return "", nil, err
		}
		var d []string
		diffPaths("", w, dep, &d)
		if best < 0 || len(d) < best {
			best, mode, diffs = len(d), string(m), d
		}
	}
	return mode, diffs, nil
}

func diffPaths(path string, want, got any, out *[]string) {
	wm, wok := want.(map[string]any)
	gm, gok := got.(map[string]any)
	if wok && gok {
		keys := map[string]bool{}
		for k := range wm {
			keys[k] = true
		}
		for k := range gm {
			keys[k] = true
		}
		var ks []string
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			p := k
			if path != "" {
				p = path + "." + k
			}
			wv, win := wm[k]
			gv, gin := gm[k]
			switch {
			case !gin:
				*out = append(*out, p+": missing from the deployed config")
			case !win:
				*out = append(*out, p+": not in the emitted config")
			default:
				diffPaths(p, wv, gv, out)
			}
		}
		return
	}
	if !reflect.DeepEqual(want, got) {
		*out = append(*out, path+": differs")
	}
}
