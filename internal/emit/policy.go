package emit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/usetero/policy-go/backend/teroscan"
	"github.com/usetero/policy-go/policy"

	"github.com/Bisman-Singh/sievelog/internal/automaton"
)

// PolicySkip is a rule that is not written as a Telemetry Policy, and why.
type PolicySkip struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

type policyFile struct {
	Policies []policyDoc `json:"policies"`
}

type policyDoc struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Enabled bool      `json:"enabled"`
	Log     policyLog `json:"log"`
}

type policyLog struct {
	Match []map[string]any `json:"match"`
	Keep  string           `json:"keep"`
}

// PolicyRuntime names the engine every emitted policy was checked against.
const PolicyRuntime = "policy-go/policy v1.12.1 with backend/teroscan v1.10.3"

// Policies writes the rules as Telemetry Policies in the JSON file format policy-go loads. Only
// rules the format can express exactly are written: drop and sample on a plain body. Every written
// policy is checked against the real policy-go engine on members of the rule's language and on
// near misses; a policy the engine would apply to a different set of lines is left out.
func Policies(rules []Rule, dir string) ([]byte, []PolicySkip, error) {
	if err := CheckDisjoint(rules); err != nil {
		return nil, nil, err
	}
	var pf policyFile
	var skips []PolicySkip
	var kept []Rule
	for _, r := range rules {
		keep := ""
		switch {
		case r.Field != "":
			skips = append(skips, PolicySkip{r.ID, "matching one field of a structured body is not expressible in the policy format"})
			continue
		case r.Action == "drop":
			keep = "none"
		case r.Action == "sample":
			keep = strconv.Itoa(r.Keep) + "%"
		default:
			skips = append(skips, PolicySkip{r.ID, "action " + r.Action + " has no equivalent in the policy format"})
			continue
		}
		pf.Policies = append(pf.Policies, policyDoc{
			ID: r.ID, Name: "sievelog " + r.ID, Enabled: true,
			Log: policyLog{Keep: keep, Match: []map[string]any{
				{"resource_attribute": map[string]any{"path": []string{r.ScopeAttr}}, "equals": r.ScopeValue},
				{"log_field": "body", "regex": r.Language},
			}},
		})
		kept = append(kept, r)
	}
	b, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	// Differential check with the real engine; drop any policy it disagrees on and re-check.
	bad, err := checkPolicies(b, kept, dir)
	if err != nil {
		return nil, nil, err
	}
	if len(bad) == 0 {
		return b, skips, nil
	}
	var ok []Rule
	for _, r := range kept {
		if why, isBad := bad[r.ID]; isBad {
			skips = append(skips, PolicySkip{r.ID, why})
			continue
		}
		ok = append(ok, r)
	}
	out, more, err := Policies(ok, dir)
	return out, append(skips, more...), err
}

type testRecord struct {
	service string
	body    string
}

// checkPolicies loads the policy file into policy-go and compares, for every rule, which strings the
// engine matches with which strings the rule's language matches.
func checkPolicies(doc []byte, rules []Rule, dir string) (map[string]string, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	path := filepath.Join(dir, "policies-under-test.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(path)
	reg := policy.NewPolicyRegistry(policy.WithRegexBackend(teroscan.New()))
	prov := policy.NewFileProvider(path)
	defer prov.Stop()
	h, err := reg.Register(prov)
	if err != nil {
		return nil, fmt.Errorf("policy-go rejected the emitted policies: %w", err)
	}
	defer h.Unregister()
	eng := policy.NewPolicyEngine(reg)
	value := func(rec *testRecord, ref policy.LogFieldRef) policy.TypedValue {
		if ref.IsField() && ref.Field == policy.LogFieldBody {
			return policy.TypedValueOfString(rec.body)
		}
		if ref.IsResourceAttr() && len(ref.AttrPath) == 1 && ref.AttrPath[0] == rules[0].ScopeAttr {
			return policy.TypedValueOfString(rec.service)
		}
		return policy.TypedValue{}
	}
	exists := func(rec *testRecord, ref policy.LogFieldRef) bool {
		return value(rec, ref).Kind != policy.TypedValueAbsent
	}
	bad := map[string]string{}
	for i, r := range rules {
		re := regexp.MustCompile(r.Language)
		members, err := automaton.Members(r.Language, 60, uint64(i)+1)
		if err != nil {
			return nil, err
		}
		cases := append(members, automaton.Near(members, 6, uint64(i)+7)...)
		for _, s := range cases {
			want := re.MatchString(s)
			for _, svc := range []string{r.ScopeValue, r.ScopeValue + "-other"} {
				res := policy.EvaluateLog(eng, &testRecord{service: svc, body: s},
					policy.WithLogTypedValue(value), policy.WithLogExists(exists))
				matched := res != policy.ResultNoMatch
				expect := want && svc == r.ScopeValue
				if matched != expect {
					bad[r.ID] = fmt.Sprintf("%s decides %q in service %q as matched=%v, the rule's language says %v", PolicyRuntime, s, svc, matched, expect)
					break
				}
			}
			if _, isBad := bad[r.ID]; isBad {
				break
			}
		}
	}
	return bad, nil
}
