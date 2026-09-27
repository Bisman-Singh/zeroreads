package loki

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"

	"go.yaml.in/yaml/v3"
)

// RuleQuery is one ruler rule's expression.
type RuleQuery struct {
	Namespace string
	Group     string
	Name      string // alert name or recorded metric
	Kind      string // alert | record
	Expr      string
}

// noRuleGroups is the body of the ruler's 404 when it has no rules. Any other 404, such as a
// gateway or query frontend that does not route the ruler API, means the rules are unknown.
const noRuleGroups = "no rule groups found"

// Rules lists every rule the Loki ruler evaluates, from GET /loki/api/v1/rules. A ruler with no
// rules answers 404 with "no rule groups found", which is reported as an empty list.
func (c *Client) Rules(ctx context.Context) ([]RuleQuery, error) {
	body, err := c.get(ctx, "/loki/api/v1/rules", url.Values{})
	var he *HTTPError
	if errors.As(err, &he) && he.Status == 404 && he.Body == noRuleGroups {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc map[string][]struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert  string `yaml:"alert"`
			Record string `yaml:"record"`
			Expr   string `yaml:"expr"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("loki: decode rules: %w", err)
	}
	var out []RuleQuery
	for ns, groups := range doc {
		for _, g := range groups {
			for _, r := range g.Rules {
				rq := RuleQuery{Namespace: ns, Group: g.Name, Expr: r.Expr}
				switch {
				case r.Alert != "":
					rq.Kind, rq.Name = "alert", r.Alert
				case r.Record != "":
					rq.Kind, rq.Name = "record", r.Record
				default:
					return nil, fmt.Errorf("loki: rule in %s/%s is neither alert nor record", ns, g.Name)
				}
				out = append(out, rq)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.Name < b.Name
	})
	return out, nil
}
