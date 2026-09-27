package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/fetch"

	"go.yaml.in/yaml/v3"

	"github.com/Bisman-Singh/sievelog/internal/analyze"
)

// RewriteOutcome is what happened to one stored query.
type RewriteOutcome struct {
	Store, Target string
	Replaced      int    // occurrences of the original query replaced in the object
	File          string // the rewritten object, written for review
	Applied       bool
	Err           string `json:",omitempty"`
}

// Rewrites rewrites every stored query the rules' rollups depend on. Each object is read, every
// occurrence of the original query replaced, and the result written to dir. With apply, Grafana
// objects are written back with their version, so a concurrent edit makes the write fail instead of
// being overwritten; Loki ruler groups are written back through the ruler API. rf.RewritesAppliedAt
// is set when every rewrite was applied.
func Rewrites(ctx context.Context, c *Config, rf *RulesFile, dir string, apply bool, now time.Time) ([]RewriteOutcome, error) {
	if err := os.MkdirAll(dir, outputDir); err != nil {
		return nil, err
	}
	// One object can hold several rewritten queries: group by object.
	type object struct {
		store, base, path string
		org               int64
		edits             map[string]string // old -> new
	}
	objs := map[string]*object{}
	var keys []string
	for _, r := range rf.Rules {
		for _, rw := range r.Rewrites {
			if rw.Store == "" {
				continue
			}
			base, path := rw.StoreURL, objectPath(rw)
			k := fmt.Sprintf("%s|%s|%d|%s", rw.Store, base, rw.Org, path)
			o, ok := objs[k]
			if !ok {
				o = &object{store: rw.Store, base: base, path: path, org: rw.Org, edits: map[string]string{}}
				objs[k] = o
				keys = append(keys, k)
			}
			if prev, ok := o.edits[rw.Old]; ok && prev != rw.New {
				return nil, fmt.Errorf("%s %s: two different rewrites of one query", rw.Store, path)
			}
			o.edits[rw.Old] = rw.New
		}
	}
	sort.Strings(keys)
	var out []RewriteOutcome
	all := true
	for i, k := range keys {
		o := objs[k]
		res := RewriteOutcome{Store: o.store, Target: o.path}
		var err error
		switch o.store {
		case "grafana":
			res, err = c.rewriteGrafana(ctx, o.base, o.org, o.path, o.edits, filepath.Join(dir, fmt.Sprintf("%02d-grafana.json", i)), apply)
		case "loki-ruler":
			res, err = c.rewriteRuler(ctx, o.path, o.edits, filepath.Join(dir, fmt.Sprintf("%02d-loki-ruler.yaml", i)), apply)
		default:
			err = fmt.Errorf("store %s cannot be rewritten", o.store)
		}
		res.Store, res.Target = o.store, o.path
		if err != nil {
			res.Err = err.Error()
		}
		if !res.Applied {
			all = false
		}
		out = append(out, res)
	}
	if apply && all {
		rf.RewritesAppliedAt = now.UTC()
	}
	return out, nil
}

// objectPath is the object a stored query lives in: the dashboard, library panel or alert rule, or
// the ruler namespace/group.
func objectPath(rw analyze.Rewrite) string {
	if rw.Store == "loki-ruler" {
		parts := strings.SplitN(rw.Path, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return rw.Path
	}
	return strings.SplitN(rw.Path, "/", 2)[0]
}

// countExprs counts, anywhere in v, the "expr" strings in set.
func countExprs(v any, set map[string]bool) int {
	n := 0
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && k == "expr" && set[s] {
				n++
				continue
			}
			n += countExprs(e, set)
		}
	case []any:
		for _, e := range x {
			n += countExprs(e, set)
		}
	}
	return n
}

func newSet(edits map[string]string) map[string]bool {
	m := map[string]bool{}
	for _, nw := range edits {
		m[nw] = true
	}
	return m
}

// replaceExprs replaces, anywhere in v, every "expr" string equal to an old query.
func replaceExprs(v any, edits map[string]string) (any, int) {
	n := 0
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && k == "expr" {
				if nw, ok := edits[s]; ok {
					x[k] = nw
					n++
				}
				continue
			}
			var m int
			x[k], m = replaceExprs(e, edits)
			n += m
		}
	case []any:
		for i, e := range x {
			var m int
			x[i], m = replaceExprs(e, edits)
			n += m
		}
	}
	return v, n
}

func (c *Config) grafanaAuth(base string) (GrafanaConfig, error) {
	for _, g := range c.Evidence.Grafana {
		if strings.TrimRight(g.URL, "/") == strings.TrimRight(base, "/") {
			return g, nil
		}
	}
	return GrafanaConfig{}, fmt.Errorf("grafana %s is not in the config", base)
}

func (c *Config) grafanaDo(ctx context.Context, base string, org int64, method, path string, body, out any, headers ...string) error {
	g, err := c.grafanaAuth(base)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Grafana-Org-Id", fmt.Sprint(org))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	gc, err := g.client()
	if err != nil {
		return err
	}
	switch {
	case gc.Token != "":
		req.Header.Set("Authorization", "Bearer "+gc.Token)
	case gc.Username != "":
		req.SetBasicAuth(gc.Username, gc.Password)
	}
	res, err := fetch.Do(ctx, &http.Client{Timeout: 60 * time.Second}, req)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("grafana %s %s: HTTP %d: %s", method, path, res.Status, fetch.Excerpt(res.Body))
	}
	if out != nil {
		return json.Unmarshal(res.Body, out)
	}
	return nil
}

func (c *Config) rewriteGrafana(ctx context.Context, base string, org int64, path string, edits map[string]string, file string, apply bool) (RewriteOutcome, error) {
	res := RewriteOutcome{File: file}
	kind, uid, _ := strings.Cut(path, ":")
	var obj map[string]any
	var get, put, method string
	switch kind {
	case "dashboard":
		get = "/api/dashboards/uid/" + url.PathEscape(uid)
	case "librarypanel":
		get = "/api/library-elements/" + url.PathEscape(uid)
		put, method = get, http.MethodPatch
	case "alertrule", "recordingrule":
		get = "/api/v1/provisioning/alert-rules/" + url.PathEscape(uid)
		put, method = get, http.MethodPut
	default:
		return res, fmt.Errorf("%s objects cannot be rewritten", kind)
	}
	if err := c.grafanaDo(ctx, base, org, http.MethodGet, get, nil, &obj); err != nil {
		return res, err
	}
	var body any
	switch kind {
	case "dashboard":
		dash, _ := obj["dashboard"].(map[string]any)
		meta, _ := obj["meta"].(map[string]any)
		_, res.Replaced = replaceExprs(dash, edits)
		body = map[string]any{"dashboard": dash, "folderUid": meta["folderUid"], "overwrite": false,
			"message": "sievelog: rewrite counting queries for rolled-up lines"}
		put, method = "/api/dashboards/db", http.MethodPost
	case "librarypanel":
		r, _ := obj["result"].(map[string]any)
		model := r["model"]
		_, res.Replaced = replaceExprs(model, edits)
		body = map[string]any{"name": r["name"], "model": model, "kind": r["kind"], "version": r["version"], "folderUid": r["folderUid"]}
	default:
		_, res.Replaced = replaceExprs(obj, edits)
		body = obj
	}
	if err := WriteJSON(file, body, SharedFile); err != nil {
		return res, err
	}
	if res.Replaced == 0 {
		if countExprs(body, newSet(edits)) > 0 {
			res.Applied = true // already rewritten by an earlier run
			return res, nil
		}
		return res, fmt.Errorf("the original query is no longer in %s", path)
	}
	if !apply {
		return res, nil
	}
	var headers []string
	if kind == "alertrule" || kind == "recordingrule" {
		// Grafana only accepts an update with the provenance the rule already has: rules created in
		// the UI have none (keep them editable there), API-managed ones "api"; file-provisioned rules
		// cannot be changed through the API at all.
		switch prov, _ := obj["provenance"].(string); prov {
		case "":
			headers = []string{"X-Disable-Provenance", "true"}
		case "api":
		default:
			return res, fmt.Errorf("the rule is provisioned from %s; apply the written rule there", prov)
		}
	}
	if err := c.grafanaDo(ctx, base, org, method, put, body, nil, headers...); err != nil {
		return res, err
	}
	res.Applied = true
	return res, nil
}

func (c *Config) rewriteRuler(ctx context.Context, path string, edits map[string]string, file string, apply bool) (RewriteOutcome, error) {
	res := RewriteOutcome{File: file}
	ns, group, _ := strings.Cut(path, "/")
	lc, err := c.lokiClient()
	if err != nil {
		return res, err
	}
	raw, err := lc.RuleNamespace(ctx, ns)
	if err != nil {
		return res, err
	}
	var doc struct {
		Groups []map[string]any `yaml:"groups"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return res, err
	}
	var target map[string]any
	for _, g := range doc.Groups {
		if g["name"] == group {
			target = g
		}
	}
	if target == nil {
		return res, fmt.Errorf("no rule group %s in namespace %s", group, ns)
	}
	_, res.Replaced = replaceExprs(target, edits)
	// The whole namespace file, as a ruler with local storage reads it.
	out, err := yaml.Marshal(map[string]any{"groups": doc.Groups})
	if err != nil {
		return res, err
	}
	if err := WriteFile(file, out, SharedFile); err != nil {
		return res, err
	}
	if res.Replaced == 0 {
		if countExprs(target, newSet(edits)) > 0 {
			res.Applied = true
			return res, nil
		}
		return res, fmt.Errorf("the original query is no longer in %s", path)
	}
	if !apply {
		return res, nil
	}
	g, err := yaml.Marshal(target)
	if err != nil {
		return res, err
	}
	if err := lc.SetRuleGroup(ctx, ns, g); err != nil {
		return res, fmt.Errorf("the ruler did not accept the group (%v); a ruler reading local files needs the written file put in place of namespace %s", err, ns)
	}
	res.Applied = true
	return res, nil
}
