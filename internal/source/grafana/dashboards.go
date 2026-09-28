package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"sort"
	"time"
)

type k8sDashboard struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec   map[string]any `json:"spec"`
	Status struct {
		Conversion *struct {
			Failed        bool   `json:"failed"`
			StoredVersion string `json:"storedVersion"`
			Error         string `json:"error"`
		} `json:"conversion"`
	} `json:"status"`
}

// dashboards reads every dashboard in both the classic (v1) and the v2 schema. Grafana converts on
// read and reports conversion failures; a dashboard is parsed in every version that converted, and
// is a gap only when no version did.
//
// Grafana 13.2.2's dashboard list sometimes answers with no items and a success status right after
// writes (reproduced: 0 listed, 357 found by search, 3 seconds after an import). So every dashboard
// the search API knows must be listed: the list is retried while any is missing, the rest are read
// one by one, and one that cannot be read is a gap.
func (r *orgReader) dashboards(ctx context.Context) {
	r.loadLibraries(ctx)
	want, err := r.searchDashboards(ctx)
	if err != nil {
		r.gap("dashboards/search", "list: %v", err) // nothing to check the list against
	}
	listed := map[string]map[string]k8sDashboard{"v1": {}, "v2": {}}
	listErr := map[string]error{}
	for attempt := 0; ; attempt++ {
		for _, v := range []string{"v1", "v2"} {
			if err := r.listDashboards(ctx, v, listed[v]); err != nil {
				if len(listed[v]) == 0 {
					listErr[v] = err
				}
				continue
			}
			delete(listErr, v)
		}
		missing := unlisted(want, listed)
		if len(missing) == 0 || attempt == 3 || !sleepCtx(ctx, time.Duration(attempt+1)*500*time.Millisecond) {
			r.readUnlisted(ctx, missing, listed["v1"])
			break
		}
	}
	for _, v := range slices.Sorted(maps.Keys(listErr)) {
		r.gap("dashboards/"+v, "list: %v", listErr[v])
	}
	parsed := map[string]bool{}
	failed := map[string]string{}
	for _, v := range []string{"v1", "v2"} {
		for _, name := range slices.Sorted(maps.Keys(listed[v])) {
			d := listed[v][name]
			if d.Status.Conversion != nil && d.Status.Conversion.Failed {
				failed[name] = fmt.Sprintf("%s conversion failed: %s", v, d.Status.Conversion.Error)
				continue
			}
			if v == "v1" {
				r.classicDashboard(name, d.Spec)
			} else {
				r.v2Dashboard(name, d.Spec)
			}
			parsed[name] = true
		}
	}
	for name, why := range failed {
		if !parsed[name] {
			r.gap("dashboard:"+name, "%s", why)
		}
	}
}

// listDashboards adds every dashboard one schema version lists to into.
func (r *orgReader) listDashboards(ctx context.Context, version string, into map[string]k8sDashboard) error {
	items, err := r.listK8s(ctx, "dashboard.grafana.app", version, "dashboards")
	if err != nil {
		return err
	}
	for _, raw := range items {
		var d k8sDashboard
		if err := json.Unmarshal(raw, &d); err != nil {
			r.gap("dashboards/"+version, "decode: %v", err)
			continue
		}
		into[d.Metadata.Name] = d
	}
	return nil
}

// readUnlisted reads, one by one, dashboards the search API found but no list returned; one that
// cannot be read is a gap.
func (r *orgReader) readUnlisted(ctx context.Context, uids []string, into map[string]k8sDashboard) {
	for _, uid := range uids {
		var d k8sDashboard
		path := fmt.Sprintf("/apis/dashboard.grafana.app/v1/namespaces/%s/dashboards/%s", namespace(r.org), url.PathEscape(uid))
		if err := r.c.do(ctx, r.org, path, &d); err != nil {
			r.gap("dashboard:"+uid, "found by search but not listed, and reading it failed: %v", err)
			continue
		}
		into[uid] = d
	}
}

// searchDashboards returns the UID of every dashboard the search API finds in the org.
func (r *orgReader) searchDashboards(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	const perPage = 5000
	for page := 1; ; page++ {
		var hits []struct {
			UID string `json:"uid"`
		}
		if err := r.c.do(ctx, r.org, fmt.Sprintf("/api/search?type=dash-db&limit=%d&page=%d", perPage, page), &hits); err != nil {
			return out, err
		}
		for _, h := range hits {
			out[h.UID] = true
		}
		if len(hits) < perPage {
			return out, nil
		}
	}
}

// unlisted is every searched dashboard that no schema version listed, sorted.
func unlisted(want map[string]bool, listed map[string]map[string]k8sDashboard) []string {
	var out []string
	for uid := range want {
		if _, v1 := listed["v1"][uid]; !v1 {
			if _, v2 := listed["v2"][uid]; !v2 {
				out = append(out, uid)
			}
		}
	}
	sort.Strings(out)
	return out
}

// sleepCtx waits d unless ctx ends first, and reports whether it waited.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// classicDashboard walks the classic JSON model.
func (r *orgReader) classicDashboard(uid string, spec map[string]any) {
	origin := "dashboard:" + uid
	r.dsVars = map[string]string{}
	if tm, ok := spec["templating"].(map[string]any); ok {
		list, _ := tm["list"].([]any)
		for _, v := range list {
			vm, _ := v.(map[string]any)
			name, _ := vm["name"].(string)
			if typ, _ := vm["type"].(string); typ == "datasource" && name != "" {
				r.dsVars[name], _ = vm["query"].(string)
			}
		}
	}
	if ann, ok := spec["annotations"].(map[string]any); ok {
		list, _ := ann["list"].([]any)
		for i, a := range list {
			am, _ := a.(map[string]any)
			if am == nil {
				continue
			}
			ds, _ := r.resolve(am["datasource"])
			expr, _ := am["expr"].(string)
			if t, ok := am["target"].(map[string]any); ok {
				if e, ok := t["expr"].(string); ok && e != "" {
					expr = e
				}
			}
			enabled, hasEnable := am["enable"].(bool)
			r.add(fmt.Sprintf("%s/annotation:%d", origin, i), ds, expr, hasEnable && !enabled)
		}
	}
	panels, _ := spec["panels"].([]any)
	r.classicPanels(origin, panels)
}

func (r *orgReader) classicPanels(origin string, panels []any) {
	for _, p := range panels {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		id := fmt.Sprint(pm["id"])
		if nested, ok := pm["panels"].([]any); ok { // collapsed rows keep their panels here
			r.classicPanels(origin, nested)
		}
		if lp, ok := pm["libraryPanel"].(map[string]any); ok {
			uid, _ := lp["uid"].(string)
			if !r.libraries[uid] {
				r.note(origin+"/panel:"+id, "library panel %q does not exist, so the panel reads nothing", uid)
			}
			continue // the library panel's own queries are read from the library
		}
		panelDS, panelInherits := r.resolve(pm["datasource"])
		if panelInherits && len(panelDS) == 0 {
			panelDS = r.defaultLoki()
		}
		targets, _ := pm["targets"].([]any)
		for _, t := range targets {
			tm, _ := t.(map[string]any)
			if tm == nil {
				continue
			}
			expr, _ := tm["expr"].(string)
			ds, inherit := r.resolve(tm["datasource"])
			if inherit {
				ds = panelDS
			}
			hidden, _ := tm["hide"].(bool)
			r.add(fmt.Sprintf("%s/panel:%s/%v", origin, id, tm["refId"]), ds, expr, hidden)
		}
	}
}

// v2Dashboard walks the v2 schema: elements, and annotations.
func (r *orgReader) v2Dashboard(uid string, spec map[string]any) {
	origin := "dashboard:" + uid
	r.dsVars = map[string]string{}
	vars, _ := spec["variables"].([]any)
	for _, v := range vars {
		vm, _ := v.(map[string]any)
		vs, _ := vm["spec"].(map[string]any)
		name, _ := vs["name"].(string)
		if kind, _ := vm["kind"].(string); kind == "DatasourceVariable" && name != "" {
			r.dsVars[name], _ = vs["pluginId"].(string)
		}
	}
	if anns, ok := spec["annotations"].([]any); ok {
		for i, a := range anns {
			am, _ := a.(map[string]any)
			s, _ := am["spec"].(map[string]any)
			if s == nil {
				continue
			}
			q, _ := s["query"].(map[string]any)
			ds, expr := r.v2Query(q)
			enabled, hasEnable := s["enable"].(bool)
			r.add(fmt.Sprintf("%s/annotation:%d", origin, i), ds, expr, hasEnable && !enabled)
		}
	}
	elements, _ := spec["elements"].(map[string]any)
	for key, e := range elements {
		em, _ := e.(map[string]any)
		kind, _ := em["kind"].(string)
		es, _ := em["spec"].(map[string]any)
		switch kind {
		case "LibraryPanel":
			lp, _ := es["libraryPanel"].(map[string]any)
			uid, _ := lp["uid"].(string)
			if !r.libraries[uid] {
				r.note(origin+"/"+key, "library panel %q does not exist, so the panel reads nothing", uid)
			}
		case "Panel":
			data, _ := es["data"].(map[string]any)
			dataSpec, _ := data["spec"].(map[string]any)
			queries, _ := dataSpec["queries"].([]any)
			for i, q := range queries {
				qm, _ := q.(map[string]any)
				qs, _ := qm["spec"].(map[string]any)
				inner, _ := qs["query"].(map[string]any)
				uids, expr := r.v2Query(inner)
				hidden, _ := qs["hidden"].(bool)
				r.add(fmt.Sprintf("%s/%s/%d", origin, key, i), uids, expr, hidden)
			}
		default:
			r.gap(origin+"/"+key, "unknown element kind %q", kind)
		}
	}
}

// v2Query resolves a v2 DataQuery: group is the datasource type, datasource.name the UID.
func (r *orgReader) v2Query(q map[string]any) ([]string, string) {
	if q == nil {
		return nil, ""
	}
	group, _ := q["group"].(string)
	var uid string
	if ds, ok := q["datasource"].(map[string]any); ok {
		uid, _ = ds["name"].(string)
	}
	spec, _ := q["spec"].(map[string]any)
	expr, _ := spec["expr"].(string)
	if group != "loki" && !isVariable(group) {
		return nil, ""
	}
	uids, _ := r.resolve(map[string]any{"uid": uid, "type": "loki"})
	return uids, expr
}
