package emit

import (
	"fmt"
	"maps"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Bisman-Singh/sievelog/internal/dialect"
	"github.com/Bisman-Singh/sievelog/internal/topology"
)

// FluentBitTarget is where in a Fluent Bit YAML configuration rules are enforced.
type FluentBitTarget struct {
	Match      string              // tag pattern of the records the rules apply to, e.g. kube.*
	After      string              // alias of the filter after which rules run; "" means first
	ScopeKey   string              // record accessor of the scope value, e.g. service or $kubernetes['container_name']
	TextKey    []string            // path of the plain text, e.g. [log]
	FieldKeys  map[string][]string // service -> path of the templated field of structured records
	MetricsTag string              // tag of the measurement metrics; outputs matching it receive them
	// SeverityKeys are record paths of level fields; a record at warning or above in any of them
	// never matches a rule. They are checked in addition to the default level fields at the top level
	// and beside every structured field.
	SeverityKeys [][]string
}

func (t FluentBitTarget) severityKeys() [][]string {
	parents := [][]string{nil}
	for _, svc := range slices.Sorted(maps.Keys(t.FieldKeys)) {
		if fk := t.FieldKeys[svc]; len(fk) > 1 {
			parents = append(parents, fk[:len(fk)-1])
		}
	}
	var defaults [][]string
	for _, parent := range parents {
		for _, k := range defaultSeverityKeys() {
			defaults = append(defaults, append(append([]string(nil), parent...), k))
		}
	}
	return withDefaults(defaults, t.SeverityKeys, func(p []string) string { return strings.Join(p, "\x00") })
}

// FluentBitSampleThreshold is the integer below which the first 13 hex digits of the SHA-256 of a
// line's sample key must fall for the line to be kept. 13 digits (52 bits) keep the comparison exact
// in LuaJIT's doubles.
func FluentBitSampleThreshold(keep int) int64 {
	span := new(big.Int).Lsh(big.NewInt(1), 52)
	k := new(big.Int).Mul(span, big.NewInt(int64(keep)))
	return k.Div(k, big.NewInt(100)).Int64()
}

func accessor(path []string) string {
	if len(path) == 1 {
		return path[0]
	}
	var b strings.Builder
	b.WriteString("$" + path[0])
	for _, p := range path[1:] {
		b.WriteString("['" + p + "']")
	}
	return b.String()
}

func metricName(prefix, id string) string {
	return prefix + "_" + strings.NewReplacer("-", "_").Replace(id)
}

// FluentBit returns the user's Fluent Bit YAML configuration with the rules wired in.
func FluentBit(files [][]byte, t FluentBitTarget, rules []Rule, mode Mode) ([]byte, error) {
	if err := CheckRules(rules); err != nil {
		return nil, err
	}
	if t.Match == "" || t.ScopeKey == "" || len(t.TextKey) == 0 || t.MetricsTag == "" {
		return nil, fmt.Errorf("emit: fluent bit target needs match, scope key, text key and a metrics tag")
	}
	cfg, err := topology.MergeFiles("fluent bit", files)
	if err != nil {
		return nil, err
	}
	pipeline := child(cfg, "pipeline")
	filters, _ := pipeline["filters"].([]any)
	pos := 0
	if t.After != "" {
		pos = -1
		for i, f := range filters {
			if fm, _ := f.(map[string]any); property(fm, "alias") == t.After {
				pos = i + 1
			}
		}
		if pos < 0 {
			return nil, fmt.Errorf("emit: no filter with alias %s", t.After)
		}
	}
	for _, f := range filters {
		if fm, _ := f.(map[string]any); strings.HasPrefix(fmt.Sprint(property(fm, "alias")), "sievelog_") {
			return nil, fmt.Errorf("emit: the configuration already has sievelog filters")
		}
	}
	pathOf := func(r Rule) ([]string, error) {
		if r.Field == "" {
			return t.TextKey, nil
		}
		p, ok := t.FieldKeys[r.ScopeValue]
		if !ok {
			return nil, fmt.Errorf("emit: no fluent bit field path for structured service %s", r.ScopeValue)
		}
		return p, nil
	}
	var added []any
	for _, r := range rules {
		if (r.Action == "dedupe" || r.Action == "rollup") && mode == Enforce {
			return nil, fmt.Errorf("emit: rule %s: Fluent Bit cannot enforce %s, which keeps a count of the removed lines; re-run analyze for runtime fluentbit", r.ID, r.Action)
		}
		path, err := pathOf(r)
		if err != nil {
			return nil, err
		}
		pat, err := dialect.Onigmo(r.Language)
		if err != nil {
			return nil, err
		}
		scope, err := dialect.Onigmo(`\A` + regexp.QuoteMeta(r.ScopeValue) + `\z`)
		if err != nil {
			return nil, err
		}
		added = append(added, map[string]any{
			"name": "modify", "alias": "sievelog_tag_" + strings.ReplaceAll(r.ID, "-", "_"), "match": t.Match,
			"condition": []any{"Key_value_matches " + t.ScopeKey + " " + scope, "Key_value_matches " + accessor(path) + " " + pat},
			"add":       "sievelog_rule " + r.ID,
		})
	}
	// A record whose level says warning or worse loses its rule tag before anything counts or removes
	// it (modify conditions only combine with AND, so this is its own filter per level field).
	severe, err := dialect.Onigmo(SeverePattern)
	if err != nil {
		return nil, err
	}
	for i, k := range t.severityKeys() {
		added = append(added, map[string]any{
			"name": "modify", "alias": fmt.Sprintf("sievelog_severe_%d", i), "match": t.Match,
			"condition": []any{"Key_value_matches " + accessor(k) + " " + severe},
			"remove":    "sievelog_rule",
		})
	}
	for _, r := range rules {
		idPat, err := dialect.Onigmo(`\A` + regexp.QuoteMeta(r.ID) + `\z`)
		if err != nil {
			return nil, err
		}
		added = append(added, map[string]any{
			"name": "log_to_metrics", "alias": "sievelog_measure_" + strings.ReplaceAll(r.ID, "-", "_"), "match": t.Match,
			"tag": t.MetricsTag, "metric_mode": "counter", "metric_name": metricName("sievelog_rule_lines", r.ID),
			"metric_description": "lines matching rule " + r.ID, "regex": "sievelog_rule " + idPat, "discard_logs": false,
		})
		if r.Action == "aggregate" && mode == Enforce {
			added = append(added, map[string]any{
				"name": "log_to_metrics", "alias": "sievelog_aggregate_" + strings.ReplaceAll(r.ID, "-", "_"), "match": t.Match,
				"tag": t.MetricsTag, "metric_mode": "counter", "metric_name": metricName("sievelog_aggregate_lines", r.ID),
				"metric_description": "lines replaced by this counter, rule " + r.ID, "regex": "sievelog_rule " + idPat, "discard_logs": false,
			})
		}
	}
	if mode == Enforce {
		var dropIDs []string
		thresholds := map[string]int64{}
		paths := map[string][]string{}
		for _, r := range rules {
			switch r.Action {
			case "drop", "aggregate":
				dropIDs = append(dropIDs, regexp.QuoteMeta(r.ID))
			case "sample":
				thresholds[r.ID] = FluentBitSampleThreshold(r.Keep)
				paths[r.ID], _ = pathOf(r)
			}
		}
		if len(dropIDs) > 0 {
			ids, err := dialect.Onigmo(`\A(?:` + strings.Join(dropIDs, "|") + `)\z`)
			if err != nil {
				return nil, err
			}
			added = append(added, map[string]any{"name": "grep", "alias": "sievelog_drop", "match": t.Match, "exclude": "sievelog_rule " + ids})
		}
		if len(thresholds) > 0 {
			added = append(added, map[string]any{"name": "lua", "alias": "sievelog_sample", "match": t.Match, "call": "sievelog_sample",
				"time_as_table": true, "protected_mode": true, "code": sampleLua(thresholds, paths)})
		}
	}
	added = append(added, map[string]any{"name": "modify", "alias": "sievelog_clean", "match": t.Match, "remove": "sievelog_rule"})
	out := append(append(append([]any(nil), filters[:pos]...), added...), filters[pos:]...)
	pipeline["filters"] = out
	return yaml.Marshal(cfg)
}

// property reads a plugin property: Fluent Bit matches property names case-insensitively.
func property(m map[string]any, name string) any {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// sampleLua is a pure LuaJIT SHA-256 plus the per-rule sampling decision.
func sampleLua(thresholds map[string]int64, paths map[string][]string) string {
	var ids []string
	for id := range thresholds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var th, ps strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&th, "  [%q] = %d,\n", id, thresholds[id])
		var q []string
		for _, p := range paths[id] {
			q = append(q, strconv.Quote(p))
		}
		fmt.Fprintf(&ps, "  [%q] = {%s},\n", id, strings.Join(q, ", "))
	}
	return luaSHA256 + "\nlocal sievelog_thresholds = {\n" + th.String() + "}\nlocal sievelog_paths = {\n" + ps.String() + "}\n" + luaSample
}

const luaSHA256 = `local bit = require("bit")
local band, bor, bxor, bnot, rshift, lshift, ror, tobit, tohex = bit.band, bit.bor, bit.bxor, bit.bnot, bit.rshift, bit.lshift, bit.ror, bit.tobit, bit.tohex
local K = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}
local function sha256(msg)
  local len = #msg
  local bitlen_hi = math.floor(len / 0x20000000)
  local bitlen_lo = (len % 0x20000000) * 8
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64) ..
    string.char(band(rshift(bitlen_hi, 24), 255), band(rshift(bitlen_hi, 16), 255), band(rshift(bitlen_hi, 8), 255), band(bitlen_hi, 255),
                band(rshift(bitlen_lo, 24), 255), band(rshift(bitlen_lo, 16), 255), band(rshift(bitlen_lo, 8), 255), band(bitlen_lo, 255))
  local h0,h1,h2,h3,h4,h5,h6,h7 = 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  local w = {}
  for chunk = 1, #msg, 64 do
    for i = 0, 15 do
      local a, b, c, d = string.byte(msg, chunk + i * 4, chunk + i * 4 + 3)
      w[i] = tobit(bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d))
    end
    for i = 16, 63 do
      local s0 = bxor(ror(w[i-15], 7), ror(w[i-15], 18), rshift(w[i-15], 3))
      local s1 = bxor(ror(w[i-2], 17), ror(w[i-2], 19), rshift(w[i-2], 10))
      w[i] = tobit(w[i-16] + s0 + w[i-7] + s1)
    end
    local a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
    for i = 0, 63 do
      local S1 = bxor(ror(e, 6), ror(e, 11), ror(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = tobit(h + S1 + ch + K[i+1] + w[i])
      local S0 = bxor(ror(a, 2), ror(a, 13), ror(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = tobit(S0 + maj)
      h, g, f, e, d, c, b, a = g, f, e, tobit(d + t1), c, b, a, tobit(t1 + t2)
    end
    h0,h1,h2,h3 = tobit(h0+a), tobit(h1+b), tobit(h2+c), tobit(h3+d)
    h4,h5,h6,h7 = tobit(h4+e), tobit(h5+f), tobit(h6+g), tobit(h7+h)
  end
  return tohex(h0)..tohex(h1)..tohex(h2)..tohex(h3)..tohex(h4)..tohex(h5)..tohex(h6)..tohex(h7)
end
`

const luaSample = `function sievelog_sample(tag, ts, record)
  local id = record["sievelog_rule"]
  local t = id and sievelog_thresholds[id]
  if t == nil then return 0, ts, record end
  local v = record
  for _, k in ipairs(sievelog_paths[id]) do
    if type(v) ~= "table" then v = nil break end
    v = v[k]
  end
  if type(v) ~= "string" then return 0, ts, record end
  local key = v .. "|" .. string.format("%d%09d", ts.sec, ts.nsec)
  if tonumber(string.sub(sha256(key), 1, 13), 16) >= t then return -1, ts, record end
  return 0, ts, record
end
`
