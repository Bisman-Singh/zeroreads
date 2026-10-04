//go:build e2e

package e2e

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bisman-Singh/zeroreads/internal/automaton"
	"github.com/Bisman-Singh/zeroreads/internal/usage"
)

// advLanguages are rule languages chosen to be hard: a packed line (Promtail/Alloy pack stage) whose
// service is not declared structured, Unicode case-folding traps, lines with newlines, escapes,
// digraphs and regex metacharacters.
var advLanguages = map[string]string{
	"packed":    `\A\{"_entry":"(?:hello|bye) world","x":"[0-9]"\}\z`,
	"fold":      `\A(?:K|K)elvin (?:ſtate|state) İstanbul (?:ΣΟΦΟΣ|σοφος)\z`,
	"multiline": `\Aline one\nline (?:two|three)\z`,
	"escapes":   `\Apath C:\\temp\\[a-z]{2} "quoted" \\n done\z`,
	"digraph":   `\AǄemal ǅ ǆ (?:ok|OK)\z`,
	"regexy":    `\Ause\[r\] (?:a|b)+ \.\* \(x\)\z`,
}

// TestUsageSoundOnLanguageMembers checks "not used" as the claim it is: about every line a rule
// could remove, not only the lines a generator happened to write. Generated members (and near
// misses) of each language are stored in Loki, and random adversarial queries must never return a
// member of a rule the analyzer calls unused.
func TestUsageSoundOnLanguageMembers(t *testing.T) {
	base := env(t, "LOKI_URL")
	run := fmt.Sprintf("adv%d", time.Now().Unix())
	var rules []usage.Rule
	streams := map[string]map[string]string{}
	lines := map[string][][2]string{}
	var tokens []string
	now := time.Now().Add(-2 * time.Minute)
	n := 0
	names := make([]string, 0, len(advLanguages))
	for k := range advLanguages {
		names = append(names, k)
	}
	sort.Strings(names)
	tr := rand.New(rand.NewPCG(3, 3))
	for _, name := range names {
		lang := advLanguages[name]
		svc := run + "-" + name
		members, err := automaton.Members(lang, 60, 11)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all := append(append([]string(nil), members...), automaton.Near(members[:min(10, len(members))], 3, 12)...)
		streams[svc] = map[string]string{"service_name": svc}
		for _, m := range all {
			if strings.TrimSpace(m) == "" {
				continue // Loki drops empty lines
			}
			n++
			lines[svc] = append(lines[svc], [2]string{strconv.FormatInt(now.UnixNano()+int64(n), 10), m})
		}
		for _, m := range members {
			rs := []rune(m)
			for k := 0; k < 3 && len(rs) > 0; k++ {
				i := tr.IntN(len(rs))
				j := min(len(rs), i+1+tr.IntN(8))
				tokens = append(tokens, string(rs[i:j]))
			}
		}
		rules = append(rules, usage.Rule{ID: name, Scope: map[string]string{"service_name": svc}, Language: automaton.MustCompile(lang)})
	}
	pushLoki(t, base, streams, lines)
	sel := `{service_name=~"` + run + `-.+"}`
	original := map[string][]string{}
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(2 * time.Second) {
		all, _ := lokiQuery(t, base, sel)
		if len(all) == n {
			for _, l := range all {
				original[l.service+"|"+l.ts] = append(original[l.service+"|"+l.ts], l.line)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Loki has %d lines, want %d", len(all), n)
		}
	}
	tokens = append(tokens, "", "_entry", "hello", "K", "k", "ſ", "S", "İ", "i̇", "σ", "ς", "Σ", "ǅ", "ǆ", "\n", "\\n", `\`, `"`, "one\nline", "[r]", ".*", "(x)")
	r := rand.New(rand.NewPCG(5, 5))
	tok := func() string { return tokens[r.IntN(len(tokens))] }
	re := func() string {
		s := regexp.QuoteMeta(tok())
		switch r.IntN(9) {
		case 0:
			return "(?i)" + strings.ToUpper(s)
		case 1:
			return "(?i)" + s
		case 2:
			return "(?m)^" + s + "$"
		case 3:
			return "(?s)" + s + ".*"
		case 4:
			return "()"
		case 5:
			return "^" + s
		case 6:
			return s + "$"
		case 7:
			return "(" + s + "|" + regexp.QuoteMeta(tok()) + ")"
		}
		return s
	}
	stage := func() string {
		switch r.IntN(17) {
		case 0, 1:
			return "|= " + strconv.Quote(tok())
		case 2, 3:
			return "!= " + strconv.Quote(tok())
		case 4:
			return "|~ " + strconv.Quote(re())
		case 5:
			return "!~ " + strconv.Quote(re())
		case 6:
			return `| unpack`
		case 7:
			return `| unpack != "_entry"`
		case 8:
			return `!= ""`
		case 9:
			return `|~ "()"`
		case 10:
			return "|= " + strconv.Quote(tok()) + " or " + strconv.Quote(tok())
		case 11:
			return "!= " + strconv.Quote(tok()) + " or " + strconv.Quote(tok())
		case 12:
			return `| decolorize`
		case 13:
			return `| line_format "{{__line__}}"`
		case 14:
			return `| json`
		case 15:
			// A label filter that keeps nothing: an exact verdict here would be caught below.
			return `| service_name="` + run + `-none"`
		}
		return "!~ " + strconv.Quote(re()) + " or " + strconv.Quote(re())
	}
	queries := envInt("E2E_MEMBER_QUERIES", 600)
	var unused, withMembers, rejected int
	var counts readCounts
	var exact []exactRead
	for i := 0; i < queries; i++ {
		var b strings.Builder
		if r.IntN(3) == 0 {
			b.WriteString(sel)
		} else {
			b.WriteString(`{service_name="` + run + "-" + names[r.IntN(len(names))] + `"}`)
		}
		for k := 1 + r.IntN(3); k > 0; k-- {
			b.WriteString(" " + stage())
		}
		q := b.String()
		got, status := lokiQuery(t, base, q)
		if status != http.StatusOK {
			rejected++
			continue
		}
		verdicts, parsed := readVerdicts(q, rules)
		pred := map[string]bool{}
		for id := range verdicts {
			pred[id] = true
		}
		if !parsed {
			t.Errorf("analyzer could not parse a query Loki accepts: %s", q)
		}
		read := map[string]bool{}
		for _, l := range got {
			for _, o := range original[l.service+"|"+l.ts] {
				for _, ru := range rules {
					if ru.Scope["service_name"] == l.service && ru.Language.Regexp().MatchString(o) {
						read[ru.ID] = true
					}
				}
			}
		}
		if len(read) > 0 {
			withMembers++
		}
		for id := range read {
			if !pred[id] {
				t.Fatalf("UNSOUND: %s\n  Loki returned members of %s, the analyzer says unused", q, id)
			}
		}
		for _, ru := range rules {
			if !pred[ru.ID] {
				unused++
			}
			if v, ok := verdicts[ru.ID]; ok {
				counts.add(v, read[ru.ID])
				if len(v.Widened) == 0 && v.Witness != "" {
					exact = append(exact, exactRead{q, ru.ID, ru.Scope["service_name"], v.Witness})
				}
			}
		}
	}
	t.Logf("over-blocking: %s", counts)
	confirmExactReads(t, base, exact)
	t.Logf("members: %d lines of %d languages, %d queries (%d rejected by Loki), %d returned members, %d proven-unused pairs, 0 unsound",
		n, len(rules), queries, rejected, withMembers, unused)
	if withMembers < queries/5 || unused == 0 {
		t.Fatalf("the test has no teeth: %d queries returned members, %d unused verdicts", withMembers, unused)
	}
}

// exactRead is an exact "reads" verdict: query q reads the lines of rule in stream svc, and witness
// is one of them.
type exactRead struct{ q, rule, svc, witness string }

// confirmExactReads checks the other side of soundness: an exact "reads" verdict must be true. Each
// verdict's witness line is stored in the rule's stream, and the query must return it.
func confirmExactReads(t *testing.T, base string, reads []exactRead) {
	t.Helper()
	if len(reads) == 0 {
		t.Fatal("no exact reads verdict to confirm: the check has no teeth")
	}
	at := time.Now().Add(-30 * time.Second).UnixNano()
	streams := map[string]map[string]string{}
	lines := map[string][][2]string{}
	stamp := map[string]string{} // svc|witness -> timestamp it was stored at
	for i, r := range reads {
		key := r.svc + "|" + r.witness
		if _, done := stamp[key]; done {
			continue
		}
		ts := strconv.FormatInt(at+int64(i), 10)
		stamp[key] = ts
		streams[r.svc] = map[string]string{"service_name": r.svc}
		lines[r.svc] = append(lines[r.svc], [2]string{ts, r.witness})
	}
	pushLoki(t, base, streams, lines)
	time.Sleep(5 * time.Second)
	byQuery := map[string][]int{}
	for i, r := range reads {
		byQuery[r.q] = append(byQuery[r.q], i)
	}
	confirmed := 0
	for q, idx := range byQuery {
		got := map[string]bool{}
		for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(2 * time.Second) {
			rows, status := lokiQuery(t, base, q)
			if status != http.StatusOK {
				t.Fatalf("Loki rejected a query it accepted before (%d): %s", status, q)
			}
			for _, l := range rows {
				got[l.service+"|"+l.ts] = true
			}
			all := true
			for _, i := range idx {
				all = all && got[reads[i].svc+"|"+stamp[reads[i].svc+"|"+reads[i].witness]]
			}
			if all || time.Now().After(deadline) {
				break
			}
		}
		for _, i := range idx {
			r := reads[i]
			if !got[r.svc+"|"+stamp[r.svc+"|"+r.witness]] {
				t.Errorf("OVER-CLAIMED EXACT: %s\n  the analyzer says it reads %s exactly, e.g. %q, but Loki did not return that line", q, r.rule, r.witness)
				continue
			}
			confirmed++
		}
	}
	t.Logf("exact reads verdicts confirmed by Loki: %d of %d (%d distinct queries)", confirmed, len(reads), len(byQuery))
}
