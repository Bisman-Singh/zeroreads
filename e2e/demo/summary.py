"""Summarises one demo run from the files run.sh leaves in its work directory: what analysis decided,
what shadow mode measured the rules would remove, what enforcement changed in Loki, and whether
reconcile and verify agree. Writes results.json and prints results.md.

Usage: summary.py WORK_DIR
"""
import json
import os
import sys

work = sys.argv[1]
rep = json.load(open(os.path.join(work, "out", "report.json")))
rules = {r["ID"]: r for r in json.load(open(os.path.join(work, "out", "rules.json")))["rules"]}
totals = json.load(open(os.path.join(work, "totals.json")))
recon = json.load(open(os.path.join(work, "reconcile.json")))
verify_exit = int(open(os.path.join(work, "verify.exit")).read().strip())

# Shadow measurement: the Collector's per-rule delta sums, written by its file exporter from the start
# of the shadow window (the Collector restarted then) to its end.
lines, nbytes = {}, {}
for l in open(os.path.join(work, "metrics-shadow.json")):
    try:
        doc = json.loads(l)
    except ValueError:
        continue  # a line still being written
    for rm in doc.get("resourceMetrics", []):
        for sm in rm.get("scopeMetrics", []):
            for m in sm.get("metrics", []):
                name = m.get("name", "")
                for kind, into in (("sievelog.rule.lines.", lines), ("sievelog.rule.bytes.", nbytes)):
                    if name.startswith(kind):
                        rid = name[len(kind):]
                        for dp in m.get("sum", {}).get("dataPoints", []):
                            into[rid] = into.get(rid, 0) + float(dp.get("asInt") or dp.get("asDouble") or 0)

acting = [r for r in rep["recommendations"] if r["Action"] != "none"]
share = {"aggregate": 1.0, "drop": 1.0, "archive": 1.0, "dedupe": 1.0}
pred_lines = pred_bytes = 0.0
per_rule = []
for r in acting:
    f = share.get(r["Action"], (100 - r.get("Keep", 0)) / 100 if r["Action"] == "sample" else 0)
    pred_lines += lines.get(r["ID"], 0) * f
    pred_bytes += nbytes.get(r["ID"], 0) * f
    per_rule.append({"id": r["ID"], "service": r["Candidate"]["Service"], "template": r["Candidate"]["Template"],
                     "action": r["Action"], "shadow_lines": lines.get(r["ID"], 0), "shadow_bytes": nbytes.get(r["ID"], 0)})

statuses = {}
for rr in recon.get("rules", []):
    statuses[rr["status"]] = statuses.get(rr["status"], 0) + 1
stored_before = sum(rr["before_lines"] for rr in recon.get("rules", []))
stored_after = sum(rr["after_lines"] for rr in recon.get("rules", []))
stored_before_bytes = sum(rr["before_bytes"] for rr in recon.get("rules", []))

before_rate = totals["shadow_lines"] / totals["shadow_seconds"]
after_rate = totals["enforce_lines"] / totals["enforce_seconds"]
before_brate = totals["shadow_bytes"] / totals["shadow_seconds"]
after_brate = totals["enforce_bytes"] / totals["enforce_seconds"]
res = {
    "shadow_seconds": totals["shadow_seconds"],
    "services": len(rep.get("services") or []),
    "rules_decided": len(rep["recommendations"]),
    "rules_acting": len(acting),
    "actions": {a: sum(1 for r in acting if r["Action"] == a) for a in sorted({r["Action"] for r in acting})},
    "gaps": [g["Key"] for g in rep.get("gaps") or []],
    "readers": rep.get("readers"),
    "shadow": {"lines_total": totals["shadow_lines"], "bytes_total": totals["shadow_bytes"],
               "lines_removable": round(pred_lines), "bytes_removable": round(pred_bytes),
               "lines_pct": 100 * pred_lines / max(totals["shadow_lines"], 1),
               "bytes_pct": 100 * pred_bytes / max(totals["shadow_bytes"], 1)},
    "enforce": {"lines_per_min_before": 60 * before_rate, "lines_per_min_after": 60 * after_rate,
                "bytes_per_min_before": 60 * before_brate, "bytes_per_min_after": 60 * after_brate,
                "lines_reduction_pct": 100 * (1 - after_rate / before_rate) if before_rate else 0,
                "bytes_reduction_pct": 100 * (1 - after_brate / before_brate) if before_brate else 0},
    "reconcile": statuses,
    "stored": {"acting_lines_before": stored_before, "acting_lines_after": stored_after,
               "acting_bytes_before": stored_before_bytes,
               "lines_pct": 100 * stored_before / max(totals["shadow_lines"], 1),
               "bytes_pct": 100 * stored_before_bytes / max(totals["shadow_bytes"], 1)},
    "verify_exit": verify_exit,
    "rules": per_rule,
}
json.dump(res, open(os.path.join(work, "results.json"), "w"), indent=2)
s, e = res["shadow"], res["enforce"]
print(f"""# sievelog on the OpenTelemetry demo (local kind)

- {res['services']} services, {res['rules_decided']} rules decided, {res['rules_acting']} act: {res['actions']}
- Evidence gaps: {res['gaps'] or 'none'}
- Readers: {res['readers']}
- Shadow ({totals['shadow_seconds'] // 60} min): the Collector measured {s['lines_removable']} lines of the acting rules
  ({s['lines_pct']:.1f}% of {s['lines_total']:.0f} stored), {s['bytes_pct']:.1f}% of the bytes, after their actions
- Loki, same window: the acting rules' lines were {res['stored']['acting_lines_before']:.0f} of {s['lines_total']:.0f}
  ({res['stored']['lines_pct']:.1f}%, {res['stored']['bytes_pct']:.1f}% of bytes); during enforce, {res['stored']['acting_lines_after']:.0f}
- Reconcile: {res['reconcile']}; verify exit {res['verify_exit']}
- Total stored lines per minute: {e['lines_per_min_before']:.0f} in the shadow window, {e['lines_per_min_after']:.0f} while enforcing
  (the load generator's traffic varies between windows, so this is not the removal)
""")
for r in sorted(per_rule, key=lambda r: -r["shadow_lines"]):
    print(f"- {r['action']:9} {r['service']:16} {int(r['shadow_lines']):7} lines  {r['template'][:90]}")
