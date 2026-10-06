"""Readers of the demo's logs, as an operator of the shop might have them: a Grafana org with a few
dashboard panels and one alert rule written for the app, and a few ad-hoc queries run against Loki
(they land in its query log). None is chosen by looking at the logs first.

Usage: readers.py GRAFANA_URL LOKI_URL PASSWORD  -> prints an org-scoped service account token.
       readers.py GRAFANA_URL LOKI_URL PASSWORD remove  -> empties the readers' org and deletes it.
"""
import base64
import json
import sys
import time
import urllib.parse
import urllib.request

GRAFANA, LOKI, PASSWORD = sys.argv[1], sys.argv[2], sys.argv[3]
ORG_NAME = "zeroreads-demo-readers"
NS = '{k8s_namespace_name="zeroreads-demo"}'

PANELS = [
    ("Checkout errors", '{service_name="checkout"} |~ "(?i)(error|fail)"'),
    ("Errors by service", 'sum by (service_name) (count_over_time(' + NS + ' |~ "(?i)error" [$__auto]))'),
    ("Frontend errors", '{service_name="frontend"} |= "error"'),
    ("Cart exceptions", '{service_name="cart"} |~ "(?i)exception"'),
    ("Payments", 'sum(count_over_time({service_name="payment"} |= "Transaction" [$__auto]))'),
]
ALERT = 'sum(count_over_time({service_name="checkout"} |~ "(?i)failed to" [5m]))'
ADHOC = [
    '{service_name="ad"}',
    '{service_name="shipping"} |= "quote"',
    NS + ' |= "timeout"',
]


def call(method, path, body=None, org=None, token=None):
    req = urllib.request.Request(GRAFANA + path, method=method,
                                 data=None if body is None else json.dumps(body).encode())
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    else:
        req.add_header("Authorization", "Basic " + base64.b64encode(b"admin:" + PASSWORD.encode()).decode())
    if org:
        req.add_header("X-Grafana-Org-Id", str(org))
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or b"{}")


def org_id():
    try:
        return call("GET", "/api/orgs/name/" + urllib.parse.quote(ORG_NAME))["id"]
    except urllib.error.HTTPError:
        return call("POST", "/api/orgs", {"name": ORG_NAME})["orgId"]


def main():
    org = org_id()
    try:
        call("POST", "/api/datasources", {"name": "Loki", "uid": "demo-loki", "type": "loki", "access": "proxy",
                                          "url": "http://loki.zeroreads-system.svc:3100", "isDefault": True}, org)
    except urllib.error.HTTPError as e:
        if e.code != 409:
            raise
    ds = {"type": "loki", "uid": "demo-loki"}
    panels = [{"id": i + 1, "title": t, "type": "logs" if not q.startswith("sum") else "timeseries", "datasource": ds,
               "targets": [{"refId": "A", "expr": q, "datasource": ds}]} for i, (t, q) in enumerate(PANELS)]
    call("POST", "/api/dashboards/db", {"overwrite": True, "dashboard": {
        "uid": "shop-logs", "title": "Shop logs", "schemaVersion": 39, "panels": panels}}, org)
    if not folder_exists(org):
        call("POST", "/api/folders", {"uid": "shop-alerts", "title": "Shop alerts"}, org)
    try:
        call("POST", "/api/v1/provisioning/alert-rules", {
            "uid": "checkout-failures", "title": "Checkout failures", "folderUID": "shop-alerts", "ruleGroup": "shop",
            "condition": "B", "for": "5m", "noDataState": "OK", "execErrState": "Error",
            "data": [
                {"refId": "A", "datasourceUid": "demo-loki", "relativeTimeRange": {"from": 600, "to": 0},
                 "model": {"refId": "A", "expr": ALERT, "queryType": "instant"}},
                {"refId": "B", "datasourceUid": "__expr__", "relativeTimeRange": {"from": 0, "to": 0},
                 "model": {"refId": "B", "type": "threshold", "expression": "A",
                           "conditions": [{"evaluator": {"type": "gt", "params": [5]}}]}},
            ]}, org)
    except urllib.error.HTTPError as e:
        if e.code != 409:
            raise
    sa = call("POST", "/api/serviceaccounts", {"name": "zeroreads-demo-%d" % time.time(), "role": "Admin"}, org)
    # Token names are unique across the org, so each run's token gets its own.
    token = call("POST", "/api/serviceaccounts/%d/tokens" % sa["id"], {"name": "zeroreads-%d" % time.time()}, org)["key"]
    now = int(time.time())
    for q in ADHOC:
        url = LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(
            {"query": q, "start": (now - 900) * 10**9, "end": now * 10**9, "limit": 100})
        with urllib.request.urlopen(url, timeout=60) as resp:
            resp.read()
    print(token)


def folder_exists(org):
    try:
        call("GET", "/api/folders/shop-alerts", org=org)
        return True
    except urllib.error.HTTPError:
        return False


def remove():
    """Empties the readers' organisation and deletes it, or renames it when Grafana refuses, so evidence in
    later runs is not read through its datasource."""
    try:
        org = call("GET", "/api/orgs/name/" + urllib.parse.quote(ORG_NAME))["id"]
    except urllib.error.HTTPError:
        return
    for path in ("/api/v1/provisioning/alert-rules/checkout-failures", "/api/dashboards/uid/shop-logs",
                 "/api/folders/shop-alerts", "/api/datasources/uid/demo-loki"):
        try:
            call("DELETE", path, org=org)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
    for sa in call("GET", "/api/serviceaccounts/search?perpage=100", org=org).get("serviceAccounts", []):
        call("DELETE", "/api/serviceaccounts/%d" % sa["id"], org=org)
    try:
        call("DELETE", "/api/orgs/%d" % org)
    except urllib.error.HTTPError:
        call("PUT", "/api/orgs/%d" % org, {"name": "zeroreads-emptied-%d" % org})


if __name__ == "__main__":
    remove() if sys.argv[4:] == ["remove"] else main()
