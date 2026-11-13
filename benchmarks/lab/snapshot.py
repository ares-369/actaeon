"""Freeze a copy of real SIEM data (OpenSearch/Elasticsearch-compatible indices) for a lab benchmark.

Run it on (or next to) the search cluster with an admin client certificate. It copies into
``actaeon-bench-*`` indices, outside any retention policy, keeping each source's field mappings, so
every benchmark run sees exactly the same data:
  alerts (the 8 days before the anchor), raw events, host inventory and vulnerability findings.

Usage: python3 snapshot.py <anchor ISO time> [--certs DIR] [--url URL]
Edit JOBS below to match your index names. Then pin the bridges to the anchor with BRIDGE_NOW.
"""
import argparse
import json
import ssl
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("anchor")
ap.add_argument("--certs", required=True, help="dir with root-ca.pem, admin.pem, admin-key.pem")
ap.add_argument("--url", default="https://127.0.0.1:9200/")
args = ap.parse_args()
C = args.certs
ctx = ssl.create_default_context(cafile=f"{C}/root-ca.pem")
ctx.check_hostname = False
ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT   # self-generated CAs often lack keyUsage; Python 3.13 strict mode rejects them
ctx.load_cert_chain(f"{C}/admin.pem", f"{C}/admin-key.pem")
BASE = args.url.rstrip("/") + "/"


def call(method, path, body=None, timeout=1800):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode()[:300]}


anchor = args.anchor
# (source pattern, destination, optional query). Adjust to your index names.
jobs = [("<alerts-index>-*", "actaeon-bench-alerts", {"range": {"timestamp": {"gte": f"{anchor}||-8d", "lte": anchor}}}),
        ("<raw-events-index>-*", "actaeon-bench-archives", {"range": {"timestamp": {"lte": anchor}}}),
        ("<vulnerabilities-index>-*", "actaeon-bench-vulns", None)]
for kind in ("processes", "ports", "users", "services", "packages", "system"):
    jobs.append((f"<inventory-index>-{kind}-*", f"actaeon-bench-inv-{kind}", None))

for src, dest, query in jobs:
    maps = call("GET", f"{src}/_mapping")
    if "error" in maps or not maps:
        print(f"skip {src}: {maps}")
        continue
    props = {}
    for m in maps.values():                       # merge the mappings of every source index
        props.update((m.get("mappings") or {}).get("properties") or {})
    call("DELETE", dest)
    r = call("PUT", dest, {"settings": {"number_of_replicas": 0, "index.mapping.total_fields.limit": 10000},
                           "mappings": {"properties": props}})
    if "error" in r:
        print(f"create {dest} failed: {r}")
        continue
    body = {"source": {"index": src}, "dest": {"index": dest}}
    if query:
        body["source"]["query"] = query
    r = call("POST", "_reindex?wait_for_completion=true&refresh=true", body)
    print(f"{dest:32} <- {src:34} copied {r.get('created', r)}")
