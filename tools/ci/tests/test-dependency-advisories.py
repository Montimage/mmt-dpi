#!/usr/bin/env python3
"""test-dependency-advisories.py -- fixture self-test for
tools/ci/check-dependency-advisories.sh (issue #492, F-DEP-204).

Drives the REAL script against throwaway fixture trees (ROOT_DIR) and a local
HTTP stub that serves tools/ci/tests/dependency-advisories-feeds.json in place
of OSV, the GitHub (repository) advisory APIs and RubyGems; the docker probe
is replaced by the fixture's recorded probe output (ADVISORY_PROBE_FIXTURE).
No docker, no network.

  - Debian `unimportant` record CVE-2019-1010022 (CVSS 9.8) -> non-blocking,
    exit 0; the CI tooling image buildpack-deps is excluded, not a failure
  - Ubuntu `negligible` record (CVSS 9.8) -> non-blocking, exit 0
  - debian:trixie maps to Debian:13; an untriaged CVSS 9.8 record -> exit 1
  - the same record under an unexpired disposition -> exit 0
  - that disposition past its expiry date -> exit 1
  - an expired disposition matching no advisory -> still exit 1
  - a malformed disposition file -> exit 2
  - an affected record with no rating in any source and no disposition ->
    NOT ASSESSED (no rating), exit 2; under a debian:13 disposition -> exit 0
    (issue #644)
  - CentOS Stream 9 and 10 have no advisory feed: listed as Not Assessed,
    never a failure, and they leave the exit code at 0 (issue #644)
  - repository advisories of the direct gems: GHSA-572m-7cg5-6j5r and
    GHSA-3343-386p-v26g are reported against docs/Gemfile.lock at the
    pre-#494 pins and not at the patched ones; a direct gem without a GitHub
    repository is Not Assessed
  - a High repository advisory of a pinned action (an `or` range) -> exit 1
  - the script's own offline --self-test passes

Usage: python3 tools/ci/tests/test-dependency-advisories.py
Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.
"""

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SELF_DIR, "..", "..", ".."))
SCRIPT = os.path.join(REPO_ROOT, "tools", "ci", "check-dependency-advisories.sh")
FEEDS_PATH = os.path.join(SELF_DIR, "dependency-advisories-feeds.json")

for path in (SCRIPT, FEEDS_PATH):
    if not os.path.isfile(path):
        print(f"✗ missing {path}", file=sys.stderr)
        sys.exit(2)
with open(FEEDS_PATH, encoding="utf-8") as fh:
    FEEDS = json.load(fh)

D12 = "debian:12@sha256:" + "1" * 64
U22 = "ubuntu:22.04@sha256:" + "2" * 64
D13 = "debian:trixie@sha256:" + "3" * 64
TOOLING = "buildpack-deps:bookworm@sha256:" + "4" * 64
D13U4 = "debian:13@sha256:" + "5" * 64
CS9 = "quay.io/centos/centos:stream9@sha256:" + "6" * 64
CS10 = "quay.io/centos/centos:stream10@sha256:" + "7" * 64
TODAY = "2026-10-21"


class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self):
        self.reply(200, headers={"Last-Modified": "Tue, 20 Oct 2026 23:00:00 GMT"})

    def do_POST(self):
        if self.path != "/v1/query":
            return self.reply(404, {})
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        pkg = req.get("package") or {}
        key = f"{pkg.get('ecosystem')}|{pkg.get('name')}"
        if "version" in req:
            key += f"|{req['version']}"
        ids = FEEDS["osv_query"].get(key, [])
        self.reply(200, {"vulns": [FEEDS["osv_vulns"][i] for i in ids]} if ids else {})

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        parts = [urllib.parse.unquote(p) for p in url.path.strip("/").split("/")]
        if parts[:2] == ["v1", "vulns"] and len(parts) == 3:
            rec = FEEDS["osv_vulns"].get(parts[2])
            return self.reply(200, rec) if rec else self.reply(404, {})
        if parts == ["advisories"]:
            return self.reply(200, [], {"Date": "Wed, 21 Oct 2026 00:00:00 GMT"})
        if len(parts) == 4 and parts[0] == "repos" and parts[3] == "security-advisories":
            advs = FEEDS["repo_advisories"].get(f"{parts[1]}/{parts[2]}")
            return self.reply(404, {}) if advs is None else self.reply(200, advs)
        if parts[:3] == ["api", "v1", "gems"] and len(parts) == 4:
            info = FEEDS["rubygems"].get(parts[3][:-len(".json")])
            return self.reply(200, info) if info else self.reply(404, {})
        return self.reply(404, {})


SERVER = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=SERVER.serve_forever, daemon=True).start()
API = f"http://127.0.0.1:{SERVER.server_address[1]}"

WORK = tempfile.mkdtemp(prefix="advisories-selftest.")
PROBE = os.path.join(WORK, "probe.json")
with open(PROBE, "w", encoding="utf-8") as fh:
    json.dump(FEEDS["probe"], fh)

PASS = FAIL = 0


def lockfile(pins):
    specs = "".join(f"    {n} ({v})\n" for n, v in sorted(pins.items()))
    direct = "".join(f"  {n}\n" for n in sorted(pins) if n != "addressable")
    return (f"GEM\n  remote: https://rubygems.org/\n  specs:\n{specs}\n"
            f"PLATFORMS\n  ruby\n\nDEPENDENCIES\n{direct}\nBUNDLED WITH\n   2.6.9\n")


def tree(name, images=(), dispositions="", pins=None, workflow=""):
    root = os.path.join(WORK, name)
    for d in ("docs", "tools/ci", ".github/workflows"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    files = {"tools/ci/base-images.txt": "# fixture\n" + "".join(f"{i}\n" for i in images),
             "tools/ci/advisory-dispositions.txt": dispositions,
             "docs/Gemfile.lock": lockfile(pins or {"jekyll-relative-links": "0.7.0"}),
             ".github/workflows/ci.yml": workflow}
    for rel, text in files.items():
        with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    return root


def scan(root, surfaces, today=TODAY):
    out = os.path.join(root, "report.json")
    env = dict(os.environ, ROOT_DIR=root, OSV_API=API, GHSA_API=API, OSV_DB_URL=API,
               RUBYGEMS_API=API, ADVISORY_PROBE_FIXTURE=PROBE, GH_TOKEN="fixture-token")
    cmd = ["bash", SCRIPT, "--json", out, "--today", today, "--out", os.path.join(root, "report.md")]
    for s in surfaces:
        cmd += ["--only", s]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
    rep = None
    if os.path.isfile(out):
        with open(out, encoding="utf-8") as fh:
            rep = json.load(fh)
    return res, rep


def check(label, cond, res=None):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}")
        if res is not None:
            print("    exit", res.returncode)
            for line in (res.stdout + res.stderr).splitlines()[-15:]:
                print("    " + line)


def adv(rep, vid):
    return next((a for a in (rep or {}).get("advisories", []) if a["id"] == vid), None)


print("check-dependency-advisories.sh fixture self-test (issue #492, F-DEP-204)")
print()

try:
    # Debian `unimportant` (the acceptance-criterion record) + excluded tooling image.
    res, rep = scan(tree("debian-unimportant", [D12, TOOLING]), ["native"])
    a = adv(rep, "DEBIAN-CVE-2019-1010022")
    check("Debian unimportant CVE-2019-1010022 (CVSS 9.8) is non-blocking -> exit 0",
          res.returncode == 0 and a is not None and a["severity"] == "CRITICAL"
          and not a["blocking"] and a["triage"] == "Debian urgency unimportant", res)
    check("buildpack-deps tooling image is excluded, not a failure",
          rep is not None and not rep["failures"] and any(e.startswith(TOOLING) for e in rep["excluded"]), res)

    # Ubuntu `negligible`.
    res, rep = scan(tree("ubuntu-negligible", [U22]), ["native"])
    a = adv(rep, "UBUNTU-CVE-2099-0002")
    check("Ubuntu negligible record (CVSS 9.8) is non-blocking -> exit 0",
          res.returncode == 0 and a is not None and not a["blocking"]
          and a["triage"] == "Ubuntu priority negligible", res)

    # trixie mapping + an untriaged critical record.
    res, rep = scan(tree("trixie-blocking", [D13]), ["native"])
    a = adv(rep, "DEBIAN-CVE-2099-0001")
    check("debian:trixie maps to Debian:13; untriaged CVSS 9.8 record blocks -> exit 1",
          res.returncode == 1 and a is not None and a["blocking"]
          and any(r["ecosystem"] == "Debian:13" for r in rep["native"]), res)
    check("the unimportant record stays non-blocking on Debian:13 too",
          adv(rep, "DEBIAN-CVE-2019-1010022") is not None
          and not adv(rep, "DEBIAN-CVE-2019-1010022")["blocking"], res)

    entry = "CVE-2099-0001 | debian:* | 2026-12-31 | #492 | awaiting a distro fix\n"
    res, rep = scan(tree("trixie-dispositioned", [D13], "# header\n\n" + entry), ["native"])
    a = adv(rep, "DEBIAN-CVE-2099-0001")
    check("unexpired disposition (by upstream alias, target glob) -> exit 0",
          res.returncode == 0 and a is not None and not a["blocking"]
          and a["status"].startswith("dispositioned until 2026-12-31"), res)

    res, rep = scan(tree("trixie-expired", [D13], entry), ["native"], today="2027-01-01")
    check("the same disposition after its expiry date -> exit 1",
          res.returncode == 1 and rep is not None and len(rep["expired_dispositions"]) == 1
          and adv(rep, "DEBIAN-CVE-2099-0001")["blocking"]
          and "expired disposition" in rep["verdict"], res)

    stale = "CVE-2000-0000 | * | 2026-10-20 | #492 | advisory no longer reported\n"
    res, rep = scan(tree("stale-expired", [D12], stale), ["native"])
    check("an expired disposition that matches nothing still fails -> exit 1",
          res.returncode == 1 and rep is not None and len(rep["expired_dispositions"]) == 1, res)

    res, rep = scan(tree("malformed", [D12], "CVE-2099-0001 | debian:* | next week | #492 | x\n"),
                    ["native"])
    check("malformed disposition file -> exit 2 (assessment incomplete)",
          res.returncode == 2 and rep is not None
          and any(f.startswith("dispositions:") for f in rep["failures"]), res)

    # An affected record no source rates (the debian:13 glibc pair of #644).
    res, rep = scan(tree("trixie-unrated", [D13U4]), ["native"])
    a = adv(rep, "DEBIAN-CVE-2099-0004")
    check("unrated affected record without a disposition -> NOT ASSESSED (no rating), exit 2",
          res.returncode == 2 and a is not None and a["severity"] is None and not a["blocking"]
          and a["status"] == "NOT ASSESSED (no rating)" and not rep["failures"]
          and rep["verdict"].startswith("NOT ASSESSED"), res)

    unrated = ("CVE-2099-0004 | debian:13 | 2026-12-31 | #492 | glibc @ 2.41-12+deb13u4: "
               "no rating in any source and unfixed in the distro\n")
    res, rep = scan(tree("trixie-unrated-dispositioned", [D13U4], unrated), ["native"])
    a = adv(rep, "DEBIAN-CVE-2099-0004")
    check("the same record under a debian:13 disposition -> exit 0",
          res.returncode == 0 and a is not None and not a["blocking"]
          and a["status"].startswith("dispositioned until 2026-12-31 (#492)")
          and rep["verdict"].startswith("PASS"), res)

    # CentOS Stream: no advisory feed, so Not Assessed but never the exit code.
    res, rep = scan(tree("centos-stream", [CS9, CS10]), ["native"])
    na = (rep or {}).get("not_assessed", [])
    check("CentOS Stream 9 and 10 are listed as Not Assessed (no feed), not failures -> exit 0",
          res.returncode == 0 and rep is not None and not rep["failures"]
          and all(any(n.startswith(img + ": CentOS Stream publishes no security advisories")
                      for n in na) for img in (CS9, CS10))
          and "(2 target(s) Not Assessed" in rep["verdict"]
          and sum(1 for r in rep["native"] if not r["assessed"]) == 8, res)

    # Repository advisories of the direct gems (the pre-#494 pins).
    old = {"jekyll-seo-tag": "2.9.0", "jekyll-remote-theme": "0.5.2",
           "jekyll-relative-links": "0.7.0", "orphan-gem": "1.0.0", "addressable": "2.8.7"}
    res, rep = scan(tree("gems-old", pins=old), ["gems"])
    a1, a2 = adv(rep, "GHSA-572m-7cg5-6j5r"), adv(rep, "GHSA-3343-386p-v26g")
    check("repository advisories report GHSA-572m-7cg5-6j5r and GHSA-3343-386p-v26g against docs/Gemfile.lock",
          a1 is not None and a2 is not None and a1["target"] == "docs/Gemfile.lock"
          and a1["package"] == "jekyll-seo-tag" and a2["package"] == "jekyll-remote-theme"
          and a1["fixed"] == ["2.9.1"] and a2["fixed"] == ["0.6.1"], res)
    check("both are Medium, so reported but non-blocking -> exit 0",
          res.returncode == 0 and a1 is not None and a1["severity"] == "MEDIUM" and not a1["blocking"], res)
    check("a direct gem without a GitHub repository is Not Assessed",
          rep is not None and any(n.startswith("gems: orphan-gem:") for n in rep["not_assessed"]), res)

    new = dict(old, **{"jekyll-seo-tag": "2.9.1", "jekyll-remote-theme": "0.6.2"})
    res, rep = scan(tree("gems-new", pins=new), ["gems"])
    check("patched pins (2.9.1 / 0.6.2) report neither -> exit 0",
          res.returncode == 0 and rep is not None and not rep["advisories"], res)

    # A pinned action with a High repository advisory (an `or` range).
    wf = ("jobs:\n  a:\n    steps:\n"
          "      - uses: fixture-org/setup-thing@" + "e" * 40 + " # v2.3.0\n")
    res, rep = scan(tree("action-repo-advisory", workflow=wf), ["actions"])
    a = adv(rep, "GHSA-2099-aaaa-bbbb")
    check("action repository advisory in an `or` range blocks -> exit 1",
          res.returncode == 1 and a is not None and a["blocking"] and a["installed"] == "2.3.0", res)

    # The script's own offline unit checks.
    res = subprocess.run(["bash", SCRIPT, "--self-test"], capture_output=True, text=True, timeout=600)
    check("check-dependency-advisories.sh --self-test", res.returncode == 0, res)
finally:
    SERVER.shutdown()
    shutil.rmtree(WORK, ignore_errors=True)

print()
print(f"dependency-advisories self-test: {PASS} passed, {FAIL} failed ({PASS + FAIL} checks)")
sys.exit(0 if FAIL == 0 else 1)
