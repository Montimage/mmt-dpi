#!/usr/bin/env bash
#
# check-dependency-advisories.sh — measure the advisory status of the
# dependencies this repository actually resolves (issue #384, plan task 2.5).
#
# Three dependency surfaces are measured at their exact resolved revisions:
#
#   gems     every spec in docs/Gemfile.lock (the frozen docs toolchain),
#            checked against OSV (RubyGems) AND the GitHub Advisory Database.
#   actions  every SHA-pinned `uses:` in .github/workflows and .github/actions,
#            at the release named by its `# vX.Y.Z` pin comment, checked
#            against the GitHub Advisory Database (OSV cannot evaluate
#            versions in its GitHub Actions ecosystem).
#   native   the runtime packages the shipped .deb/.rpm declare (the
#            tools/ci/shlib-deps.sh set for an ENABLESEC=1 build: libc,
#            libstdc++, libgcc, libxml2), resolved inside every pinned
#            release image of tools/ci/base-images.txt exactly as the package
#            build resolves them (apt-get update / dnf repoquery), checked
#            against the distro's own OSV feed.
#
# Distro advisories are judged against the distro revision, so a fix the
# distro backported into an older upstream version counts as fixed. The
# report separates the two cases explicitly:
#   fixed-by-backport     not affected; the distro fix kept the upstream base
#   backport-available    affected; a newer distro revision of the SAME
#                         upstream base fixes it (update the package)
#   upstream-version-gap  affected; the fix only exists in a newer upstream
#                         version (gems/actions always fall here when affected)
#   unfixed               affected; no fixed version published yet
#
# Missing assessment is never reported as zero vulnerabilities: a required
# scanner that did not run, an unreadable pin, or an affected advisory whose
# severity cannot be established makes the verdict NOT ASSESSED / INCOMPLETE.
# CentOS Stream 9 has no advisory feed (no OSV ecosystem, no errata), so it is
# always listed as Not Assessed — its revisions are still recorded when the
# pinned image can be pulled.
#
# Exit codes:
#   0 = every required scanner ran; no affected High/Critical advisory
#   1 = at least one confirmed, unresolved High/Critical advisory (blocks M1)
#   2 = assessment incomplete: a required scanner/tool did not run, or an
#       affected advisory has no determinable severity
#
# Usage:
#   bash tools/ci/check-dependency-advisories.sh [--out report.md]
#        [--json report.json] [--only gems|actions|native]... [--self-test]
#
# Requires python3 and network access to api.osv.dev and api.github.com;
# the native surface also requires docker. GitHub API auth is taken from
# GH_TOKEN / GITHUB_TOKEN, else `gh auth token`, else unauthenticated.
# OSV_API / GHSA_API / OSV_DB_URL override the endpoints (used by --self-test).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

exec python3 - "$0" "$@" <<'PYEOF'
import argparse
import datetime as dt
import glob
import json
import math
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

SCRIPT = sys.argv[1]
ARGS = sys.argv[2:]

OSV_API = os.environ.get("OSV_API", "https://api.osv.dev").rstrip("/")
GHSA_API = os.environ.get("GHSA_API", "https://api.github.com").rstrip("/")
OSV_DB_URL = os.environ.get(
    "OSV_DB_URL", "https://osv-vulnerabilities.storage.googleapis.com").rstrip("/")
TIMEOUT = 60

LOCKFILE = "docs/Gemfile.lock"
BASE_IMAGES = "tools/ci/base-images.txt"
ACTION_GLOBS = [".github/workflows/*.yml", ".github/workflows/*.yaml",
                ".github/actions/*/action.yml", ".github/actions/*/action.yaml"]

# Runtime package set the shipped packages declare (tools/ci/shlib-deps.sh,
# ENABLESEC=1 as tools/ci/build-package.sh builds it). Keep in sync.
DEB_PKGS = ["libc6", "libstdc++6", "libgcc-s1", "libxml2"]
RPM_PKGS = ["glibc", "libstdc++", "libgcc", "libxml2"]

# image repository (before ':' / '@') + tag -> (OSV ecosystem or None, family)
DISTROS = {
    ("ubuntu", "22.04"): ("Ubuntu:22.04:LTS", "deb"),
    ("ubuntu", "24.04"): ("Ubuntu:24.04:LTS", "deb"),
    ("debian", "12"): ("Debian:12", "deb"),
    ("rockylinux", "9"): ("Rocky Linux:9", "rpm"),
    ("quay.io/centos/centos", "stream9"): (None, "rpm"),
}
NO_FEED_REASON = ("CentOS Stream publishes no security advisories "
                  "(no OSV ecosystem, no errata feed)")

SEV_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
BLOCKING = {"HIGH", "CRITICAL"}


def now_utc():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScannerError(Exception):
    pass


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def http(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "mmt-dpi-check-dependency-advisories")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
            return resp.headers, (json.loads(raw) if raw else None)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ScannerError(f"{method} {url}: {exc}") from exc


_QUERY_CACHE = {}


def osv_query(package, ecosystem, version=None):
    """All OSV records for package (optionally only those affecting version)."""
    key = (package, ecosystem, version)
    if key not in _QUERY_CACHE:
        _QUERY_CACHE[key] = _osv_query(package, ecosystem, version)
    return _QUERY_CACHE[key]


def _osv_query(package, ecosystem, version):
    out, token = [], None
    while True:
        body = {"package": {"name": package, "ecosystem": ecosystem}}
        if version is not None:
            body["version"] = version
        if token:
            body["page_token"] = token
        _, resp = http("POST", f"{OSV_API}/v1/query", body)
        resp = resp or {}
        out.extend(resp.get("vulns", []))
        token = resp.get("next_page_token")
        if not token:
            return out


_OSV_CACHE = {}
# Alias lookups that failed for a reason other than "no such record": their
# ratings are missing, so the severity may be understated (fail closed).
ALIAS_FAILURES = []


def osv_vuln(vid):
    if vid not in _OSV_CACHE:
        try:
            _OSV_CACHE[vid] = http("GET", f"{OSV_API}/v1/vulns/{urllib.parse.quote(vid)}")[1]
        except ScannerError as exc:
            _OSV_CACHE[vid] = None
            if not (isinstance(exc.__cause__, urllib.error.HTTPError) and exc.__cause__.code == 404):
                ALIAS_FAILURES.append(f"OSV alias lookup did not run: {exc}")
    return _OSV_CACHE[vid]


def osv_db_date(ecosystem):
    base = ecosystem.split(":")[0]
    try:
        headers, _ = http("HEAD", f"{OSV_DB_URL}/{urllib.parse.quote(base)}/all.zip")
        return headers.get("Last-Modified", "unknown")
    except ScannerError:
        return "unavailable"


def gh_token():
    for var in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    if shutil.which("gh"):
        try:
            tok = subprocess.run(["gh", "auth", "token"], capture_output=True,
                                 text=True, timeout=30).stdout.strip()
            return tok or None
        except (OSError, subprocess.SubprocessError):
            return None
    return None


def ghsa_affecting(ecosystem, pkg_at_version):
    """Reviewed GitHub Advisory Database advisories affecting one name@version.

    One query per name@version, so every returned advisory affects exactly that
    pin; pagination follows the Link rel="next" cursor (the endpoint ignores
    `page`)."""
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    tok = gh_token()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    out, date, seen = [], None, set()
    url = (f"{GHSA_API}/advisories?type=reviewed&ecosystem={ecosystem}&per_page=100"
           f"&affects={urllib.parse.quote(pkg_at_version, safe='@/')}")
    while url:
        hdrs, resp = http("GET", url, headers=headers)
        date = hdrs.get("Date", date)
        if not isinstance(resp, list):
            raise ScannerError(f"GET {url}: unexpected response")
        for adv in resp:
            if adv.get("ghsa_id") not in seen:
                seen.add(adv.get("ghsa_id"))
                out.append(adv)
        m = re.search(r'<([^>]+)>;\s*rel="next"', hdrs.get("Link") or "")
        url = m.group(1) if m else None
    return out, date


# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------

CVSS3_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    """CVSS v3.x base score, or None when the vector is not v3 / incomplete."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        cia = [CVSS3_W["C"][m[k]] for k in ("C", "I", "A")]
        av, ac, ui = CVSS3_W["AV"][m["AV"]], CVSS3_W["AC"][m["AC"]], CVSS3_W["UI"][m["UI"]]
    except KeyError:
        return None
    iss = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    total = impact + expl if not scope_changed else 1.08 * (impact + expl)
    return _roundup(min(total, 10))


def score_label(score):
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"


def norm_label(text):
    t = (text or "").strip().upper()
    return {"MODERATE": "MEDIUM", "NEGLIGIBLE": "LOW", "IMPORTANT": "HIGH",
            "UNTRIAGED": None, "UNKNOWN": None, "": None}.get(t, t if t in SEV_ORDER else None)


def ratings_of_osv(rec):
    """[(label, source)] from an OSV record — vendor labels and CVSS v3."""
    out = []
    if not rec:
        return out
    ds = rec.get("database_specific") or {}
    lab = norm_label(ds.get("severity")) if isinstance(ds.get("severity"), str) else None
    if lab:
        out.append((lab, "advisory"))
    for sev in rec.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            s = cvss3_score(sev.get("score"))
            if s is not None:
                out.append((score_label(s), f"CVSS {s}"))
        elif sev.get("type") in ("Ubuntu", "Debian"):
            lab = norm_label(sev.get("score"))
            if lab:
                out.append((lab, f"{sev['type']} priority"))
    return out


def ratings_of_ghsa(adv):
    out = []
    lab = norm_label(adv.get("severity"))
    if lab:
        out.append((lab, "GHSA"))
    v3 = ((adv.get("cvss_severities") or {}).get("cvss_v3") or {})
    s = cvss3_score(v3.get("vector_string")) if v3.get("vector_string") else None
    if s is not None:
        out.append((score_label(s), f"CVSS {s}"))
    return out


def worst(ratings):
    """Conservative: the highest of every available rating."""
    labels = [r[0] for r in ratings if r[0]]
    if not labels:
        return None
    return max(labels, key=SEV_ORDER.index)


def resolve_osv_rating(rec):
    ratings = ratings_of_osv(rec)
    # Distro records (e.g. DEBIAN-CVE-*) may carry a weaker or no rating;
    # merge the ratings of every upstream CVE/GHSA record they alias.
    for alias in sorted(set(rec.get("upstream") or []) | set(rec.get("aliases") or [])):
        ratings += [(lab, f"{src} via {alias}") for lab, src in ratings_of_osv(osv_vuln(alias))]
    return worst(ratings), ratings


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------

def upstream_base(version, family):
    """Upstream component version of a distro revision (no epoch/revision)."""
    v = re.sub(r"^\d+:", "", version or "")
    if family == "deb":
        v = v.rsplit("-", 1)[0] if "-" in v else v
    elif family == "rpm":
        v = v.split("-", 1)[0]
    return re.split(r"[+~]", v, maxsplit=1)[0]


def fixed_versions(rec, package, ecosystem):
    out = []
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != package or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            out.extend(ev["fixed"] for ev in rng.get("events") or [] if "fixed" in ev)
    return sorted(set(out))


def classify_distro(installed, fixes, affected, family):
    base = upstream_base(installed, family)
    same_base = [f for f in fixes if upstream_base(f, family) == base]
    if not affected:
        return "fixed-by-backport" if same_base else "not-affected"
    if not fixes:
        return "unfixed"
    return "backport-available" if same_base else "upstream-version-gap"


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------

def parse_lockfile(text):
    """{name: version} for every resolved spec (platform variants collapsed)."""
    gems, in_specs = {}, False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line) if in_specs else None
        if m:
            version = re.sub(r"-(x86_64|aarch64|arm64|x86|universal|java)[\w.-]*$", "", m.group(2))
            gems[m.group(1)] = version
    return gems


USES_RE = re.compile(
    r"uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)((?:/[^@\s'\"]*)?)@([^\s'\"#]+)"
    r"['\"]?\s*(?:#\s*(\S+))?")


def parse_actions(files):
    """[(name, version-or-None, ref, file)] for every remote `uses:`."""
    out = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.lstrip().startswith("#"):
                    continue
                m = USES_RE.search(line)
                if not m or m.group(1).startswith("."):
                    continue
                comment = m.group(4)
                version = comment.lstrip("v") if comment and re.match(r"^v?\d", comment) else None
                out.append((m.group(1), version, m.group(3), path))
    return out


def parse_base_images(text):
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.startswith("#") and not ln.startswith("digest-source:")]


def distro_of(image):
    repo_tag = image.split("@", 1)[0]
    repo, _, tag = repo_tag.rpartition(":")
    return DISTROS.get((repo, tag))


DEB_PROBE = r'''
set -e
apt-get update -qq >/dev/null 2>&1
for p in "$@"; do
  v=$(apt-cache policy "$p" | sed -n "s/^ *Candidate: //p")
  s=$(apt-cache show "$p=$v" 2>/dev/null | sed -n "s/^Source: //p" | head -1)
  echo "$p|$v|$s"
done
'''
RPM_PROBE = r'''
set -e
dnf -q repoquery --latest-limit 1 --arch "$(uname -m),noarch" \
  --qf '%{name}|%{epoch}:%{version}-%{release}|%{sourcerpm}\n' "$@"
'''


def probe_image(image, family):
    """[(binary, binary_version, source, source_version)] resolved in image."""
    pkgs = DEB_PKGS if family == "deb" else RPM_PKGS
    probe = DEB_PROBE if family == "deb" else RPM_PROBE
    try:
        res = subprocess.run(["docker", "run", "--rm", image, "sh", "-c", probe, "probe"] + pkgs,
                             capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScannerError(f"docker run {image}: {exc}") from exc
    if res.returncode != 0:
        err = (res.stderr.strip().splitlines() or ["no output"])[-1]
        raise ScannerError(f"docker run {image}: exit {res.returncode}: {err}")
    rows = {}
    for line in res.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3 or not parts[1] or parts[1] == "(none)":
            continue
        name, ver, src = parts
        if family == "deb":
            m = re.match(r"^(\S+)(?: \(([^)]+)\))?$", src.strip()) if src.strip() else None
            srcname = m.group(1) if m else name
            srcver = (m.group(2) if m and m.group(2) else ver)
        else:
            srcname = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", src) or name
            srcver = ver
        rows[name] = (name, ver, srcname, srcver)
    missing = [p for p in pkgs if p not in rows]
    if missing:
        raise ScannerError(f"{image}: could not resolve {', '.join(missing)}")
    return [rows[p] for p in pkgs]


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------

def measure(only):
    rep = {"started": now_utc(), "scanners": [], "failures": [], "not_assessed": [],
           "gems": [], "actions": [], "native": [], "advisories": []}

    def fail(surface, msg):
        rep["failures"].append(f"{surface}: {msg}")

    # ---- gems --------------------------------------------------------------
    if "gems" in only:
        try:
            gems = parse_lockfile(open(LOCKFILE, encoding="utf-8").read())
        except OSError as exc:
            gems = {}
            fail("gems", f"cannot read {LOCKFILE}: {exc}")
        if not gems:
            fail("gems", f"no specs parsed from {LOCKFILE}")
        else:
            found = {}
            try:
                for name, ver in sorted(gems.items()):
                    for rec in osv_query(name, "RubyGems", ver):
                        found.setdefault((name, rec["id"]), ("OSV", rec))
                rep["scanners"].append({"surface": "gems", "scanner": f"OSV {OSV_API}/v1/query (RubyGems)",
                                        "database_date": osv_db_date("RubyGems"), "queried": now_utc()})
            except ScannerError as exc:
                fail("gems", f"OSV scanner did not run: {exc}")
            try:
                date = None
                for name, ver in sorted(gems.items()):
                    advs, date = ghsa_affecting("rubygems", f"{name}@{ver}")
                    for adv in advs:
                        found.setdefault((name, adv["ghsa_id"]), ("GHSA", adv))
                rep["scanners"].append({"surface": "gems", "scanner": f"GitHub Advisory Database {GHSA_API}/advisories (rubygems, reviewed)",
                                        "database_date": f"live (HTTP Date {date})", "queried": now_utc()})
            except ScannerError as exc:
                fail("gems", f"GitHub Advisory Database scanner did not run: {exc}")
            seen_alias = set()
            for (name, vid), (src, rec) in sorted(found.items()):
                aliases = set(rec.get("aliases") or []) if src == "OSV" else {
                    i["value"] for i in rec.get("identifiers") or []}
                key = (name, frozenset(aliases | {vid}))
                if any(name == n and (aliases | {vid}) & a for n, a in seen_alias):
                    continue
                seen_alias.add(key)
                if src == "OSV":
                    label, ratings = resolve_osv_rating(rec)
                    fixes = fixed_versions(rec, name, "RubyGems")
                else:
                    ratings = ratings_of_ghsa(rec)
                    label = worst(ratings)
                    fixes = [v.get("first_patched_version") for v in rec.get("vulnerabilities") or []
                             if (v.get("package") or {}).get("name") == name and v.get("first_patched_version")]
                rep["advisories"].append({
                    "surface": "gems", "target": LOCKFILE, "package": name, "installed": gems[name],
                    "id": vid, "aliases": sorted(aliases - {vid}), "severity": label,
                    "ratings": [f"{l} ({s})" for l, s in ratings],
                    "disposition": "upstream-version-gap" if fixes else "unfixed",
                    "fixed": fixes})
            for name, ver in sorted(gems.items()):
                n = sum(1 for a in rep["advisories"] if a["surface"] == "gems" and a["package"] == name)
                rep["gems"].append({"gem": name, "version": ver, "affected": n})

    # ---- actions -----------------------------------------------------------
    if "actions" in only:
        files = sorted({f for g in ACTION_GLOBS for f in glob.glob(g)})
        uses = parse_actions(files)
        pins = {}
        for name, version, ref, path in uses:
            pins.setdefault((name, version, ref), set()).add(path)
        for (name, version, ref), paths in sorted(pins.items(), key=lambda kv: (kv[0][0], kv[0][1] or "", kv[0][2])):
            if version is None:
                fail("actions", f"{name}@{ref} has no `# vX.Y.Z` pin comment; version not measurable")
            rep["actions"].append({"action": name, "version": version, "ref": ref,
                                   "files": sorted(paths), "affected": 0})
        if pins:
            try:
                date = None
                for row in rep["actions"]:
                    if not row["version"]:
                        continue
                    advs, date = ghsa_affecting("actions", f"{row['action']}@{row['version']}")
                    for adv in advs:
                        row["affected"] += 1
                        ratings = ratings_of_ghsa(adv)
                        fixes = sorted({v.get("first_patched_version") for v in adv.get("vulnerabilities") or []
                                        if (v.get("package") or {}).get("name") == row["action"]
                                        and v.get("first_patched_version")})
                        rep["advisories"].append({
                            "surface": "actions", "target": ", ".join(row["files"]), "package": row["action"],
                            "installed": row["version"], "id": adv["ghsa_id"],
                            "aliases": [adv["cve_id"]] if adv.get("cve_id") else [],
                            "severity": worst(ratings), "ratings": [f"{l} ({s})" for l, s in ratings],
                            "disposition": "upstream-version-gap" if fixes else "unfixed",
                            "fixed": fixes})
                rep["scanners"].append({"surface": "actions", "scanner": f"GitHub Advisory Database {GHSA_API}/advisories (actions, reviewed)",
                                        "database_date": f"live (HTTP Date {date})", "queried": now_utc()})
            except ScannerError as exc:
                fail("actions", f"GitHub Advisory Database scanner did not run: {exc}")
        else:
            fail("actions", "no pinned `uses:` found")

    # ---- native ------------------------------------------------------------
    if "native" in only:
        try:
            images = parse_base_images(open(BASE_IMAGES, encoding="utf-8").read())
        except OSError as exc:
            images = []
            fail("native", f"cannot read {BASE_IMAGES}: {exc}")
        if not images and not any(f.startswith("native:") for f in rep["failures"]):
            fail("native", f"no images parsed from {BASE_IMAGES}")
        have_docker = shutil.which("docker") is not None
        platform = None
        if have_docker:
            try:
                platform = subprocess.run(["docker", "version", "-f", "{{.Server.Os}}/{{.Server.Arch}}"],
                                          capture_output=True, text=True, timeout=60).stdout.strip() or None
            except (OSError, subprocess.SubprocessError):
                platform = None
        rep["native_platform"] = platform or "unknown"
        db_dates, listed = {}, set()
        for image in images:
            info = distro_of(image)
            if info is None:
                fail("native", f"{image}: no distro/ecosystem mapping in {os.path.basename(SCRIPT)}")
                continue
            ecosystem, family = info
            if ecosystem is None:
                rep["not_assessed"].append(f"{image}: {NO_FEED_REASON}")
            if not have_docker:
                if ecosystem is not None:
                    fail("native", f"{image}: docker is not available; revisions not resolved")
                continue
            try:
                rows = probe_image(image, family)
            except ScannerError as exc:
                if ecosystem is not None:
                    fail("native", str(exc))
                else:
                    rep["not_assessed"][-1] += f"; revisions not resolved ({exc})"
                continue
            for binary, bver, src, sver in rows:
                row = {"image": image, "ecosystem": ecosystem or "none", "package": binary,
                       "version": bver, "source": src, "source_version": sver,
                       "upstream_base": upstream_base(sver, family),
                       "backported": 0, "affected": 0, "feed_records": 0, "assessed": ecosystem is not None}
                rep["native"].append(row)
                if ecosystem is None:
                    continue
                # Every distro feed (Debian, Ubuntu, Rocky) keys on the source
                # package; for rpm the source EVR equals the binary EVR.
                qname, qver = src, sver
                try:
                    affected = {r["id"]: r for r in osv_query(qname, ecosystem, qver)}
                    every = osv_query(qname, ecosystem)
                except ScannerError as exc:
                    fail("native", f"OSV scanner did not run for {qname} ({ecosystem}): {exc}")
                    row["assessed"] = False
                    continue
                row["feed_records"] = len(every)
                if ecosystem not in db_dates:
                    db_dates[ecosystem] = osv_db_date(ecosystem)
                for rec in every:
                    fixes = fixed_versions(rec, qname, ecosystem)
                    disp = classify_distro(qver, fixes, rec["id"] in affected, family)
                    if disp == "fixed-by-backport":
                        row["backported"] += 1
                for vid, rec in sorted(affected.items()):
                    row["affected"] += 1
                    # libstdc++/libgcc share one source package: list each
                    # (image, source, advisory) once.
                    if (image, qname, vid) in listed:
                        continue
                    listed.add((image, qname, vid))
                    fixes = fixed_versions(rec, qname, ecosystem)
                    label, ratings = resolve_osv_rating(rec)
                    rep["advisories"].append({
                        "surface": "native", "target": image, "package": qname,
                        "installed": qver, "id": vid,
                        "aliases": sorted(set(rec.get("aliases") or []) | set(rec.get("upstream") or [])),
                        "severity": label, "ratings": [f"{l} ({s})" for l, s in ratings],
                        "disposition": classify_distro(qver, fixes, True, family), "fixed": fixes})
        for eco, date in sorted(db_dates.items()):
            rep["scanners"].append({"surface": "native", "scanner": f"OSV {OSV_API}/v1/query ({eco})",
                                    "database_date": date, "queried": now_utc()})

    for msg in ALIAS_FAILURES:
        fail("severity", msg)
    rep["finished"] = now_utc()
    blocking = [a for a in rep["advisories"] if a["severity"] in BLOCKING]
    unrated = [a for a in rep["advisories"] if a["severity"] is None]
    if blocking:
        rep["verdict"], rep["exit"] = "FAIL — confirmed unresolved High/Critical advisory (blocks M1)", 1
    elif rep["failures"] or unrated:
        rep["verdict"], rep["exit"] = "NOT ASSESSED — assessment incomplete (never a zero-vulnerability claim)", 2
    else:
        rep["verdict"], rep["exit"] = "PASS — no affected High/Critical advisory in the assessed scope", 0
        if rep["not_assessed"]:
            rep["verdict"] += f" ({len(rep['not_assessed'])} target(s) Not Assessed — see that section)"
    if blocking and (rep["failures"] or unrated):
        rep["verdict"] += "; assessment also incomplete"
    return rep


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(out)


def render(rep, only):
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    lines = ["# Dependency advisory status", "",
             f"- Commit: `{commit or 'unknown'}`",
             f"- Measured: {rep['started']} → {rep['finished']} (UTC)",
             f"- Command: `bash tools/ci/check-dependency-advisories.sh`"
             + ("" if only == {"gems", "actions", "native"} else f" (surfaces: {', '.join(sorted(only))})"),
             f"- **Verdict: {rep['verdict']}** (exit {rep['exit']})", ""]
    lines += ["## Scanners and database dates", "",
              md_table(["Surface", "Scanner", "Database date", "Queried (UTC)"],
                       [(s["surface"], s["scanner"], s["database_date"], s["queried"]) for s in rep["scanners"]]), ""]
    if rep["failures"]:
        lines += ["## Required scanners that did not run", ""] + [f"- {f}" for f in rep["failures"]] + [""]
    if rep["not_assessed"]:
        lines += ["## Not Assessed", ""] + [f"- {n}" for n in rep["not_assessed"]] + [""]
    advs = sorted(rep["advisories"], key=lambda a: (-SEV_ORDER.index(a["severity"]) if a["severity"] else -9,
                                                    a["surface"], a["target"], a["package"], a["id"]))
    lines += ["## Affected advisories", "",
              "Severity is the highest of every available rating (advisory label, distro "
              "priority, CVSS v3 base score); each rating is listed. Targets are the pinned "
              "images of the distro table below.", ""]
    if advs:
        lines += [md_table(["Severity", "Surface", "Target", "Package @ installed", "Advisory", "Aliases",
                            "Ratings", "Disposition", "Fixed in"],
                           [(a["severity"] or "NOT ASSESSED", a["surface"], a["target"].split("@sha256:")[0],
                             f"{a['package']} @ {a['installed']}", a["id"], ", ".join(a["aliases"]) or "—",
                             "; ".join(a["ratings"]) or "none", a["disposition"], ", ".join(a["fixed"]) or "—")
                            for a in advs]), ""]
    else:
        lines += ["None in the assessed scope.", ""]
    if rep["native"]:
        lines += [f"## Release distro dependencies (platform {rep.get('native_platform', 'unknown')})", "",
                  "Upstream base = upstream version inside the distro revision; `Feed records` = "
                  "advisories the distro feed holds for the source package (queried by source name); "
                  "`Fixed by backport` counts those the distro fixed without moving that base.", "",
                  md_table(["Image", "Package", "Revision", "Source @ revision", "Upstream base",
                            "Feed records", "Fixed by backport", "Affected"],
                           [(f"`{r['image']}`", r["package"], r["version"],
                             f"{r['source']} @ {r['source_version']}", r["upstream_base"],
                             r["feed_records"] if r["assessed"] else "Not Assessed",
                             r["backported"] if r["assessed"] else "Not Assessed",
                             r["affected"] if r["assessed"] else "Not Assessed") for r in rep["native"]]), ""]
    if rep["gems"]:
        lines += [f"## Resolved docs gems ({LOCKFILE})", "",
                  md_table(["Gem", "Version", "Affected"],
                           [(g["gem"], g["version"], g["affected"]) for g in rep["gems"]]), ""]
    if rep["actions"]:
        lines += ["## Pinned GitHub Actions", "",
                  md_table(["Action", "Release (pin comment)", "Commit", "Affected"],
                           [(a["action"], a["version"] or "NOT ASSESSED", a["ref"][:12], a["affected"])
                            for a in rep["actions"]]), ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Self-test (offline)
# --------------------------------------------------------------------------

def self_test():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    check("cvss 9.8", cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8)
    check("cvss 8.6 scope changed", cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:H") == 8.6)
    # v3.1 changed only the environmental (modified) impact term; the base
    # scope-changed formula is the v3.0 one (FIRST v3.1 spec section 7.1).
    check("cvss 3.1 scope changed base 8.5", cvss3_score("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H") == 8.5)
    check("cvss 3.1 scope changed base 6.9", cvss3_score("CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H") == 6.9)
    check("cvss 7.3", cvss3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N") == 7.3)
    check("cvss 5.9", cvss3_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H") == 5.9)
    check("cvss zero impact", cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0)
    check("cvss v4 not scored", cvss3_score("CVSS:4.0/AV:N/AC:L") is None)
    check("labels", [score_label(x) for x in (0, 3.9, 4.0, 7.0, 9.0)] == ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    check("worst is conservative", worst([("MEDIUM", "Ubuntu priority"), ("HIGH", "CVSS 7.5")]) == "HIGH")
    check("unrated stays unrated", worst([]) is None)
    check("deb base", upstream_base("2.9.13+dfsg-1ubuntu0.3", "deb") == "2.9.13")
    check("deb epoch base", upstream_base("1:2.36-9+deb12u10", "deb") == "2.36")
    check("rpm base", upstream_base("0:2.9.13-14.el9_8.4", "rpm") == "2.9.13")
    check("backport fixed", classify_distro("2.9.13+dfsg-1ubuntu0.9", ["2.9.13+dfsg-1ubuntu0.5"], False, "deb") == "fixed-by-backport")
    check("backport available", classify_distro("2.9.13+dfsg-1ubuntu0.3", ["2.9.13+dfsg-1ubuntu0.5"], True, "deb") == "backport-available")
    check("upstream gap", classify_distro("2.9.13+dfsg-1", ["2.10.0-1"], True, "deb") == "upstream-version-gap")
    check("unfixed", classify_distro("2.9.13+dfsg-1", [], True, "deb") == "unfixed")
    lock = ("GEM\n  remote: https://rubygems.org/\n  specs:\n    ffi (1.17.4)\n"
            "    ffi (1.17.4-x86_64-linux-gnu)\n    jekyll (4.4.1)\n      addressable (~> 2.4)\n\n"
            "PLATFORMS\n  ruby\n")
    check("lockfile", parse_lockfile(lock) == {"ffi": "1.17.4", "jekyll": "4.4.1"})
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
        fh.write("    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
                 "      uses: github/codeql-action/init@b96794f015dfd88f77b49b1c93e0fa7110f94c63 # v4.38.0\n"
                 "    - uses: ./.github/actions/bootstrap-deps\n"
                 "    - uses: some/action@0123456789012345678901234567890123456789\n")
    got = parse_actions([fh.name])
    os.unlink(fh.name)
    check("actions parse", [(n, v) for n, v, _r, _p in got] ==
          [("actions/checkout", "7.0.1"), ("github/codeql-action", "4.38.0"), ("some/action", None)])
    check("distro map", distro_of("debian:12@sha256:ab") == ("Debian:12", "deb")
          and distro_of("quay.io/centos/centos:stream9@sha256:cd") == (None, "rpm"))
    # Fail closed: an alias whose ratings could not be fetched is a failure,
    # not a silently weaker severity.
    saved_api, globals()["OSV_API"] = OSV_API, "http://127.0.0.1:9"
    resolve_osv_rating({"id": "UBUNTU-CVE-0000-0", "upstream": ["CVE-0000-0"]})
    globals()["OSV_API"] = saved_api
    check("alias lookup fails closed", len(ALIAS_FAILURES) == 1)
    ALIAS_FAILURES.clear()
    _OSV_CACHE.clear()
    # Fail closed: an unreachable scanner must yield exit 2, never a PASS.
    env = dict(os.environ, OSV_API="http://127.0.0.1:9", GHSA_API="http://127.0.0.1:9",
               OSV_DB_URL="http://127.0.0.1:9")
    for surface in ("gems", "actions"):
        res = subprocess.run(["bash", SCRIPT, "--only", surface], capture_output=True, text=True,
                             env=env, timeout=300)
        check(f"fail closed ({surface})", res.returncode == 2 and "NOT ASSESSED" in res.stdout)
    for name, ok in checks:
        print(f"{'✓' if ok else '✗'} {name}")
    bad = [n for n, ok in checks if not ok]
    print(f"{len(checks) - len(bad)}/{len(checks)} self-test checks passed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(prog="check-dependency-advisories.sh")
    ap.add_argument("--out", help="write the Markdown report here (default: stdout)")
    ap.add_argument("--json", help="also write the raw measurement as JSON")
    ap.add_argument("--only", action="append", choices=["gems", "actions", "native"],
                    help="restrict to one surface (repeatable)")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test")
    a = ap.parse_args(ARGS)
    if a.self_test:
        return self_test()
    only = set(a.only or ["gems", "actions", "native"])
    rep = measure(only)
    text = render(rep, only)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"report written to {a.out}")
        print(rep["verdict"])
    else:
        print(text)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2, sort_keys=True)
    for f in rep["failures"]:
        print(f"✗ {f}", file=sys.stderr)
    return rep["exit"]


try:
    sys.exit(main())
except Exception as exc:  # an unexpected crash is incomplete, never exit 1 (confirmed)
    print(f"✗ assessment aborted: {exc!r}", file=sys.stderr)
    sys.exit(2)
PYEOF
