#!/usr/bin/env python3
"""check-accuracy-corpus.py -- oracle for the reviewed accuracy corpus:
DNS/TLS/QUIC/HTTP-2 (issue #389), S1AP/NGAP/NAS and unknown/malformed traffic
(issue #390), F-TEST-003; per-classifier coverage of the default TCP/UDP
chains (issue #527, F-BUG-313).

The corpus lives in tools/phase0/ci/accuracy/: one synthetic capture per case
plus corpus.json, which records for every capture its protocol family, whether
it is a positive, negative, ambiguous or unknown case, the expected per-packet
handling, its redistribution provenance and its review notes. The captures are
NOT part of tools/phase0/ci/golden_pcaps.txt, so the golden classification
fingerprint's input set is unchanged.

Protocol families need both a positive and a negative/ambiguous case. The
"abstention" family (``"abstention": true``, no wire labels) holds unknown and
malformed inputs: its cases are of kind "unknown" and state explicitly how many
packets the SDK abstains on and which (if any) it still attributes.

Classifier coverage (issue #527): a case may name, in "classifiers", the
mmt_check_* functions of the default TCP/UDP chains it exercises. Every
classifier registered in src/mmt_tcpip/lib/inter_proto_classif_list.def
(commented-out registrations excluded) needs a positive case and a
negative/ambiguous case naming it, or an entry in coverage-pending.txt next to
corpus.json. The pending list only shrinks: an entry for a covered or no
longer registered classifier fails, as does a case naming a classifier the
chains do not register. With --base REF the oracle also reads
tools/phase0/ci/accuracy/coverage-pending.txt and the chain definition at REF
(`git show`) and fails on a pending entry that REF's list lacks although REF's
chains already register it -- a covered classifier cannot move back to
pending; only a newly registered one may enter. A REF that does not resolve,
or lacks the chain file, is an environment error; a REF without the pending
file (it predates issue #527) skips this ratchet with a note.

The oracle:
  0. checks classifier coverage against the chains and the pending list
     (and, with --base, the pending list against the base commit's);
  1. validates the manifest strictly -- a missing capture, a capture on disk
     that has no manifest entry, a missing label/provenance/review field, a
     sha256 mismatch, a generator that no longer reproduces the committed
     bytes, or a family without its required cases is a failure, never a skip;
  2. (unless --offline) classifies every listed capture with
     tools/phase0/phase0_classify.c against a built SDK and compares the
     per-packet handling with the expectation:
       wire        -- the packet carries the family's wire-protocol label
       other       -- the packet is attributed to a different application
                      protocol (keyed by the outermost one)
       abstain     -- no application verdict at all
       attribution -- application names the SDK derives heuristically BENEATH
                      the wire label (e.g. ssl.google from a TLS SNI); reported
                      separately and never counted as wire-protocol accuracy.
                      A protocol that is itself some family's wire label
                      (nas_5g beneath ngap) is encapsulation, not attribution.
     SCTP chunk layers (sctp_data, sctp_init, ...) are transport, like tcp.
  3. prints per-family support (packets in positive cases), wire hits,
     abstentions and misattributions, negative/ambiguous handling, the
     unknown/malformed abstention table, and the heuristic attribution table
     on its own.

Usage:
  check-accuracy-corpus.py                     # build+install SDK in a temp prefix
                                               # (runs `make -C sdk clean` before
                                               # and after: the in-tree objects
                                               # would otherwise keep the deleted
                                               # temp prefix baked in)
  check-accuracy-corpus.py --prefix P --no-build   # reuse an installed prefix
  check-accuracy-corpus.py --classify-bin BIN  # use a prebuilt phase0_classify
  check-accuracy-corpus.py --offline           # manifest + reproducibility only
  options: --corpus DIR (default tools/phase0/ci/accuracy), --json,
           --chain FILE (default src/mmt_tcpip/lib/inter_proto_classif_list.def),
           --base REF (shrink-only ratchet against the pending list at REF;
           CI passes HEAD^1), --base-repo DIR (git repository REF is read
           from, default this checkout)

Exit: 0 = pass, 1 = corpus/expectation failure, 2 = usage or environment error.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SELF_DIR, "..", "..", ".."))
DEFAULT_CORPUS = os.path.join(REPO_ROOT, "tools", "phase0", "ci", "accuracy")
CLASSIFY_SRC = os.path.join(REPO_ROOT, "tools", "phase0", "phase0_classify.c")
CHAIN_DEF = os.path.join(REPO_ROOT, "src", "mmt_tcpip", "lib",
                         "inter_proto_classif_list.def")
PENDING_FILE = "coverage-pending.txt"
# Canonical repo-relative paths read at the --base REF.
BASE_PENDING = "tools/phase0/ci/accuracy/" + PENDING_FILE
BASE_CHAIN = "src/mmt_tcpip/lib/inter_proto_classif_list.def"
CLASSIFIER_RE = re.compile(r"^mmt_check_[a-z0-9_]+$")

CASE_KINDS = ("positive", "negative", "ambiguous", "unknown")
# Families issues #389 and #390 require; dropping one is a failure.
REQUIRED_FAMILIES = ("dns", "tls", "quic", "http2", "s1ap", "ngap", "nas",
                     "unknown")

# Link / network / transport names that never count as an application verdict
# -- the same list as tools/phase0/phase0_precision.c.
NON_APP = {
    "meta", "ethernet", "ip", "ipv4", "ipv6", "arp", "rarp",
    "tcp", "udp", "sctp", "icmp", "icmpv6", "igmp", "gre",
    "ppp", "pppoe", "vlan", "mpls", "sll", "ipsec", "esp", "ah",
    "unknown", "?", "<none>",
    # SCTP chunk layers (mmt_tcpip_protocols.h PROTO_SCTP_*_ALIAS): transport
    "sctp_data", "sctp_sack", "sctp_init", "sctp_heartbeat", "sctp_shutdown",
    "sctp_shutdown_complete", "sctp_abort", "sctp_error", "sctp_cookie_echo",
    "sctp_ecne", "sctp_cwr", "sctp_auth", "sctp_asconf", "sctp_re_config",
}


class CorpusError(Exception):
    """A corpus or expectation failure (exit 1)."""


class EnvError(Exception):
    """Build/tooling failure unrelated to the corpus content (exit 2)."""


# --------------------------------------------------------------------------
# manifest validation
# --------------------------------------------------------------------------

def _need(obj, key, typ, where):
    if not isinstance(obj, dict) or key not in obj:
        raise CorpusError("%s: missing field %r" % (where, key))
    val = obj[key]
    if not isinstance(val, typ) or (isinstance(val, bool) and typ is int):
        raise CorpusError("%s: field %r must be %s" % (where, key, typ.__name__))
    if isinstance(val, str) and not val.strip():
        raise CorpusError("%s: field %r is empty" % (where, key))
    return val


def _count_map(obj, key, where):
    m = _need(obj, key, dict, where)
    for name, n in m.items():
        if not name or not isinstance(n, int) or isinstance(n, bool) or n <= 0:
            raise CorpusError("%s: %s entry %r must be a positive count"
                              % (where, key, name))
    return m


def load_manifest(corpus_dir):
    path = os.path.join(corpus_dir, "corpus.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            man = json.load(fh)
    except OSError as e:
        raise CorpusError("cannot read manifest %s: %s" % (path, e))
    except ValueError as e:
        raise CorpusError("manifest %s is not valid JSON: %s" % (path, e))

    if not isinstance(man, dict):
        raise CorpusError("manifest %s must be a JSON object" % path)
    if man.get("schema") != 1:
        raise CorpusError("manifest: unsupported schema %r (expected 1)"
                          % man.get("schema"))
    families = _need(man, "families", dict, "manifest")
    missing_fams = [f for f in REQUIRED_FAMILIES if f not in families]
    if missing_fams:
        raise CorpusError("manifest: required family(ies) missing: %s"
                          % ", ".join(missing_fams))
    unknown = families["unknown"]
    if not isinstance(unknown, dict) or unknown.get("abstention") is not True:
        raise CorpusError("family unknown: must be the abstention family "
                          "(\"abstention\": true)")
    for fam, spec in families.items():
        labels = _need(spec, "wire_labels", list, "family %s" % fam)
        abstention = spec.get("abstention", False)
        if not isinstance(abstention, bool):
            raise CorpusError("family %s: abstention must be true or false"
                              % fam)
        if abstention:
            if labels:
                raise CorpusError("family %s: an abstention family has no "
                                  "wire_labels" % fam)
        elif not labels or not all(isinstance(x, str) and x for x in labels):
            raise CorpusError("family %s: wire_labels must be non-empty names"
                              % fam)
    for fam in REQUIRED_FAMILIES:
        if fam != "unknown" and families[fam].get("abstention"):
            raise CorpusError("family %s: a required protocol family cannot "
                              "be an abstention family" % fam)
    cases = _need(man, "cases", list, "manifest")
    if not cases:
        raise CorpusError("manifest: no cases listed")

    seen = set()
    for i, c in enumerate(cases):
        where = "case #%d" % (i + 1)
        pcap = _need(c, "pcap", str, where)
        where = "case %s" % pcap
        if os.path.basename(pcap) != pcap or not pcap.endswith(".pcap"):
            raise CorpusError("%s: pcap must be a bare *.pcap file name" % where)
        if pcap in seen:
            raise CorpusError("%s: listed twice" % where)
        seen.add(pcap)
        fam = _need(c, "family", str, where)
        if fam not in families:
            raise CorpusError("%s: unknown family %r" % (where, fam))
        kind = _need(c, "case", str, where)
        if kind not in CASE_KINDS:
            raise CorpusError("%s: case must be one of %s, got %r"
                              % (where, "/".join(CASE_KINDS), kind))
        if (kind == "unknown") != bool(families[fam].get("abstention")):
            raise CorpusError("%s: case 'unknown' belongs to the abstention "
                              "family and only there (family %s, case %s)"
                              % (where, fam, kind))
        classifiers = c.get("classifiers", [])
        if (not isinstance(classifiers, list)
                or not all(isinstance(x, str) and CLASSIFIER_RE.match(x)
                           for x in classifiers)
                or len(set(classifiers)) != len(classifiers)):
            raise CorpusError("%s: classifiers must be a list of distinct "
                              "mmt_check_* names" % where)
        if classifiers and kind == "unknown":
            raise CorpusError("%s: an unknown case exercises no classifier"
                              % where)
        _need(c, "description", str, where)
        digest = _need(c, "sha256", str, where)
        if len(digest) != 64 or any(ch not in "0123456789abcdef"
                                    for ch in digest.lower()):
            raise CorpusError("%s: sha256 must be 64 hex digits" % where)

        exp = _need(c, "expected", dict, where)
        packets = _need(exp, "packets", int, where + " expected")
        wire = _need(exp, "wire", int, where + " expected")
        abstain = _need(exp, "abstain", int, where + " expected")
        other = _count_map(exp, "other", where + " expected")
        attribution = _count_map(exp, "attribution", where + " expected")
        if min(packets, wire, abstain) < 0 or packets == 0:
            raise CorpusError("%s: expected counts must be >= 0 and packets > 0"
                              % where)
        if wire + abstain + sum(other.values()) != packets:
            raise CorpusError("%s: expected wire+abstain+other (%d) != packets "
                              "(%d)" % (where, wire + abstain
                                        + sum(other.values()), packets))
        if sum(attribution.values()) > wire:
            raise CorpusError("%s: attribution exceeds wire packets" % where)
        if kind == "positive" and wire == 0:
            raise CorpusError("%s: a positive case must expect wire > 0" % where)
        if kind != "positive" and (wire or attribution):
            raise CorpusError("%s: a %s case must expect wire == 0 (a verdict "
                              "for the family would be a false accept)"
                              % (where, kind))

        prov = _need(c, "provenance", dict, where)
        origin = _need(prov, "origin", str, where + " provenance")
        _need(prov, "redistribution", str, where + " provenance")
        if origin == "synthetic":
            gen = _need(prov, "generator", dict, where + " provenance")
            _need(gen, "script", str, where + " provenance.generator")
            _need(gen, "pcap", str, where + " provenance.generator")
        review = _need(c, "review", dict, where)
        _need(review, "reviewed_in", str, where + " review")
        _need(review, "date", str, where + " review")
        checks = _need(review, "checks", list, where + " review")
        if not checks or not all(isinstance(x, str) and x.strip()
                                 for x in checks):
            raise CorpusError("%s: review.checks must list what was reviewed"
                              % where)

    for fam in families:
        kinds = {c["case"] for c in cases if c["family"] == fam}
        if families[fam].get("abstention"):
            if not kinds:
                raise CorpusError("family %s: no unknown/malformed case" % fam)
            continue
        if "positive" not in kinds:
            raise CorpusError("family %s: no positive case" % fam)
        if not kinds & {"negative", "ambiguous"}:
            raise CorpusError("family %s: no negative/ambiguous case" % fam)
    return man


# --------------------------------------------------------------------------
# classifier coverage (issue #527)
# --------------------------------------------------------------------------

def load_chain(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        raise EnvError("cannot read classifier chain %s: %s" % (path, e))
    return parse_chain(text, path)


def parse_chain(text, path):
    """Ordered distinct classifiers registered in the default TCP/UDP chains:
    every MMT_INTER_PROTO(PROTO_TCP|PROTO_UDP, fn, weight) row outside a
    comment."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    rows = re.findall(r"\bMMT_INTER_PROTO\s*\(\s*PROTO_(TCP|UDP)\s*,"
                      r"\s*(\w+)\s*,\s*\d+\s*\)", text)
    chain = {}
    for transport, fn in rows:
        chain.setdefault(fn, []).append(transport.lower())
    if not chain:
        raise EnvError("no MMT_INTER_PROTO(PROTO_TCP|PROTO_UDP, ...) row in %s"
                       % path)
    return chain


def load_pending(corpus_dir):
    path = os.path.join(corpus_dir, PENDING_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        raise CorpusError("cannot read %s: %s" % (PENDING_FILE, e))
    return parse_pending(text, PENDING_FILE)


def parse_pending(text, name):
    pending = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        body, _, reason = line.partition("#")
        body = body.strip()
        if not body:
            continue
        where = "%s:%d" % (name, lineno)
        if not CLASSIFIER_RE.match(body):
            raise CorpusError("%s: %r is not an mmt_check_* name" % (where,
                                                                     body))
        if not reason.strip():
            raise CorpusError("%s: %s needs a '# reason'" % (where, body))
        if body in pending:
            raise CorpusError("%s: %s listed twice" % (where, body))
        pending[body] = reason.strip()
    return pending


def check_coverage(man, chain, pending):
    """Require a positive and a negative/ambiguous case per chain
    classifier, unless it is pending; the pending list only shrinks."""
    positive, negative = set(), set()
    for c in man["cases"]:
        for fn in c.get("classifiers", []):
            if fn not in chain:
                raise CorpusError("case %s: classifier %s is not registered "
                                  "in the default TCP/UDP chains"
                                  % (c["pcap"], fn))
            (positive if c["case"] == "positive" else negative).add(fn)
    covered = [fn for fn in chain if fn in positive and fn in negative]
    stale = sorted(fn for fn in pending if fn not in chain)
    if stale:
        raise CorpusError("%s lists classifier(s) the default chains no "
                          "longer register: %s -- remove them"
                          % (PENDING_FILE, ", ".join(stale)))
    done = [fn for fn in covered if fn in pending]
    if done:
        raise CorpusError("%s lists classifier(s) that now have a positive "
                          "and a negative case: %s -- remove them (the list "
                          "only shrinks)" % (PENDING_FILE, ", ".join(done)))
    missing = []
    for fn in chain:
        if fn in covered or fn in pending:
            continue
        lacks = [k for k, s in (("positive", positive),
                                ("negative/ambiguous", negative))
                 if fn not in s]
        missing.append("%s (no %s case)" % (fn, " or ".join(lacks)))
    if missing:
        raise CorpusError("default-chain classifier(s) without a positive and "
                          "a negative case and not in %s: %s"
                          % (PENDING_FILE, "; ".join(missing)))
    return {"classifiers": len(chain), "covered": len(covered),
            "pending": len(pending),
            "covered_classifiers": covered,
            "pending_classifiers": [fn for fn in chain if fn in pending]}


def _git_show(repo, ref, path):
    """Text of `path` at `ref`, or None when `ref` lacks it. A `ref` that
    does not resolve to a commit is an environment error."""
    try:
        rev = subprocess.run(["git", "-C", repo, "rev-parse", "--verify",
                              "--quiet", ref + "^{commit}"],
                             capture_output=True, text=True)
        if rev.returncode != 0:
            raise EnvError("--base %s does not resolve to a commit in %s "
                           "(fetch it, e.g. checkout fetch-depth: 2)"
                           % (ref, repo))
        commit = rev.stdout.strip()
        if subprocess.run(["git", "-C", repo, "cat-file", "-e",
                           "%s:%s" % (commit, path)],
                          capture_output=True).returncode != 0:
            return None
        show = subprocess.run(["git", "-C", repo, "show",
                               "%s:%s" % (commit, path)],
                              capture_output=True, text=True)
    except OSError as e:
        raise EnvError("cannot run git for --base %s: %s" % (ref, e))
    if show.returncode != 0:
        raise EnvError("git show %s:%s failed: %s"
                       % (ref, path, show.stderr.strip()))
    return show.stdout


def check_base_ratchet(pending, ref, repo):
    """The pending list only shrinks: an entry REF's list lacks is allowed
    only for a classifier REF's chains do not register yet. Returns a status
    line, or None when REF predates the pending list."""
    chain_text = _git_show(repo, ref, BASE_CHAIN)
    if chain_text is None:
        raise EnvError("--base %s has no %s" % (ref, BASE_CHAIN))
    base_chain = parse_chain(chain_text, "%s:%s" % (ref, BASE_CHAIN))
    pending_text = _git_show(repo, ref, BASE_PENDING)
    if pending_text is None:
        return None
    base_pending = parse_pending(pending_text, "%s:%s" % (ref, BASE_PENDING))
    added = [fn for fn in pending
             if fn not in base_pending and fn in base_chain]
    if added:
        raise CorpusError("%s adds classifier(s) the base %s already "
                          "registered: %s -- the list only shrinks; add their "
                          "cases instead" % (PENDING_FILE, ref,
                                             ", ".join(sorted(added))))
    return ("✓ ratchet: %s adds no classifier registered at the base %s "
            "(%d pending there, %d now)" % (PENDING_FILE, ref,
                                            len(base_pending), len(pending)))


def check_files(man, corpus_dir):
    listed = {c["pcap"] for c in man["cases"]}
    on_disk = {n for n in os.listdir(corpus_dir) if n.endswith(".pcap")}
    missing = sorted(listed - on_disk)
    if missing:
        raise CorpusError("missing capture(s) listed in corpus.json: %s -- a "
                          "listed case may never be dropped"
                          % ", ".join(missing))
    unlisted = sorted(on_disk - listed)
    if unlisted:
        raise CorpusError("capture(s) without a corpus.json label: %s"
                          % ", ".join(unlisted))
    for c in man["cases"]:
        with open(os.path.join(corpus_dir, c["pcap"]), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        if digest != c["sha256"].lower():
            raise CorpusError("%s: sha256 %s does not match the reviewed "
                              "capture %s -- re-review and update corpus.json"
                              % (c["pcap"], digest, c["sha256"]))


def check_reproducible(man, corpus_dir):
    """Regenerate every synthetic capture and require byte identity, so the
    recorded provenance (generator + constants in the tree) is verifiable.
    One generator run per script (`--pcap NAME...`) regenerates its cases."""
    tmp = tempfile.mkdtemp(prefix="acc-regen.")
    try:
        by_script = {}
        for c in man["cases"]:
            prov = c["provenance"]
            if prov["origin"] != "synthetic":
                continue
            by_script.setdefault(prov["generator"]["script"], []).append(c)
        for rel, cases in sorted(by_script.items()):
            script = os.path.join(REPO_ROOT, rel)
            if not os.path.isfile(script):
                raise CorpusError("%s: generator %s not found"
                                  % (cases[0]["pcap"], rel))
            names = [c["provenance"]["generator"]["pcap"] for c in cases]
            proc = subprocess.run(
                [sys.executable, script, "--out-dir", tmp, "--pcap", *names],
                capture_output=True, text=True)
            for c in cases:
                gen = c["provenance"]["generator"]
                out = os.path.join(tmp, gen["pcap"] + ".pcap")
                if proc.returncode != 0 or not os.path.isfile(out):
                    raise CorpusError("%s: generator failed: %s"
                                      % (c["pcap"], proc.stderr.strip()))
                with open(out, "rb") as a, \
                        open(os.path.join(corpus_dir, c["pcap"]), "rb") as b:
                    if a.read() != b.read():
                        raise CorpusError("%s: committed capture differs from "
                                          "its generator output (%s --pcap %s)"
                                          % (c["pcap"], gen["script"],
                                             gen["pcap"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# classification + evaluation
# --------------------------------------------------------------------------

def parse_fingerprint(pcap, text):
    rows = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        count, sep, path = line.partition("\t")
        if not sep or not count.isdigit() or not path.strip():
            raise CorpusError("%s: malformed classifier line %d: %r"
                              % (pcap, lineno, line))
        rows.append((int(count), path.strip()))
    if not rows:
        raise CorpusError("%s: classifier produced no output" % pcap)
    return rows


def evaluate(rows, wire_labels, protocol_labels=()):
    """protocol_labels: every family's wire labels. One of them beneath the
    wire label is an encapsulated protocol (nas_5g in ngap), not a heuristic
    attribution."""
    obs = {"packets": 0, "wire": 0, "abstain": 0, "other": {},
           "attribution": {}}
    labels = {x.lower() for x in wire_labels}
    protocols = {x.lower() for x in protocol_labels}
    for count, path in rows:
        obs["packets"] += count
        parts = [p.lower() for p in path.split(".")]
        apps = [(i, p) for i, p in enumerate(parts) if p not in NON_APP]
        wire_at = next((i for i, p in apps if p in labels), None)
        if wire_at is not None:
            obs["wire"] += count
            deeper = [p for i, p in apps if i > wire_at and p not in protocols]
            if deeper:
                name = deeper[-1]
                obs["attribution"][name] = obs["attribution"].get(name, 0) + count
        elif apps:
            name = apps[0][1]
            obs["other"][name] = obs["other"].get(name, 0) + count
        else:
            obs["abstain"] += count
    return obs


def _run(cmd, log, cwd=None, env=None):
    with open(log, "a") as fh:
        rc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                            cwd=cwd, env=env).returncode
    if rc != 0:
        with open(log) as fh:
            tail = "".join(fh.readlines()[-20:])
        raise EnvError("command failed (%s): %s\n%s"
                       % (rc, " ".join(cmd), tail))


def prepare_classifier(args, workdir):
    """Return (classify_bin, lib_dir-or-None)."""
    if args.classify_bin:
        lib = os.path.join(args.prefix, "dpi", "lib") if args.prefix else None
        return os.path.abspath(args.classify_bin), lib
    prefix = args.prefix or os.path.join(workdir, "prefix")
    log = os.path.join(workdir, "build.log")
    if not args.no_build:
        jobs = str(os.cpu_count() or 4)
        sdk = os.path.join(REPO_ROOT, "sdk")
        print("[build] SDK -> %s (discards the in-tree sdk/ build)" % prefix,
              flush=True)
        # Clean first (profile-switch rule, docs/AGENT_ENVIRONMENT.md §5) and
        # afterwards: the objects compiled here bake the temporary prefix into
        # plugins_engine.o, so an in-tree build left behind would look for
        # plugins under a deleted directory.
        _run(["make", "-C", sdk, "clean"], log)
        try:
            _run(["make", "-C", sdk, "-j" + jobs, "MMT_BASE=" + prefix], log)
            _run(["make", "-C", sdk, "MMT_BASE=" + prefix, "install"], log)
        finally:
            subprocess.run(["make", "-C", sdk, "clean"],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    inc = os.path.join(prefix, "dpi", "include")
    lib = os.path.join(prefix, "dpi", "lib")
    if not os.path.isdir(inc) or not os.path.isdir(lib):
        raise EnvError("no installed SDK under %s (drop --no-build or pass an "
                       "installed --prefix)" % prefix)
    binary = os.path.join(workdir, "phase0_classify")
    _run(["gcc", "-O2", "-o", binary, CLASSIFY_SRC, "-I", inc, "-L", lib,
          "-lmmt_core", "-ldl", "-lpcap"], log)
    return binary, lib


def classify_all(man, corpus_dir, binary, lib, workdir):
    env = dict(os.environ)
    if lib:
        env["LD_LIBRARY_PATH"] = lib + (":" + env["LD_LIBRARY_PATH"]
                                        if env.get("LD_LIBRARY_PATH") else "")
    neutral = os.path.join(workdir, "run")   # no ./plugins here (README note)
    os.makedirs(neutral, exist_ok=True)
    results = []
    protocols = sorted({x for spec in man["families"].values()
                        for x in spec["wire_labels"]})
    for c in man["cases"]:
        pcap = os.path.join(corpus_dir, c["pcap"])
        proc = subprocess.run([binary, pcap], capture_output=True, text=True,
                              cwd=neutral, env=env)
        if proc.returncode != 0:
            raise CorpusError("%s: classifier exited %d: %s"
                              % (c["pcap"], proc.returncode,
                                 proc.stderr.strip()))
        rows = parse_fingerprint(c["pcap"], proc.stdout)
        wire_labels = man["families"][c["family"]]["wire_labels"]
        results.append((c, evaluate(rows, wire_labels, protocols)))
    return results


def compare(results):
    failures = []
    for c, obs in results:
        exp = c["expected"]
        diffs = [k for k in ("packets", "wire", "abstain", "other",
                             "attribution") if obs[k] != exp[k]]
        if diffs:
            failures.append("%s (%s %s): %s" % (
                c["pcap"], c["family"], c["case"],
                "; ".join("%s expected %s got %s"
                          % (k, json.dumps(exp[k], sort_keys=True),
                             json.dumps(obs[k], sort_keys=True))
                          for k in diffs)))
    return failures


def summarize(man, results):
    fams = {}
    attribution = []
    for c, obs in results:
        other = sum(obs["other"].values())
        if c["case"] == "unknown":
            # abstention family: its own keys, never negative-case ones
            f = fams.setdefault(c["family"], {
                "unknown_cases": 0, "packets": 0, "abstain": 0,
                "accepted": 0})
            f["unknown_cases"] += 1
            f["packets"] += obs["packets"]
            f["abstain"] += obs["abstain"]
            f["accepted"] += other
            continue
        f = fams.setdefault(c["family"], {
            "positive_cases": 0, "support": 0, "wire": 0, "abstain": 0,
            "misattributed": 0, "negative_cases": 0, "ambiguous_cases": 0,
            "neg_packets": 0, "false_accept": 0, "neg_abstain": 0,
            "neg_other": 0})
        if c["case"] == "positive":
            f["positive_cases"] += 1
            f["support"] += obs["packets"]
            f["wire"] += obs["wire"]
            f["abstain"] += obs["abstain"]
            f["misattributed"] += other
        else:
            f[c["case"] + "_cases"] += 1
            f["neg_packets"] += obs["packets"]
            f["false_accept"] += obs["wire"]
            f["neg_abstain"] += obs["abstain"]
            f["neg_other"] += other
        for name in sorted(obs["attribution"]):
            attribution.append((c["family"], c["pcap"], name,
                                obs["attribution"][name]))
    return {f: fams[f] for f in sorted(fams)}, attribution


def _is_unknown(f):
    return "unknown_cases" in f


def render(results, fams, attribution):
    out = ["# per capture (packets: wire / abstain / other; attribution "
           "reported separately)",
           "%-34s %-10s %-9s %-7s %-5s %-7s %s"
           % ("capture", "family", "case", "packets", "wire", "abstain",
              "other")]
    for c, obs in results:
        other = ",".join("%s:%d" % (k, obs["other"][k])
                         for k in sorted(obs["other"])) or "-"
        out.append("%-34s %-10s %-9s %-7d %-5d %-7d %s"
                   % (c["pcap"], c["family"], c["case"], obs["packets"],
                      obs["wire"], obs["abstain"], other))
    out += ["", "# per family -- wire-protocol accuracy (support and abstain "
            "include payload-less packets such as TCP SYN/ACK)",
            "%-10s %-9s %-7s %-5s %-7s %-6s | %-9s %-7s %-12s %-7s %s"
            % ("family", "positive", "support", "wire", "abstain", "other",
               "neg+amb", "packets", "false_accept", "abstain", "other")]
    for name, f in fams.items():
        if _is_unknown(f):
            continue
        out.append("%-10s %-9d %-7d %-5d %-7d %-6d | %-9d %-7d %-12d %-7d %d"
                   % (name, f["positive_cases"], f["support"], f["wire"],
                      f["abstain"], f["misattributed"],
                      f["negative_cases"] + f["ambiguous_cases"],
                      f["neg_packets"], f["false_accept"], f["neg_abstain"],
                      f["neg_other"]))
    out += ["", "# unknown / malformed inputs -- explicit abstention "
            "expectations (accepted = still given an application verdict)",
            "%-34s %-7s %-7s %s" % ("capture", "packets", "abstain",
                                    "accepted")]
    for c, obs in results:
        if c["case"] == "unknown":
            accepted = ",".join("%s:%d" % (k, obs["other"][k])
                                for k in sorted(obs["other"])) or "-"
            out.append("%-34s %-7d %-7d %s" % (c["pcap"], obs["packets"],
                                               obs["abstain"], accepted))
    out += ["", "# heuristic application attribution (beneath the wire label;"
            " not wire-protocol accuracy)"]
    if attribution:
        out.append("%-10s %-34s %-12s %s" % ("family", "capture", "application",
                                            "packets"))
        for fam, pcap, name, n in attribution:
            out.append("%-10s %-34s %-12s %d" % (fam, pcap, name, n))
    else:
        out.append("(none)")
    return "\n".join(out) + "\n"


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", default=DEFAULT_CORPUS)
    ap.add_argument("--chain", default=CHAIN_DEF,
                    help="classifier chain definition (default: %(default)s)")
    ap.add_argument("--base", metavar="REF",
                    help="fail on a pending entry REF's list lacks for a "
                         "classifier REF already registers (shrink-only)")
    ap.add_argument("--base-repo", metavar="DIR", default=REPO_ROOT,
                    help="git repository --base is read from "
                         "(default: %(default)s)")
    ap.add_argument("--prefix", help="SDK install prefix (default: a temp dir)")
    ap.add_argument("--no-build", action="store_true",
                    help="reuse the SDK already installed under --prefix")
    ap.add_argument("--classify-bin", help="prebuilt phase0_classify binary")
    ap.add_argument("--offline", action="store_true",
                    help="validate manifest, files and reproducibility only")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.no_build and not args.prefix:
        ap.error("--no-build needs --prefix")

    corpus = os.path.abspath(args.corpus)
    try:
        man = load_manifest(corpus)
        pending = load_pending(corpus)
        coverage = check_coverage(man, load_chain(args.chain), pending)
        ratchet = (check_base_ratchet(pending, args.base, args.base_repo)
                   if args.base else "")
        check_files(man, corpus)
        check_reproducible(man, corpus)
        print("✓ manifest: %d cases, %d families; files, labels, provenance, "
              "review and reproducibility OK"
              % (len(man["cases"]), len(man["families"])), flush=True)
        print("✓ coverage: %d/%d default-chain classifiers have a positive "
              "and a negative case; %d pending (%s)"
              % (coverage["covered"], coverage["classifiers"],
                 coverage["pending"], PENDING_FILE), flush=True)
        if ratchet is None:
            print("note: shrink-only ratchet skipped: %s has no %s"
                  % (args.base, BASE_PENDING), flush=True)
        elif ratchet:
            print(ratchet, flush=True)
        if args.offline:
            return 0
        workdir = tempfile.mkdtemp(prefix="acc-oracle.")
        try:
            binary, lib = prepare_classifier(args, workdir)
            results = classify_all(man, corpus, binary, lib, workdir)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        fams, attribution = summarize(man, results)
        if args.json:
            json.dump({"cases": [dict(pcap=c["pcap"], family=c["family"],
                                      case=c["case"], observed=o)
                                 for c, o in results],
                       "families": fams,
                       "coverage": coverage,
                       "attribution": [dict(family=a, pcap=b, application=n,
                                            packets=k)
                                       for a, b, n, k in attribution]},
                      sys.stdout, indent=1, sort_keys=True)
            sys.stdout.write("\n")
        else:
            sys.stdout.write(render(results, fams, attribution))
        failures = compare(results)
        if failures:
            sys.stderr.write("✗ accuracy corpus: %d case(s) diverge from the "
                             "reviewed expectation:\n" % len(failures))
            for f in failures:
                sys.stderr.write("  - %s\n" % f)
            return 1
        print("✓ accuracy corpus: all %d cases match the reviewed expectation"
              % len(results))
        return 0
    except CorpusError as e:
        sys.stderr.write("✗ accuracy corpus: %s\n" % e)
        return 1
    except EnvError as e:
        sys.stderr.write("✗ accuracy oracle environment: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
