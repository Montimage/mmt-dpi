#!/usr/bin/env python3
"""test-precision-metrics.py -- self-test for the phase0 precision/recall
metric accounting (issue #373, F-TEST-002).

Drives the REAL renderer (tools/phase0/ci/render_precision.py) on synthetic
raw TSV and asserts the confusion-matrix accounting exactly:

  - a true-FTP packet predicted HTTP increments HTTP false positives AND FTP
    false negatives;
  - abstentions count as FN of the actual class and as no class's FP;
  - precision/recall are exact for correct, incorrect, abstained and
    zero-support (predicted-only / never-predicted) classes;
  - malformed or empty harness output exits non-zero instead of silently
    dropping examples;
  - the seeded abstention set (issue #527) renders its unknown rate exactly,
    in its own section after the labelled metrics, without touching them,
    and a mislabelled or malformed abstention row fails.

Usage: python3 tools/ci/tests/test-precision-metrics.py
Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.
"""

import json
import os
import subprocess
import sys
import tempfile

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SELF_DIR, "..", "..", ".."))
RENDER = os.path.join(REPO_ROOT, "tools", "phase0", "ci", "render_precision.py")

PASS = 0
FAIL = 0
TESTED = 0


def run_render(tsv_text, *extra):
    """Feed `tsv_text` to the real renderer; return (rc, parsed_json_or_None,
    stderr). A missing file case passes a path that does not exist instead."""
    with tempfile.NamedTemporaryFile(
            "w", suffix=".tsv", delete=False) as f:
        f.write(tsv_text)
        path = f.name
    try:
        proc = subprocess.run(
            [sys.executable, RENDER, "--json", path, *extra],
            capture_output=True, text=True)
        try:
            payload = json.loads(proc.stdout) if proc.returncode == 0 else None
        except json.JSONDecodeError:
            payload = None
        return proc.returncode, payload, proc.stderr
    finally:
        os.unlink(path)


def check(name, cond, detail=""):
    global PASS, FAIL, TESTED
    TESTED += 1
    if cond:
        PASS += 1
        print("  ok   %-58s" % name)
    else:
        FAIL += 1
        print("  FAIL %-58s %s" % (name, detail))


def cls(payload, name):
    if not payload:
        return None
    for c in payload["classes"]:
        if c["name"] == name:
            return c
    return None


def close(a, b):
    return a is not None and abs(a - b) < 1e-9


print("render_precision.py metric-accounting self-test (issue #373, F-TEST-002)")
print()

if not os.path.isfile(RENDER):
    print("x missing renderer: %s" % RENDER, file=sys.stderr)
    sys.exit(2)

# --- 1. all-correct: TP only, precision == recall == 1 ------------------------
rc, p, err = run_render("a.pcap\tftp\t10\t10\t0\t0\tftp:10\n")
check("all-correct renders (rc 0)", rc == 0, err.strip())
c = cls(p, "ftp")
check("all-correct: ftp tp=10 fp=0 fn=0",
      c and c["tp"] == 10 and c["fp"] == 0 and c["fn"] == 0, c)
check("all-correct: ftp precision=1 recall=1",
      c and close(c["precision"], 1.0) and close(c["recall"], 1.0), c)

# --- 2. AC headline: true FTP predicted HTTP -> HTTP FP+1 AND FTP FN+1 --------
rc, p, err = run_render("a.pcap\tftp\t10\t9\t1\t0\tftp:9,http:1\n")
check("FTP->HTTP renders (rc 0)", rc == 0, err.strip())
c = cls(p, "ftp")
check("FTP->HTTP: ftp fn=1 (misclassification is a false negative)",
      c and c["fn"] == 1, c)
c = cls(p, "http")
check("FTP->HTTP: http fp=1 (predicted class takes the false positive)",
      c and c["fp"] == 1, c)
check("FTP->HTTP: http is zero-support (support=0, tp=0, recall n/a)",
      c and c["support"] == 0 and c["tp"] == 0 and c["recall"] is None, c)
check("FTP->HTTP: http precision=0 (0 TP / 1 FP)",
      c and close(c["precision"], 0.0), c)

# --- 3. abstained: FN of the actual class, FP of nobody -----------------------
rc, p, err = run_render("a.pcap\tftp\t5\t0\t0\t5\t-\n")
check("all-abstain renders (rc 0)", rc == 0, err.strip())
c = cls(p, "ftp")
check("all-abstain: ftp fn=5 fp=0 (abstention is FN, never FP)",
      c and c["fn"] == 5 and c["fp"] == 0, c)
check("all-abstain: ftp recall=0, precision n/a (0/0 denominator)",
      c and close(c["recall"], 0.0) and c["precision"] is None, c)
check("all-abstain: confusion records the <abstain> pseudo-column",
      p and p["confusion"].get("ftp", {}).get("<abstain>") == 5,
      p and p["confusion"])

# --- 4. mixed matrix: exact cross-class TP/FP/FN ------------------------------
rc, p, err = run_render(
    "a.pcap\tftp\t10\t8\t2\t0\tftp:8,http:2\n"
    "b.pcap\thttp\t10\t9\t1\t0\thttp:9,ftp:1\n")
check("mixed matrix renders (rc 0)", rc == 0, err.strip())
c = cls(p, "ftp")
check("mixed: ftp tp=8 fp=1 fn=2 support=10",
      c and c["tp"] == 8 and c["fp"] == 1 and c["fn"] == 2
      and c["support"] == 10, c)
check("mixed: ftp precision=8/9 recall=8/10",
      c and close(c["precision"], 8 / 9) and close(c["recall"], 0.8), c)
c = cls(p, "http")
check("mixed: http tp=9 fp=2 fn=1 support=10",
      c and c["tp"] == 9 and c["fp"] == 2 and c["fn"] == 1
      and c["support"] == 10, c)
check("mixed: http precision=9/11 recall=9/10",
      c and close(c["precision"], 9 / 11) and close(c["recall"], 0.9), c)
o = p and p["overall"]
check("mixed: overall tp=17 fp=3 fn=3 total=20",
      o and o["tp"] == 17 and o["fp"] == 3 and o["fn"] == 3
      and o["total"] == 20, o)
check("mixed: micro precision=17/20 recall=17/20 accuracy=17/20",
      o and close(o["micro_precision"], 0.85)
      and close(o["micro_recall"], 0.85) and close(o["accuracy"], 0.85), o)

# --- 5. multi-class: three-way confusion stays exact --------------------------
rc, p, err = run_render(
    "a.pcap\tftp\t10\t7\t3\t0\tftp:7,http:2,dns:1\n"
    "b.pcap\thttp\t10\t9\t1\t0\thttp:9,dns:1\n"
    "c.pcap\tdns\t10\t10\t0\t0\tdns:10\n")
check("three-class renders (rc 0)", rc == 0, err.strip())
c = cls(p, "dns")
check("three-class: dns tp=10 fp=2 (1 from ftp + 1 from http) fn=0",
      c and c["tp"] == 10 and c["fp"] == 2 and c["fn"] == 0, c)
check("three-class: dns precision=10/12 recall=1",
      c and close(c["precision"], 10 / 12) and close(c["recall"], 1.0), c)
c = cls(p, "ftp")
check("three-class: ftp fn=3 tp=7 fp=0",
      c and c["fn"] == 3 and c["tp"] == 7 and c["fp"] == 0, c)

# --- 6. fail-fast: malformed / empty harness output is never dropped ----------
rc, p, err = run_render("a.pcap\tftp\t10\t9\t1\t0\tftp:9,http:2\n")
check("inconsistent histogram (9+2 != tp+fp=10) -> rc 2", rc == 2, err.strip())
rc, p, err = run_render("a.pcap\tftp\t10\t8\t2\t0\tftp:9,http:1\n")
check("histogram[actual] != tp -> rc 2", rc == 2, err.strip())
rc, p, err = run_render("a.pcap\tftp\t10\t8\t1\t0\tftp:8,http:1\n")
check("tp+fp+abstained != total -> rc 2", rc == 2, err.strip())
rc, p, err = run_render("a.pcap\tftp\t10\t8\t2\t0\n")
check("missing predicted_csv column -> rc 2", rc == 2, err.strip())
rc, p, err = run_render("")
check("empty input -> rc 2", rc == 2, err.strip())
rc, p, err = run_render("a.pcap\tftp\tx\t8\t2\t0\tftp:8,http:2\n")
check("non-integer total -> rc 2", rc == 2, err.strip())

# --- 7. fail-fast: missing raw file -------------------------------------------
proc = subprocess.run([sys.executable, RENDER, "--json",
                       "/nonexistent/raw.tsv"],
                      capture_output=True, text=True)
check("missing input file -> rc 2", proc.returncode == 2,
      proc.stderr.strip())

# --- 8. determinism: identical input renders byte-identical --------------------
rc1, p1, _ = run_render("b.pcap\thttp\t10\t9\t1\t0\thttp:9,ftp:1\n"
                        "a.pcap\tftp\t10\t8\t2\t0\tftp:8,http:2\n")
rc2, p2, _ = run_render("b.pcap\thttp\t10\t9\t1\t0\thttp:9,ftp:1\n"
                        "a.pcap\tftp\t10\t8\t2\t0\tftp:8,http:2\n")
check("same input -> identical metrics", rc1 == 0 and p1 == p2)

# --- 9. abstention set (issue #527): unknown rate in its own section ---------
LABELLED = "a.pcap\tftp\t10\t9\t0\t1\tftp:9\n"
ABSTAIN = ("abstain_tcp_0016.pcap\t<abstain>\t40\t0\t2\t38\tdicom:2\n"
           "abstain_udp_0016.pcap\t<abstain>\t16\t0\t0\t16\t-\n")


def render_pair(labelled, abstain, *flags):
    """Run the renderer on a labelled TSV plus an --abstention TSV."""
    paths = []
    try:
        for text in (labelled, abstain):
            with tempfile.NamedTemporaryFile("w", suffix=".tsv",
                                             delete=False) as f:
                f.write(text)
                paths.append(f.name)
        proc = subprocess.run([sys.executable, RENDER, *flags, paths[0],
                               "--abstention", paths[1]],
                              capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        for path in paths:
            os.unlink(path)


rc, out, err = render_pair(LABELLED, ABSTAIN, "--json")
try:
    ab = json.loads(out)["abstention"] if rc == 0 else None
except (ValueError, KeyError):
    ab = None
check("abstention renders (rc 0)", rc == 0 and ab is not None, err.strip())
check("abstention: total=56 abstained=54 accepted=2",
      ab and ab["total"] == 56 and ab["abstained"] == 54
      and ab["accepted"] == 2, ab)
check("abstention: unknown_rate=54/56",
      ab and close(ab["unknown_rate"], 54 / 56), ab)
rc_l, p_l, _ = run_render(LABELLED)
check("abstention never enters the labelled confusion matrix",
      rc == 0 and json.loads(out)["confusion"] == p_l["confusion"]
      and json.loads(out)["overall"] == p_l["overall"], out)
rc, text, err = render_pair(LABELLED, ABSTAIN)
plain = subprocess.run([sys.executable, RENDER, "/dev/stdin"],
                       input=LABELLED, capture_output=True, text=True).stdout
check("text: labelled report is a prefix, abstention section follows",
      rc == 0 and text.startswith(plain)
      and "# --- abstention set" in text[len(plain):], text)
check("text: overall abstention line carries the unknown rate",
      "abstention total=56     abstain=54     accepted=2      "
      "unknown_rate=0.9643" in text, text)
check("text: per-capture row names the accepted protocol",
      any(ln.startswith("abstain_tcp_0016.pcap") and ln.endswith("dicom:2")
          for ln in text.splitlines()), text)
rc, _, err = render_pair(LABELLED,
                         "abstain_tcp_0001.pcap\tftp\t4\t4\t0\t0\tftp:4\n")
check("abstention row with a real label -> rc 2", rc == 2, err.strip())
rc, _, err = render_pair(LABELLED, "")
check("empty abstention input -> rc 2", rc == 2, err.strip())
rc, _, err = render_pair(LABELLED,
                         "abstain_tcp_0001.pcap\t<abstain>\t4\t0\t1\t2\t-\n")
check("inconsistent abstention row -> rc 2", rc == 2, err.strip())
proc = subprocess.run([sys.executable, RENDER, "/dev/null", "--abstention"],
                      capture_output=True, text=True)
check("--abstention without a file -> rc 2", proc.returncode == 2,
      proc.stderr.strip())

print()
print("precision-metrics self-test: %d passed, %d failed (%d checks)"
      % (PASS, FAIL, TESTED))
sys.exit(0 if FAIL == 0 else 1)
