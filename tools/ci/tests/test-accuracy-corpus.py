#!/usr/bin/env python3
"""test-accuracy-corpus.py -- self-test for the accuracy-corpus oracle
(tools/ci/tests/check-accuracy-corpus.py, issue #389, F-TEST-003).

Needs no SDK build: it validates the committed corpus offline, then drives the
REAL oracle on temporary copies of the corpus with a fake phase0_classify that
replays canned fingerprints, asserting that

  - the committed corpus passes (manifest, files, provenance, review,
    byte-reproducibility from its generator);
  - a missing capture, an unlabelled capture, a missing label/provenance/review
    field, a sha256 mismatch, a dropped required family and a family without
    a negative/ambiguous case all FAIL;
  - expected handling is enforced: a diverging verdict, an empty or failing
    classifier run and a negative case that expects a family verdict all FAIL;
  - heuristic application attribution beneath the wire label (ssl.google) is
    counted as wire + attribution, never as a different protocol.

Usage: python3 tools/ci/tests/test-accuracy-corpus.py
Exit: 0 = all checks passed, 1 = at least one failed.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SELF_DIR, "..", "..", ".."))
ORACLE = os.path.join(SELF_DIR, "check-accuracy-corpus.py")
CORPUS = os.path.join(REPO_ROOT, "tools", "phase0", "ci", "accuracy")

# Replays $FAKE_FP_DIR/<capture>.fp; exits with $FAKE_RC when set.
FAKE_CLASSIFY = """#!/usr/bin/env python3
import os, sys
rc = int(os.environ.get("FAKE_RC", "0"))
if rc:
    sys.stderr.write("fake classifier failure\\n")
    sys.exit(rc)
name = os.path.basename(sys.argv[1])
with open(os.path.join(os.environ["FAKE_FP_DIR"], name + ".fp")) as fh:
    sys.stdout.write(fh.read())
"""

# Fingerprints matching the committed expectations (see corpus.json).
GOOD_FP = {
    "acc_dns_positive.pcap": "2\tmeta.ethernet.ip.udp.dns\n",
    "acc_dns_negative.pcap": "2\tmeta.ethernet.ip.udp.unknown\n",
    "acc_tls_positive.pcap": "2\tmeta.ethernet.ip.tcp.ssl\n"
                             "3\tmeta.ethernet.ip.tcp.unknown\n",
    "acc_tls_sni_attribution.pcap": "2\tmeta.ethernet.ip.tcp.ssl.google\n"
                                    "3\tmeta.ethernet.ip.tcp.unknown\n",
    "acc_tls_negative.pcap": "2\tmeta.ethernet.ip.tcp.http\n"
                             "3\tmeta.ethernet.ip.tcp.unknown\n",
    "acc_quic_positive.pcap": "3\tmeta.ethernet.ip.udp.quic_ietf\n",
    "acc_quic_v2_ambiguous.pcap": "2\tmeta.ethernet.ip.udp.unknown\n",
    "acc_http2_positive.pcap": "2\tmeta.ethernet.ip.tcp.http2\n"
                               "3\tmeta.ethernet.ip.tcp.unknown\n",
    "acc_http2_negative.pcap": "2\tmeta.ethernet.ip.tcp.http\n"
                               "3\tmeta.ethernet.ip.tcp.unknown\n",
}

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, detail))


def oracle(*args, env=None):
    proc = subprocess.run([sys.executable, ORACLE, *args],
                          capture_output=True, text=True,
                          env=dict(os.environ, **(env or {})))
    return proc.returncode, proc.stdout + proc.stderr


class Scratch:
    """A temp copy of the committed corpus plus a fake classifier."""

    def __enter__(self):
        self.root = tempfile.mkdtemp(prefix="acc-selftest.")
        self.corpus = os.path.join(self.root, "corpus")
        shutil.copytree(CORPUS, self.corpus)
        self.fp_dir = os.path.join(self.root, "fp")
        os.makedirs(self.fp_dir)
        for name, text in GOOD_FP.items():
            self.write_fp(name, text)
        self.fake = os.path.join(self.root, "fake_classify")
        with open(self.fake, "w") as fh:
            fh.write(FAKE_CLASSIFY)
        os.chmod(self.fake, 0o755)
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_fp(self, name, text):
        with open(os.path.join(self.fp_dir, name + ".fp"), "w") as fh:
            fh.write(text)

    def manifest(self):
        with open(os.path.join(self.corpus, "corpus.json")) as fh:
            return json.load(fh)

    def save(self, man):
        with open(os.path.join(self.corpus, "corpus.json"), "w") as fh:
            json.dump(man, fh, indent=2)

    def case(self, man, pcap):
        return next(c for c in man["cases"] if c["pcap"] == pcap)

    def offline(self):
        return oracle("--corpus", self.corpus, "--offline")

    def run(self, **env):
        return oracle("--corpus", self.corpus, "--classify-bin", self.fake,
                      env=dict({"FAKE_FP_DIR": self.fp_dir}, **env))


print("accuracy-corpus oracle self-test (issue #389, F-TEST-003)")
print()

rc, out = oracle("--offline")
check("committed corpus validates offline", rc == 0, out)

with Scratch() as s:
    rc, out = s.run()
    check("matching verdicts pass", rc == 0, out)
    check("per-family report is printed", "# per family" in out, out)
    attr = [ln for ln in out.splitlines()
            if ln.startswith("tls ") and "google" in ln]
    check("SNI attribution reported separately", len(attr) == 1, out)
    tls_row = [ln.split() for ln in out.splitlines()
               if ln.startswith("tls ") and "|" in ln]
    check("attribution counted as wire, not other",
          tls_row and tls_row[0][3] == "4" and tls_row[0][5] == "0", out)

with Scratch() as s:
    os.remove(os.path.join(s.corpus, "acc_quic_positive.pcap"))
    rc, out = s.offline()
    check("missing listed capture fails", rc == 1 and "missing capture" in out,
          out)

with Scratch() as s:
    shutil.copy(os.path.join(s.corpus, "acc_dns_positive.pcap"),
                os.path.join(s.corpus, "stray.pcap"))
    rc, out = s.offline()
    check("unlabelled capture fails", rc == 1 and "without a corpus.json" in out,
          out)

for field, needle in (("family", "'family'"), ("case", "'case'"),
                      ("expected", "'expected'"), ("review", "'review'")):
    with Scratch() as s:
        man = s.manifest()
        del s.case(man, "acc_dns_positive.pcap")[field]
        s.save(man)
        rc, out = s.offline()
        check("missing %s label fails" % field, rc == 1 and needle in out, out)

with Scratch() as s:
    man = s.manifest()
    del s.case(man, "acc_tls_negative.pcap")["provenance"]["redistribution"]
    s.save(man)
    rc, out = s.offline()
    check("missing redistribution provenance fails",
          rc == 1 and "redistribution" in out, out)

with Scratch() as s:
    path = os.path.join(s.corpus, "acc_http2_positive.pcap")
    with open(path, "r+b") as fh:
        fh.seek(-1, os.SEEK_END)
        last = fh.read(1)
        fh.seek(-1, os.SEEK_END)
        fh.write(bytes([last[0] ^ 0xFF]))
    rc, out = s.offline()
    check("modified capture fails the sha256 check",
          rc == 1 and "sha256" in out, out)

with Scratch() as s:
    man = s.manifest()
    man["cases"] = [c for c in man["cases"] if c["pcap"] != "acc_dns_negative.pcap"]
    s.save(man)
    os.remove(os.path.join(s.corpus, "acc_dns_negative.pcap"))
    rc, out = s.offline()
    check("family without a negative/ambiguous case fails",
          rc == 1 and "no negative/ambiguous" in out, out)

with Scratch() as s:
    man = s.manifest()
    del man["families"]["quic"]
    man["cases"] = [c for c in man["cases"] if c["family"] != "quic"]
    s.save(man)
    for c in os.listdir(s.corpus):
        if c.startswith("acc_quic_"):
            os.remove(os.path.join(s.corpus, c))
    rc, out = s.offline()
    check("dropping a required family fails",
          rc == 1 and "required family" in out, out)

with Scratch() as s:
    man = s.manifest()
    c = s.case(man, "acc_dns_negative.pcap")
    c["expected"].update(wire=2, abstain=0)
    s.save(man)
    rc, out = s.offline()
    check("negative case expecting a family verdict fails",
          rc == 1 and "false accept" in out, out)

with Scratch() as s:
    s.write_fp("acc_dns_positive.pcap", "2\tmeta.ethernet.ip.udp.unknown\n")
    rc, out = s.run()
    check("diverging verdict fails and names the capture",
          rc == 1 and "acc_dns_positive.pcap" in out and "wire expected 2" in out,
          out)

with Scratch() as s:
    s.write_fp("acc_quic_v2_ambiguous.pcap",
               "2\tmeta.ethernet.ip.udp.quic_ietf\n")
    rc, out = s.run()
    check("false accept on an ambiguous case fails", rc == 1, out)

with Scratch() as s:
    s.write_fp("acc_tls_positive.pcap", "")
    rc, out = s.run()
    check("empty classifier output fails", rc == 1 and "no output" in out, out)

with Scratch() as s:
    rc, out = s.run(FAKE_RC="3")
    check("failing classifier run fails", rc == 1 and "exited 3" in out, out)

print()
print("%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
