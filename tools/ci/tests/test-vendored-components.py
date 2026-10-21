#!/usr/bin/env python3
"""test-vendored-components.py -- self-test for tools/ci/vendored-components.py
(issue #496, F-DEP-305).

Drives the REAL helper:
  - `check` passes on the committed manifest and tree
  - `check` fails (exit 1) on fixture trees with a drifted version, a drifted
    pin, a missing path, a vendor-paths.txt entry no component covers, and an
    SPDXID outside ^SPDXRef-[A-Za-z0-9.-]+$; an unreadable manifest is exit 2
  - `sbom` on a fixture shaped like the syft SPDX-JSON of a built package
    (one root package, DOCUMENT DESCRIBES it) adds the committed components
    as packages, each CONTAINed by the root, every SPDXID valid; the
    workflow's exact-name query finds llhttp and asn1c; a second run is a
    no-op (idempotent); a non-SPDX document is exit 2

Usage: python3 tools/ci/tests/test-vendored-components.py
Exit: 0 = all checks passed, 1 = at least one failed.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(SELF_DIR)))
HELPER = os.path.join(ROOT, "tools", "ci", "vendored-components.py")
MANIFEST = "tools/ci/vendored-components.json"
SPDX_ID_RE = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")

failures = 0


def run(*args):
    proc = subprocess.run([sys.executable, HELPER, *args],
                          capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout + proc.stderr


def expect(cond, msg, detail=""):
    global failures
    if cond:
        print(f"  ✓ {msg}")
    else:
        failures += 1
        print(f"  ✗ {msg}\n{detail}")


def fixture_tree(tmp):
    """A minimal tree with one vendored file and a version source."""
    root = os.path.join(tmp, "tree")
    os.makedirs(os.path.join(root, "lib"))
    os.makedirs(os.path.join(root, "tools", "ci"))
    with open(os.path.join(root, "lib", "dep.h"), "w", encoding="utf-8") as fh:
        fh.write("#define DEP_VERSION \"1.2.3\"\n#define DEP_REF abc123\n")
    with open(os.path.join(root, "tools", "ci", "vendor-paths.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# comment\nlib/dep.h\n")
    manifest = {"schema_version": 1, "components": [{
        "name": "dep", "spdx_id": "SPDXRef-Vendored-dep", "version": "1.2.3",
        "upstream": "https://example.invalid/dep", "pin": "abc123",
        "download_location": "https://example.invalid/dep/abc123",
        "purl": "pkg:generic/dep@1.2.3", "license": "MIT",
        "copyright": "Copyright (c) Example", "paths": ["lib/dep.h"],
        "checks": [
            {"field": "version", "file": "lib/dep.h",
             "pattern": "DEP_VERSION \"([0-9.]+)\""},
            {"field": "pin", "file": "lib/dep.h", "pattern": "DEP_REF (\\w+)"},
        ]}]}
    write_manifest(root, manifest)
    return root, manifest


def write_manifest(root, manifest):
    with open(os.path.join(root, MANIFEST), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)


def check_fixture(root, manifest, mutate, msg):
    vendor_paths = os.path.join(root, "tools", "ci", "vendor-paths.txt")
    with open(vendor_paths, encoding="utf-8") as fh:
        saved = fh.read()
    data = json.loads(json.dumps(manifest))
    mutate(data, root)
    write_manifest(root, data)
    code, out = run("--root", root, "check")
    expect(code == 1, f"check fails: {msg}", out)
    write_manifest(root, manifest)
    with open(vendor_paths, "w", encoding="utf-8") as fh:
        fh.write(saved)


def main():
    code, out = run("check")
    expect(code == 0, "check passes on the committed manifest", out)

    with open(os.path.join(ROOT, MANIFEST), encoding="utf-8") as fh:
        committed = json.load(fh)
    names = [c["name"] for c in committed["components"]]
    expect({"llhttp", "asn1c"} <= set(names),
           "the committed manifest lists llhttp and asn1c", str(names))

    tmp = tempfile.mkdtemp(prefix="vendored-test-")
    try:
        root, manifest = fixture_tree(tmp)
        code, out = run("--root", root, "check")
        expect(code == 0, "check passes on the consistent fixture", out)

        def drift_version(d, _):
            d["components"][0]["version"] = "1.2.4"

        def drift_pin(d, _):
            d["components"][0]["pin"] = "def456"

        def missing_path(d, _):
            d["components"][0]["paths"].append("lib/gone.c")

        def bad_spdx_id(d, _):
            d["components"][0]["spdx_id"] = "SPDXRef-Vendored-nodejs/dep"

        def uncovered(_, r):
            with open(os.path.join(r, "tools", "ci", "vendor-paths.txt"), "a",
                      encoding="utf-8") as fh:
                fh.write("lib/other.c\n")

        check_fixture(root, manifest, drift_version, "recorded version drifts")
        check_fixture(root, manifest, drift_pin, "recorded pin drifts")
        check_fixture(root, manifest, missing_path, "a component path is missing")
        check_fixture(root, manifest, bad_spdx_id, "an SPDXID is not SPDX-valid")
        check_fixture(root, manifest, uncovered,
                      "a vendor-paths.txt entry belongs to no component")

        with open(os.path.join(root, MANIFEST), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        code, out = run("--root", root, "check")
        expect(code == 2, "check exits 2 on an unreadable manifest", out)

        sbom = os.path.join(tmp, "pkg.deb.sbom.json")
        root_id = "SPDXRef-DocumentRoot-File-pkg.deb"
        with open(sbom, "w", encoding="utf-8") as fh:
            json.dump({
                "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT", "name": "pkg.deb",
                "packages": [{"name": "pkg.deb", "SPDXID": root_id,
                              "downloadLocation": "NOASSERTION",
                              "filesAnalyzed": False}],
                "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                                   "relatedSpdxElement": root_id,
                                   "relationshipType": "DESCRIBES"}],
            }, fh)
        code, out = run("sbom", sbom)
        expect(code == 0, "sbom injects the committed components", out)
        with open(sbom, encoding="utf-8") as fh:
            first = json.load(fh)
        pkg_names = [p["name"] for p in first["packages"]]
        expect(all(n in pkg_names for n in ("llhttp", "asn1c")),
               "[.packages[].name] contains llhttp and asn1c", str(pkg_names))
        expect(all(SPDX_ID_RE.match(p["SPDXID"]) for p in first["packages"]),
               "every SPDXID is SPDX-valid")
        injected = [p for p in first["packages"] if p["name"] in names]
        expect(all(p.get("downloadLocation") and p.get("filesAnalyzed") is False
                   and p.get("licenseDeclared") and p.get("versionInfo")
                   for p in injected),
               "injected packages carry version, downloadLocation, licence, "
               "filesAnalyzed false")
        contains = {(r["spdxElementId"], r["relatedSpdxElement"])
                    for r in first["relationships"]
                    if r["relationshipType"] == "CONTAINS"}
        expect(all((root_id, p["SPDXID"]) in contains for p in injected),
               "the described root CONTAINS each vendored package",
               str(contains))

        code, out = run("sbom", sbom)
        with open(sbom, encoding="utf-8") as fh:
            second = json.load(fh)
        expect(code == 0 and second == first, "a second sbom run is a no-op", out)

        with open(sbom, "w", encoding="utf-8") as fh:
            json.dump({"bomFormat": "CycloneDX"}, fh)
        code, out = run("sbom", sbom)
        expect(code == 2, "sbom exits 2 on a non-SPDX document", out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print(f"✗ {failures} vendored-components check(s) failed")
        return 1
    print("✓ vendored-components self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
