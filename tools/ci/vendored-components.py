#!/usr/bin/env python3
"""vendored-components.py -- the vendored-code inventory (issue #496, F-DEP-305).

tools/ci/vendored-components.json records every third-party component
vendored into the tree: its paths, upstream, pinned revision, licence and
copyright. This helper keeps that record honest and carries it into the
release SBOM.

  check            validate the manifest against the tree: required fields,
                   SPDX-valid ids and names, every path present, each
                   recorded version/pin equal to the value its `checks` entry
                   reads from the source of truth (e.g. LLHTTP_VERSION_* in
                   llhttp.h, ASN1C_REF in src/mmt_mobile/asn1c/ASN1C_VERSION),
                   and every tools/ci/vendor-paths.txt entry covered by a
                   component path
  sbom FILE        add one SPDX package per component to the SPDX-JSON
                   document FILE (in place), each CONTAINed by the element(s)
                   the document DESCRIBES; idempotent. Fails when a manifest
                   name is then missing from [.packages[].name].

Options (both commands): --root DIR (repository root, default: this
checkout), --manifest FILE, --vendor-paths FILE (paths relative to --root).

Exit codes: 0 = condition holds, 1 = violation, 2 = helper broken or bad
usage (unreadable manifest/SBOM, not JSON).
"""

import argparse
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST = "tools/ci/vendored-components.json"
VENDOR_PATHS = "tools/ci/vendor-paths.txt"

REQUIRED = ("name", "spdx_id", "version", "upstream", "pin", "download_location",
            "purl", "license", "copyright", "paths", "checks")
SPDX_ID_RE = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
LICENSE_RE = re.compile(r"^(LicenseRef-)?[A-Za-z0-9.+-]+$")
CHECK_FIELDS = ("version", "pin")


class Broken(Exception):
    """The helper cannot run (exit 2)."""


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise Broken(f"cannot read {what} {path}: {exc}") from exc


def load_manifest(root, manifest):
    data = load_json(os.path.join(root, manifest), "manifest")
    if not isinstance(data, dict) or data.get("schema_version") != 1 \
            or not isinstance(data.get("components"), list):
        raise Broken(f"{manifest}: expected schema_version 1 with a components list")
    return data["components"]


def path_present(root, rel):
    full = os.path.join(root, rel)
    if rel.endswith("/"):
        return os.path.isdir(full) and any(
            files for _, _, files in os.walk(full))
    return os.path.isfile(full)


def covered(entry, components):
    for comp in components:
        for p in comp.get("paths", []):
            if entry == p or (p.endswith("/") and entry.startswith(p)):
                return True
    return False


def cmd_check(root, manifest, vendor_paths):
    components = load_manifest(root, manifest)
    errors = []
    seen_names, seen_ids = set(), set()

    for idx, comp in enumerate(components):
        label = comp.get("name", f"components[{idx}]") if isinstance(comp, dict) \
            else f"components[{idx}]"
        if not isinstance(comp, dict):
            errors.append(f"{label}: not an object")
            continue
        missing = [k for k in REQUIRED if not comp.get(k)]
        if missing:
            errors.append(f"{label}: missing {', '.join(missing)}")
            continue
        if not NAME_RE.match(comp["name"]):
            errors.append(f"{label}: name is not a plain package name")
        if not SPDX_ID_RE.match(comp["spdx_id"]):
            errors.append(f"{label}: spdx_id {comp['spdx_id']!r} is not ^SPDXRef-[A-Za-z0-9.-]+$")
        if not LICENSE_RE.match(comp["license"]):
            errors.append(f"{label}: license {comp['license']!r} is not an SPDX identifier")
        if not comp["purl"].startswith("pkg:"):
            errors.append(f"{label}: purl does not start with pkg:")
        if comp["name"] in seen_names:
            errors.append(f"{label}: duplicate name")
        if comp["spdx_id"] in seen_ids:
            errors.append(f"{label}: duplicate spdx_id")
        seen_names.add(comp["name"])
        seen_ids.add(comp["spdx_id"])

        for rel in comp["paths"]:
            if not path_present(root, rel):
                errors.append(f"{label}: path {rel} is not in the tree")

        for chk in comp["checks"]:
            field, rel, pattern = chk.get("field"), chk.get("file"), chk.get("pattern")
            if field not in CHECK_FIELDS or not rel or not pattern:
                errors.append(f"{label}: malformed check {chk!r}")
                continue
            try:
                with open(os.path.join(root, rel), encoding="utf-8") as fh:
                    text = fh.read()
            except OSError:
                errors.append(f"{label}: check file {rel} is not in the tree")
                continue
            try:
                m = re.search(pattern, text)
            except re.error as exc:
                raise Broken(f"{label}: bad check pattern: {exc}") from exc
            if not m:
                errors.append(f"{label}: {rel} does not match the {field} pattern")
                continue
            found = ".".join(m.groups()) if m.groups() else m.group(0)
            if found != comp[field]:
                errors.append(f"{label}: {field} {comp[field]!r} but {rel} says {found!r}")

    try:
        with open(os.path.join(root, vendor_paths), encoding="utf-8") as fh:
            entries = [re.sub(r"#.*", "", line).strip() for line in fh]
    except OSError as exc:
        raise Broken(f"cannot read {vendor_paths}: {exc}") from exc
    for entry in filter(None, entries):
        if not covered(entry, components):
            errors.append(f"{vendor_paths}: {entry} belongs to no component in {manifest}")

    for err in errors:
        print(f"  ✗ {err}")
    if errors:
        print(f"✗ {len(errors)} vendored-inventory violation(s)", file=sys.stderr)
        return 1
    print(f"✓ vendored inventory holds: {len(components)} component(s) "
          f"({', '.join(c['name'] for c in components)})")
    return 0


def spdx_package(comp):
    return {
        "SPDXID": comp["spdx_id"],
        "name": comp["name"],
        "versionInfo": comp["version"],
        "supplier": "NOASSERTION",
        "downloadLocation": comp["download_location"],
        "filesAnalyzed": False,
        "licenseConcluded": comp["license"],
        "licenseDeclared": comp["license"],
        "copyrightText": comp["copyright"],
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": comp["purl"],
        }],
        "comment": (f"Vendored source compiled into this package, pinned at "
                    f"{comp['upstream']} {comp['pin']}; in-tree paths: "
                    f"{', '.join(comp['paths'])} (tools/ci/vendored-components.json)."),
    }


def cmd_sbom(root, manifest, sbom_path):
    components = load_manifest(root, manifest)
    for comp in components:
        if not isinstance(comp, dict) or any(not comp.get(k) for k in REQUIRED):
            raise Broken(f"{manifest}: incomplete component; run the check command")
    doc = load_json(sbom_path, "SBOM")
    if not isinstance(doc, dict) or not str(doc.get("spdxVersion", "")).startswith("SPDX-2."):
        raise Broken(f"{sbom_path}: not an SPDX 2.x JSON document")

    ours = {c["spdx_id"] for c in components}
    packages = [p for p in doc.get("packages", []) if p.get("SPDXID") not in ours]
    relationships = [r for r in doc.get("relationships", [])
                     if r.get("relatedSpdxElement") not in ours]

    doc_id = doc.get("SPDXID", "SPDXRef-DOCUMENT")
    targets = [r.get("relatedSpdxElement") for r in relationships
               if r.get("spdxElementId") == doc_id
               and r.get("relationshipType") == "DESCRIBES"]
    targets += [t for t in doc.get("documentDescribes", []) or [] if t not in targets]

    for comp in components:
        packages.append(spdx_package(comp))
        if targets:
            for target in targets:
                relationships.append({"spdxElementId": target,
                                      "relatedSpdxElement": comp["spdx_id"],
                                      "relationshipType": "CONTAINS"})
        else:
            relationships.append({"spdxElementId": doc_id,
                                  "relatedSpdxElement": comp["spdx_id"],
                                  "relationshipType": "DESCRIBES"})
    doc["packages"] = packages
    doc["relationships"] = relationships

    names = {p.get("name") for p in packages}
    missing = [c["name"] for c in components if c["name"] not in names]
    if missing:
        print(f"✗ {sbom_path}: packages missing after injection: {', '.join(missing)}",
              file=sys.stderr)
        return 1

    out_dir = os.path.dirname(os.path.abspath(sbom_path))
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".sbom-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
            fh.write("\n")
        os.chmod(tmp, os.stat(sbom_path).st_mode & 0o777)
        os.replace(tmp, sbom_path)
    except OSError as exc:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise Broken(f"cannot write {sbom_path}: {exc}") from exc
    print(f"✓ {sbom_path}: added {len(components)} vendored package(s) "
          f"({', '.join(c['name'] for c in components)})")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=ROOT)
    parser.add_argument("--manifest", default=MANIFEST)
    parser.add_argument("--vendor-paths", default=VENDOR_PATHS)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sbom = sub.add_parser("sbom")
    sbom.add_argument("file")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    try:
        if args.command == "check":
            return cmd_check(args.root, args.manifest, args.vendor_paths)
        return cmd_sbom(args.root, args.manifest, args.file)
    except Broken as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
