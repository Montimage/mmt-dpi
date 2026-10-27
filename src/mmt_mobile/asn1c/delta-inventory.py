#!/usr/bin/env python3
"""Inventory what the r16.1.0 S1AP/NGAP modules add over the old inputs.

Issue #523 (task 7.5, F-DEP-303 part 1) moved the asn1c generation from
S1AP r10.5.0 / NGAP r15.2.0 to the vendored r16.1.0 modules. This script
reads the ASN.1 sources under ./support/ and writes the delta inventory --
procedures and protocol IEs added, renamed or removed, where each new IE is
carried, and the new type definitions -- that task 17.5 (#574) maps into the
dissectors. Codes are compared by value, so a renamed constant is reported
as a rename, never as a removal plus an addition.

Usage: delta-inventory.py [--check] <output.md>
  Paths in the inventory are relative to this script's directory.
  --check compares with <output.md> instead of writing; exit 1 on drift.
"""

import argparse
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IDENT = r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*"

FAMILIES = [
    {
        "name": "S1AP",
        "spec": "TS 36.413",
        "old": ("r10.5.0", ["support/s1ap-r10.5.0/S1AP-Constants.asn",
                            "support/s1ap-r10.5.0/S1AP-PDU-Contents.asn",
                            "support/s1ap-r10.5.0/S1AP-IEs.asn",
                            "support/s1ap-r10.5.0/S1AP-PDU.asn"]),
        "new": ("r16.1.0", ["support/s1ap-r16.1.0/36413-g10.asn"]),
        "prefix": "S1ap-",
        "class_prefix": "S1AP",
    },
    {
        "name": "NGAP",
        "spec": "TS 38.413",
        "old": ("r15.2.0", ["support/ngap-r15.2.0/Constant-Definitions.asn1",
                            "support/ngap-r15.2.0/PDU-Definitions.asn1",
                            "support/ngap-r15.2.0/Information-Element-Definitions.asn1"]),
        "new": ("r16.1.0", ["support/ngap-r16.1.0/38413-g10.asn"]),
        "prefix": "",
        "class_prefix": "NGAP",
    },
]

# Types the OAI-style r10.5.0 S1AP schema invents; not 3GPP definitions.
SYNTHETIC_TYPES = {"IE", "IE-Extensions", "S1AP-PDU", "InitiatingMessage",
                   "SuccessfulOutcome", "UnsuccessfulOutcome"}


def strip_comments(text):
    out = []
    for line in text.splitlines():
        kept = []
        while True:
            start = line.find("--")
            if start < 0:
                kept.append(line)
                break
            kept.append(line[:start])
            end = line.find("--", start + 2)
            if end < 0:
                break
            line = line[end + 2:]
        out.append("".join(kept))
    return "\n".join(out)


def braced(text, start):
    """Return the text of the balanced {...} group opening at text[start]."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise ValueError("unbalanced braces")


def _simplify_module():
    spec = importlib.util.spec_from_file_location(
        "s1ap_simplify", os.path.join(HERE, "s1ap-simplify.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ASN1 = _simplify_module()


def root(rhs):
    """The part of a normalized definition before its first extension marker."""
    depth = 0
    for i, c in enumerate(rhs):
        if c in "{(":
            depth += 1
        elif c in "})":
            depth -= 1
        elif depth == 1 and rhs.startswith("...", i):
            return rhs[:i]
    return rhs


def normalize(rhs, prefix, values):
    """Compare definitions across the OAI-style and the 3GPP schema: the
    containers both encode the same way, the S1ap-/s1ap- prefix, value
    names (by their value) and whitespace are dropped."""
    text = re.sub(r"ProtocolExtensionContainer\s*\{\s*\{[^}]*\}\s*\}", "EXT", rhs)
    text = re.sub(r"ProtocolIE-SingleContainer\s*\{\s*\{[^}]*\}\s*\}", "IE", text)
    text = re.sub(r"(?:E-RAB|ProtocolError)-IE-ContainerList\s*\{\s*\{[^}]*\}\s*\}",
                  "SEQUENCE(SIZE(1..maxnoofE-RABs))OFIE", text)
    text = re.sub(r"ProtocolIE-ContainerList\s*\{\s*([^,]+),\s*([^,]+),\s*\{[^}]*\}\s*\}",
                  r"SEQUENCE(SIZE(\1..\2))OFIE", text)
    if prefix:
        text = re.sub(r"\bS1ap-IE-Extensions\b", "EXT", text)
        text = re.sub(r"\bS1ap-IE\b(?!-)", "IE", text)
        # type references only: a hand-prefixed r10.5.0 enumerator (TraceDepth's
        # s1ap-maximum) is a real C-name change; value names go by value below
        text = re.sub(r"(?<![A-Za-z0-9-])S1ap-", "", text)
    text = re.sub(IDENT, lambda m: str(values.get(m.group(0), m.group(0))), text)
    return re.sub(r"\s+", "", text)


def unprefix(name, prefix):
    return name[len(prefix):] if prefix and name.startswith(prefix) else name


def load(paths, family):
    text = ""
    for path in paths:
        with open(os.path.join(HERE, path), encoding="utf-8") as handle:
            text += strip_comments(handle.read()) + "\n"
    prefix = family["prefix"]
    codes = {"ProcedureCode": {}, "ProtocolIE-ID": {}}
    for name, governor, value in re.findall(
            r"^\s*(id-[A-Za-z0-9-]+)\s+(" + re.escape(prefix)
            + r"ProcedureCode|" + re.escape(prefix) + r"ProtocolIE-ID|ProcedureCode|"
            r"ProtocolIE-ID)\s*::=\s*(\d+)", text, re.M):
        codes[unprefix(governor, prefix)][int(value)] = name
    carriers = {}
    pattern = re.compile(r"^(" + IDENT + r")\s+" + family["class_prefix"]
                         + r"-(PROTOCOL-IES|PROTOCOL-IES-PAIR|PROTOCOL-EXTENSION)\s*::=\s*\{", re.M)
    for m in pattern.finditer(text):
        body = braced(text, m.end() - 1)
        holder = unprefix(m.group(1), prefix)
        holder = re.sub(r"(?:-ExtIEs|-IEs|IEs)$", "", holder)
        for ie in re.findall(r"\bID\s+(id-[A-Za-z0-9-]+)", body):
            carriers.setdefault(ie, [])
            if holder not in carriers[ie]:
                carriers[ie].append(holder)
    # (holder, IE id) -> the TYPE / EXTENSION each object set gives it
    ie_types = {}
    for m in pattern.finditer(text):
        holder = re.sub(r"(?:-ExtIEs|-IEs|IEs)$", "", unprefix(m.group(1), prefix))
        for ie, ie_type in re.findall(r"\bID\s+(id-[A-Za-z0-9-]+)\s+CRITICALITY\s+\w+\s+"
                                      r"(?:TYPE|EXTENSION)\s+(" + IDENT + r")",
                                      braced(text, m.end() - 1)):
            ie_types[(holder, ie)] = unprefix(ie_type, prefix)
    # type name -> right-hand side, and INTEGER value name -> value
    rhs_of = {}
    values = {}
    for module_name, _, body in ASN1.split_modules(text):
        for header, rhs in ASN1.split_assignments(ASN1.drop_imports(body)):
            kind, aname, governor = ASN1.classify(header, rhs)
            if kind == "type":
                rhs_of[unprefix(aname, prefix)] = rhs
            elif kind == "value" and governor == "INTEGER" and rhs.isdigit():
                values[aname] = int(rhs)
                values[unprefix(aname, prefix.lower())] = int(rhs)
    defs = {}
    for tname, rhs in rhs_of.items():
        if tname in SYNTHETIC_TYPES or re.search(r"ProtocolIE-Container|PrivateIE-Container|-ies\b", rhs):
            continue  # messages: their IEs are compared through ie_types
        defs[tname] = normalize(rhs, prefix, values)
    types = set(rhs_of) - SYNTHETIC_TYPES
    return codes, carriers, types, ie_types, defs


def compare(old, new):
    added = [(c, new[c]) for c in sorted(new) if c not in old]
    removed = [(c, old[c]) for c in sorted(old) if c not in new]
    renamed = [(c, old[c], new[c]) for c in sorted(new) if c in old and old[c] != new[c]]
    return added, renamed, removed


def section(family):
    old_rel, old_paths = family["old"]
    new_rel, new_paths = family["new"]
    old_codes, _, old_types, old_ie_types, old_defs = load(old_paths, family)
    new_codes, carriers, new_types, new_ie_types, new_defs = load(new_paths, family)
    name = family["name"]
    lines = ["## %s %s -> %s (%s)" % (name, old_rel, new_rel, family["spec"]), ""]
    lines.append("Sources: %s; %s." % (
        ", ".join("`%s`" % p for p in old_paths), ", ".join("`%s`" % p for p in new_paths)))
    lines.append("")
    lines.append("| | %s | %s | added | renamed | removed |" % (old_rel, new_rel))
    lines.append("|---|---:|---:|---:|---:|---:|")
    deltas = {}
    for kind, label in (("ProcedureCode", "Procedure codes"), ("ProtocolIE-ID", "Protocol IE ids")):
        deltas[kind] = compare(old_codes[kind], new_codes[kind])
        added, renamed, removed = deltas[kind]
        lines.append("| %s | %d | %d | %d | %d | %d |" % (
            label, len(old_codes[kind]), len(new_codes[kind]), len(added), len(renamed), len(removed)))
    added_types = sorted(new_types - old_types)
    lines.append("| Type definitions | %d | %d | %d | | %d |" % (
        len(old_types), len(new_types), len(added_types), len(old_types - new_types)))
    lines.append("")

    added, renamed, removed = deltas["ProcedureCode"]
    lines.append("### %s procedures added" % name)
    lines.append("")
    lines.append("| Code | Procedure |")
    lines.append("|---:|---|")
    lines += ["| %d | `%s` |" % (code, ident) for code, ident in added]
    lines.append("")
    if renamed or removed:
        lines.append("Procedure constants renamed: %s. Removed: %s." % (
            ", ".join("%d `%s` -> `%s`" % r for r in renamed) or "none",
            ", ".join("%d `%s`" % r for r in removed) or "none"))
        lines.append("")

    added, renamed, removed = deltas["ProtocolIE-ID"]
    lines.append("### %s protocol IEs added" % name)
    lines.append("")
    lines.append("*Carried by* names each message, and each IE type extended by a protocol"
                 " extension, whose %s-PROTOCOL-IES or -EXTENSION object set lists the IE"
                 " in %s." % (family["class_prefix"], new_rel))
    lines.append("")
    lines.append("| Id | IE | Carried by |")
    lines.append("|---:|---|---|")
    for code, ident in added:
        held = carriers.get(ident, [])
        lines.append("| %d | `%s` | %s |" % (code, ident, ", ".join(held) if held else "(not referenced)"))
    lines.append("")
    lines.append("Protocol IE constants renamed: %s. Removed: %s." % (
        ", ".join("%d `%s` -> `%s`" % r for r in renamed) or "none",
        ", ".join("%d `%s`" % r for r in removed) or "none"))
    lines.append("")

    lines.append("### %s type definitions added" % name)
    lines.append("")
    lines.append("Type assignments in %s with no same-named assignment in %s"
                 " (a renamed type appears here under its new name)." % (new_rel, old_rel))
    lines.append("")
    lines.append(", ".join("`%s`" % t for t in added_types) + ".")
    lines.append("")
    removed_types = sorted(old_types - new_types)
    lines.append("Type assignments in %s with no same-named assignment in %s (renamed or"
                 " dropped): %s." % (old_rel, new_rel,
                                     ", ".join("`%s`" % t for t in removed_types) or "none"))
    lines.append("")

    lines.append("### %s changes to existing definitions" % name)
    lines.append("")
    retyped = [(holder, ie, old_ie_types[(holder, ie)], new_ie_types[(holder, ie)])
               for holder, ie in sorted(new_ie_types)
               if (holder, ie) in old_ie_types
               and old_ie_types[(holder, ie)] != new_ie_types[(holder, ie)]]
    lines.append("IEs whose type changed in a message or extension both releases define"
                 " (a renamed type with the same definition shows up here too):")
    lines.append("")
    if retyped:
        lines.append("| Carried by | IE | %s type | %s type |" % (old_rel, new_rel))
        lines.append("|---|---|---|---|")
        lines += ["| %s | `%s` | `%s` | `%s` |" % r for r in retyped]
    else:
        lines.append("None.")
    lines.append("")
    both = set(old_defs) & set(new_defs)
    changed = sorted(t for t in both if root(old_defs[t]) != root(new_defs[t]))
    extended = sorted(t for t in both
                      if root(old_defs[t]) == root(new_defs[t]) and old_defs[t] != new_defs[t])
    lines.append("Types defined in both releases whose root -- the components,"
                 " alternatives, enumerators or constraints before the first extension"
                 " marker -- differs once both are normalized (container syntax, the S1ap-"
                 " type prefix and value names by value). A root change alters the encoding or"
                 " the generated C names, unlike an addition after the marker:")
    lines.append("")
    lines.append((", ".join("`%s`" % t for t in changed) + ".") if changed else "None.")
    lines.append("")
    lines.append("Types whose root is unchanged but whose extension additions differ -- the"
                 " old encoding still decodes; the new members or alternatives are not"
                 " extracted yet:")
    lines.append("")
    lines.append((", ".join("`%s`" % t for t in extended) + ".") if extended else "None.")
    lines.append("")
    return lines


def render():
    lines = [
        "# S1AP / NGAP Rel-16 delta inventory",
        "",
        "Generated by `src/mmt_mobile/asn1c/delta-inventory.py` (issue #523,"
        " F-DEP-303 part 1); do not edit. Regenerate with"
        " `python3 src/mmt_mobile/asn1c/delta-inventory.py"
        " src/mmt_mobile/asn1c/support/DELTA-r16.1.0.md`.",
        "",
        "The asn1c recipe (`src/mmt_mobile/asn1c/Makefile`) generates both decoders"
        " from the r16.1.0 modules. This inventory lists what r16.1.0 adds over the"
        " releases the decoders were generated from before: the dissectors extract"
        " none of the additions yet -- mapping them is task 17.5 (#574).",
        "",
    ]
    for family in FAMILIES:
        lines += section(family)
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    content = render()
    if args.check:
        try:
            with open(args.output, encoding="utf-8") as handle:
                current = handle.read()
        except FileNotFoundError:
            current = None
        if current != content:
            print("delta-inventory: %s is stale; regenerate it" % args.output, file=sys.stderr)
            return 1
        return 0
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(content)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
