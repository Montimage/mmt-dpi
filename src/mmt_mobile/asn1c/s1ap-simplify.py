#!/usr/bin/env python3
"""Derive the S1AP decoder schema from the 3GPP TS 36.413 ASN.1 modules.

The S1AP dissector (src/mmt_mobile/s1ap/s1ap_common.c) decodes the OAI-style
"simplified" S1AP schema the r10.5.0 inputs carry: every type is prefixed
``S1ap-``, every message is ``SEQUENCE OF S1ap-IE`` whose ``value`` is an
``ANY`` the dissector decodes per IE id, and every IE extension container is
``S1ap-IE-Extensions``. The 3GPP modules use information object classes
instead (``ProtocolIE-Container {{...IEs}}``), which asn1c turns into typed
open-type CHOICEs with a different C API.

This script applies that simplification mechanically to the 3GPP modules
(issue #523), so the generation recipe can feed the decoder the r16.1.0
specification without a hand-maintained copy:

* object classes, object sets and parameterized container types are dropped;
* ``protocolIEs ProtocolIE-Container {{X}}`` / ``privateIEs
  PrivateIE-Container {{X}}`` become ``s1ap-<Msg>-ies SEQUENCE (SIZE
  (0..s1ap-maxProtocolIEs)) OF S1ap-IE``;
* ``ProtocolIE-SingleContainer {{X}}`` becomes ``S1ap-IE``, a container list
  ``SEQUENCE (SIZE (lb..ub)) OF S1ap-IE`` and ``ProtocolExtensionContainer
  {{X}}`` ``S1ap-IE-Extensions`` -- the same wire encoding (each field is an
  id, a criticality and an open type), read back as ``ANY``;
* type references gain the ``S1ap-`` prefix and value references ``s1ap-``;
* ``S1ap-ProcedureCode`` / ``S1ap-ProtocolIE-ID`` carry the ``id-*`` constants
  as named numbers, which is where the dissector's
  ``S1ap_ProtocolIE_ID_id_*`` enumerators come from.

The output is four modules (S1AP-CommonDataTypes, S1AP-Constants, S1AP-IEs,
S1AP-PDU), the layout of the r10.5.0 inputs. ``--check`` compares instead of
writing and exits 1 on drift.

Usage: s1ap-simplify.py [--check] <36413-xxx.asn> <output-dir>
"""

import argparse
import os
import re
import sys

PREFIX_TYPE = "S1ap-"
PREFIX_VALUE = "s1ap-"

# Information object classes of S1AP-PDU-Descriptions / S1AP-Containers.
CLASSES = {
    "S1AP-ELEMENTARY-PROCEDURE",
    "S1AP-PROTOCOL-IES",
    "S1AP-PROTOCOL-IES-PAIR",
    "S1AP-PROTOCOL-EXTENSION",
    "S1AP-PRIVATE-IES",
}

# Module -> output module. S1AP-PDU-Descriptions and S1AP-Containers only
# hold the classes and the PDU, which the simplified schema writes itself.
MODULE_MAP = {
    "S1AP-CommonDataTypes": "S1AP-CommonDataTypes",
    "S1AP-Constants": "S1AP-Constants",
    "S1AP-IEs": "S1AP-IEs",
    "S1AP-PDU-Contents": "S1AP-IEs",  # messages are moved to S1AP-PDU
    "S1AP-PDU-Descriptions": None,
    "S1AP-Containers": None,
}
OUTPUT_ORDER = ["S1AP-CommonDataTypes", "S1AP-Constants", "S1AP-IEs", "S1AP-PDU"]

# Named-number lists derived from the constants of these types.
NAMED_NUMBER_TYPES = ("ProcedureCode", "ProtocolIE-ID")

IDENT = r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*"
SET_REF = r"\{\s*\{\s*" + IDENT + r"\s*\}\s*\}"

PDU_HEADER = """S1AP-PDU ::= CHOICE {
\tinitiatingMessage\tS1ap-InitiatingMessage,
\tsuccessfulOutcome\tS1ap-SuccessfulOutcome,
\tunsuccessfulOutcome\tS1ap-UnsuccessfulOutcome,
\t...
}

S1ap-InitiatingMessage ::= SEQUENCE {
\tprocedureCode\tS1ap-ProcedureCode,
\tcriticality\tS1ap-Criticality,
\tvalue\t\tANY
}

S1ap-SuccessfulOutcome ::= SEQUENCE {
\tprocedureCode\tS1ap-ProcedureCode,
\tcriticality\tS1ap-Criticality,
\tvalue\t\tANY
}

S1ap-UnsuccessfulOutcome ::= SEQUENCE {
\tprocedureCode\tS1ap-ProcedureCode,
\tcriticality\tS1ap-Criticality,
\tvalue\t\tANY
}"""

IE_TYPE = """S1ap-IE ::= SEQUENCE {
\tid\t\tS1ap-ProtocolIE-ID,
\tcriticality\tS1ap-Criticality,
\tvalue\t\tANY
}"""

IE_EXTENSIONS_TYPE = (
    "S1ap-IE-Extensions ::= SEQUENCE (SIZE (1..s1ap-maxProtocolExtensions)) OF S1ap-IE"
)


class SchemaError(Exception):
    pass


def strip_comments(text):
    """Remove ASN.1 comments: '--' up to the next '--' or the end of line."""
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
        out.append("".join(kept).rstrip())
    return "\n".join(out)


def split_modules(text):
    pattern = re.compile(
        r"^(" + IDENT + r")\s*\{[^}]*\}\s*DEFINITIONS\s+AUTOMATIC\s+TAGS\s*::=\s*BEGIN\b"
        r"(.*?)^END\b",
        re.S | re.M,
    )
    modules = []
    for m in pattern.finditer(text):
        oid = re.search(r"\{[^}]*\}", m.group(0)).group(0)
        modules.append((m.group(1), " ".join(oid.split()), m.group(2)))
    if not modules:
        raise SchemaError("no ASN.1 module found")
    return modules


def drop_imports(body):
    m = re.search(r"\bIMPORTS\b.*?;", body, re.S)
    if m:
        body = body[: m.start()] + body[m.end():]
    if re.search(r"\bEXPORTS\b", body):
        raise SchemaError("EXPORTS clauses are not supported")
    return body


def split_assignments(body):
    """Split a module body into (header, rhs) at every depth-0 '::='."""
    depth = 0
    marks = []
    i = 0
    while i < len(body):
        c = body[i]
        if c in "{(":
            depth += 1
        elif c in "})":
            depth -= 1
        elif body.startswith("::=", i) and depth == 0:
            marks.append(body.rfind("\n", 0, i) + 1)
            i += 3
            continue
        i += 1
    if depth != 0:
        raise SchemaError("unbalanced braces")
    if not marks or body[: marks[0]].strip():
        raise SchemaError("text before the first assignment")
    result = []
    for n, start in enumerate(marks):
        end = marks[n + 1] if n + 1 < len(marks) else len(body)
        chunk = body[start:end]
        header, rhs = chunk.split("::=", 1)
        result.append((header.strip(), rhs.strip()))
    return result


def classify(header, rhs):
    """Return (kind, name, governor)."""
    if "{" in header:
        return "parameterized", re.match(IDENT, header).group(0), None
    words = header.split()
    if any(not re.fullmatch(IDENT, w) for w in words):
        raise SchemaError("unexpected assignment header: %r" % header)
    if len(words) == 1:
        if rhs.startswith("CLASS"):
            return "class", words[0], None
        return "type", words[0], None
    if len(words) == 2:
        if words[1] in CLASSES:
            return "object", words[0], words[1]
        return "value", words[0], words[1]
    raise SchemaError("unexpected assignment header: %r" % header)


def parse(text):
    modules = split_modules(strip_comments(text))
    found = [name for name, _, _ in modules]
    if sorted(found) != sorted(MODULE_MAP):
        raise SchemaError("unexpected module set: %s" % ", ".join(found))
    parsed = []
    for name, oid, body in modules:
        parsed.append((name, oid, split_assignments(drop_imports(body))))
    return parsed


def container_lists(parsed):
    """Parameterized E-RAB/ProtocolError container lists -> (lb, ub)."""
    lists = {}
    for module, _, assignments in parsed:
        if module == "S1AP-Containers":
            continue
        for header, rhs in assignments:
            kind, name, _ = classify(header, rhs)
            if kind != "parameterized":
                continue
            m = re.fullmatch(
                r"ProtocolIE-ContainerList\s*\{\s*(" + IDENT + r"|\d+)\s*,\s*("
                + IDENT + r"|\d+)\s*,\s*\{\s*" + IDENT + r"\s*\}\s*\}",
                rhs,
            )
            lists[name] = m.groups() if m else None
    return lists


def rewrite_rhs(name, rhs, lists):
    """Replace the class-based containers; return (rhs, is_message)."""
    message = False

    def message_ies(_match):
        nonlocal message
        message = True
        return "%s%s-ies SEQUENCE (SIZE (0..%smaxProtocolIEs)) OF %sIE" % (
            PREFIX_VALUE, name, PREFIX_VALUE, PREFIX_TYPE)

    rhs = re.sub(r"\b(?:protocolIEs\s+ProtocolIE-Container|privateIEs\s+PrivateIE-Container)\s*"
                 + SET_REF, message_ies, rhs)
    rhs = re.sub(r"ProtocolExtensionContainer\s*" + SET_REF, PREFIX_TYPE + "IE-Extensions", rhs)
    rhs = re.sub(r"ProtocolIE-SingleContainer\s*" + SET_REF, PREFIX_TYPE + "IE", rhs)
    rhs = re.sub(r"ProtocolIE-Container\s*" + SET_REF,
                 "SEQUENCE (SIZE (0..%smaxProtocolIEs)) OF %sIE" % (PREFIX_VALUE, PREFIX_TYPE), rhs)
    rhs = re.sub(
        r"ProtocolIE-ContainerList\s*\{\s*(" + IDENT + r"|\d+)\s*,\s*(" + IDENT
        + r"|\d+)\s*,\s*\{\s*" + IDENT + r"\s*\}\s*\}",
        lambda m: "SEQUENCE (SIZE (%s..%s)) OF %sIE" % (m.group(1), m.group(2), PREFIX_TYPE), rhs)

    def param_list(match):
        bounds = lists.get(match.group(1))
        if bounds is None:
            raise SchemaError("%s uses unsupported container %s" % (name, match.group(1)))
        return "SEQUENCE (SIZE (%s..%s)) OF %sIE" % (bounds[0], bounds[1], PREFIX_TYPE)

    if lists:
        rhs = re.sub(r"\b(" + "|".join(re.escape(k) for k in sorted(lists)) + r")\s*" + SET_REF,
                     param_list, rhs)
    leftover = re.search(r"ProtocolIE-(?!ID\b)|ProtocolExtension(?!ID\b)|PrivateIE-|S1AP-PRIVATE|S1AP-PROTOCOL|&", rhs)
    if leftover:
        raise SchemaError("%s keeps an unsupported construct: %s" % (name, leftover.group(0)))
    return rhs, message


def build(text, source_name):
    parsed = parse(text)
    lists = container_lists(parsed)
    oids = {name: oid for name, oid, _ in parsed}

    # (output module, original name or None, kind, text-with-original-names)
    entries = []
    type_names = set()
    value_names = set()
    named_numbers = {t: [] for t in NAMED_NUMBER_TYPES}

    for module, _, assignments in parsed:
        target = MODULE_MAP[module]
        if target is None:
            continue
        for header, rhs in assignments:
            kind, name, governor = classify(header, rhs)
            if kind in ("class", "object", "parameterized"):
                continue
            if kind == "value":
                if target != "S1AP-Constants":
                    raise SchemaError("value %s outside S1AP-Constants" % name)
                if governor in named_numbers:
                    named_numbers[governor].append((name, rhs))
                value_names.add(name)
                entries.append((target, name, "value", "%s %s ::= %s" % (name, governor, rhs)))
                continue
            rhs, message = rewrite_rhs(name, rhs, lists)
            type_names.add(name)
            entries.append(("S1AP-PDU" if message else target, name, "type",
                            "%s ::= %s" % (name, rhs)))

    for governor, numbers in named_numbers.items():
        if not numbers:
            raise SchemaError("no %s constants found" % governor)

    for clash in (PREFIX_TYPE + "IE", PREFIX_TYPE + "IE-Extensions"):
        if clash[len(PREFIX_TYPE):] in type_names:
            raise SchemaError("%s already names a type" % clash)

    rename = {n: PREFIX_TYPE + n for n in type_names}
    rename.update({n: PREFIX_VALUE + n for n in value_names})

    def apply(snippet):
        return re.sub(IDENT, lambda m: rename.get(m.group(0), m.group(0)), snippet)

    bodies = {m: [] for m in OUTPUT_ORDER}
    defined = {m: set() for m in OUTPUT_ORDER}
    for target, name, kind, snippet in entries:
        renamed = apply(snippet)
        if kind == "type" and name in NAMED_NUMBER_TYPES:
            numbers = ",\n".join("\t%s(%s)" % (n, v) for n, v in named_numbers[name])
            renamed = re.sub(r"::=\s*INTEGER\s*",
                             "::= INTEGER {\n%s\n} " % numbers, renamed, count=1)
        bodies[target].append(renamed)
        defined[target].add(rename[name])
    bodies["S1AP-PDU"].insert(0, PDU_HEADER)
    bodies["S1AP-PDU"].append(IE_TYPE)
    defined["S1AP-PDU"].update({"S1AP-PDU", PREFIX_TYPE + "InitiatingMessage",
                                PREFIX_TYPE + "SuccessfulOutcome",
                                PREFIX_TYPE + "UnsuccessfulOutcome", PREFIX_TYPE + "IE"})
    bodies["S1AP-IEs"].insert(0, IE_EXTENSIONS_TYPE)
    defined["S1AP-IEs"].add(PREFIX_TYPE + "IE-Extensions")

    owner = {}
    for module in OUTPUT_ORDER:
        for symbol in defined[module]:
            owner[symbol] = module

    out_oids = dict(oids)
    out_oids["S1AP-PDU"] = oids["S1AP-PDU-Descriptions"]

    files = {}
    for module in OUTPUT_ORDER:
        text_body = "\n\n".join(bodies[module])
        imports = {}
        for token in re.findall(IDENT, text_body):
            source = owner.get(token)
            if source and source != module:
                names = imports.setdefault(source, [])
                if token not in names:
                    names.append(token)
        lines = [
            "-- Derived from %s by src/mmt_mobile/asn1c/s1ap-simplify.py (issue #523)." % source_name,
            "-- Do not edit: `make -C src/mmt_mobile/asn1c gen-s1ap` rewrites it.",
            "",
            "%s %s" % (module, out_oids[module]),
            "",
            "DEFINITIONS AUTOMATIC TAGS ::=",
            "",
            "BEGIN",
            "",
        ]
        if imports:
            lines.append("IMPORTS")
            groups = []
            for source in OUTPUT_ORDER:
                if source in imports:
                    groups.append(",\n".join("\t" + n for n in imports[source])
                                  + "\nFROM " + source)
            lines.append("\n\n".join(groups) + ";")
            lines.append("")
        lines.append(text_body)
        lines.append("")
        lines.append("END")
        content = "\n".join(lines)
        content = re.sub(r"\n{3,}", "\n\n", content) + "\n"
        files[module + ".asn"] = content
    return files


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true",
                        help="compare with the output directory instead of writing")
    parser.add_argument("source")
    parser.add_argument("outdir")
    args = parser.parse_args(argv)
    with open(args.source, encoding="utf-8") as handle:
        text = handle.read()
    try:
        files = build(text, os.path.basename(args.source))
    except SchemaError as exc:
        print("s1ap-simplify: %s: %s" % (args.source, exc), file=sys.stderr)
        return 2
    if args.check:
        drift = []
        for name, content in sorted(files.items()):
            path = os.path.join(args.outdir, name)
            try:
                with open(path, encoding="utf-8") as handle:
                    if handle.read() != content:
                        drift.append(path)
            except FileNotFoundError:
                drift.append(path)
        extra = sorted(set(os.listdir(args.outdir)) - set(files)) if os.path.isdir(args.outdir) else []
        for path in drift:
            print("s1ap-simplify: %s differs from its derivation" % path, file=sys.stderr)
        for name in extra:
            print("s1ap-simplify: %s is not derived" % os.path.join(args.outdir, name),
                  file=sys.stderr)
        return 1 if drift or extra else 0
    os.makedirs(args.outdir, exist_ok=True)
    for name, content in sorted(files.items()):
        with open(os.path.join(args.outdir, name), "w", encoding="utf-8") as handle:
            handle.write(content)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
