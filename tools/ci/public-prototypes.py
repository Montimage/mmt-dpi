#!/usr/bin/env python3
"""public-prototypes.py — the public C API as the headers declare it, and the
documentation's copies of it (issue #581, F-DOCS-007).

The prototypes the reference pages show (``docs/MMT-*.md``) are copies of the
``MMTAPI`` declarations in ``src/mmt_core/public_include/*.h``. Nothing kept
the copies current, so after the #231 typedef pass most of them still showed
``int``/``uint32_t protocol_id``/``char *``/``void *``. This helper is the one
parser both sides go through:

* ``header_prototypes(include_dir)`` maps every ``MMTAPI … MMTCALL name(…)``
  function to its normalised prototype;
* ``doc_prototypes(path)`` yields every declaration-shaped statement in the
  page's fenced ``c`` blocks, with its line number;
* ``normalise(text)`` is the comparison form: comments, ``MMTAPI``,
  ``MMTCALL``, ``extern`` and ``__attribute__((…))`` dropped, whitespace
  collapsed, ``()`` read as ``(void)``.

Usage (paths relative to the repository root):

  public-prototypes.py --list
        print ``name<TAB>prototype`` for every public function, sorted.
  public-prototypes.py --check DOC...
        compare every prototype a DOC shows for a public function with the
        header; print each mismatch with the header's form. A
        declaration-shaped statement that names no public function is not
        checked (callbacks the reader writes, such as ``packet_handler``).
        Exit 1 on a mismatch, or when no DOC shows a public prototype at
        all (the parser lost them).

``scripts/validate-doc-drift.sh`` runs ``--check`` over every ``docs/*.md``
but the append-only ``docs/DECISIONS.md``; a later
check (issue #582) can import this file (``importlib`` by path) to reuse the
header parser instead of writing another.

Exit codes: 0 = consistent, 1 = mismatch, 2 = helper broken (no header
declaration parsed, unreadable file, bad arguments).
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INCLUDE_DIR = os.path.join(ROOT, "src", "mmt_core", "public_include")

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# A statement that starts with one of these is code, not a declaration.
NOT_A_TYPE = {"return", "else", "case", "goto", "do", "sizeof", "if", "while",
              "for", "switch", "typedef", "define"}


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _drop_attributes(text):
    """Remove every ``__attribute__((…))``, balancing the parentheses."""
    out = []
    i = 0
    while True:
        j = text.find("__attribute__", i)
        if j < 0:
            out.append(text[i:])
            return "".join(out)
        out.append(text[i:j])
        k = text.find("(", j)
        if k < 0:
            out.append(text[j:])
            return "".join(out)
        depth = 0
        for m in range(k, len(text)):
            if text[m] == "(":
                depth += 1
            elif text[m] == ")":
                depth -= 1
                if depth == 0:
                    i = m + 1
                    break
        else:
            return "".join(out)


def normalise(text):
    """The comparison form of one prototype (without the trailing ``;``)."""
    text = _drop_attributes(_strip_comments(text))
    text = re.sub(r"\b(MMTAPI|MMTCALL|extern)\b", " ", text)
    text = " ".join(text.replace(";", " ").split())
    text = re.sub(r"\s*([*(),\[\]])\s*", r"\1", text)
    # Keep one space between a type and a following name or pointer.
    text = re.sub(r"\*(?=[A-Za-z_])", "* ", text)
    text = re.sub(r"(?<=[A-Za-z0-9_])\*", " *", text)
    text = re.sub(r"\*\s+\*", "**", text)
    text = re.sub(r",", ", ", text)
    return re.sub(r"\(\)$", "(void)", text.strip())


def _split_statements(code):
    """(offset, statement) for every ``;``-terminated statement of ``code``."""
    start = 0
    for m in re.finditer(r"[;{}]", code):
        if m.group(0) == ";":
            yield start, code[start:m.start()]
        start = m.end()


def _declared_name(stmt):
    """The function name a declaration-shaped statement declares, else None."""
    m = re.match(r"\s*((?:" + IDENT + r"[\s*]+|\*\s*)+?)(" + IDENT + r")\s*\(", stmt)
    if not m or "=" in stmt.split("(", 1)[0]:
        return None
    words = re.findall(IDENT, m.group(1))
    if not words or words[0] in NOT_A_TYPE:
        return None
    # The text after the opening parenthesis must close once, at the end.
    rest = stmt[m.end() - 1:].strip()
    rest = _drop_attributes(rest).strip()
    depth = 0
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return m.group(2) if not rest[i + 1:].strip() else None
    return None


def header_prototypes(include_dir=INCLUDE_DIR):
    """{name: normalised prototype} for every public MMTAPI function."""
    protos = {}
    for h in sorted(glob.glob(os.path.join(include_dir, "*.h"))):
        with open(h, encoding="utf-8", errors="replace") as f:
            text = _strip_comments(f.read())
        text = re.sub(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", "", text, flags=re.M)
        for _, stmt in _split_statements(text):
            if not re.search(r"\bMMTAPI\b", stmt) or "MMTCALL" not in stmt:
                continue
            stmt = stmt[re.search(r"\bMMTAPI\b", stmt).start():]
            name = _declared_name(_drop_attributes(stmt).replace("MMTCALL", " "))
            if name:
                protos[name] = normalise(stmt)
    return protos


def doc_prototypes(path):
    """(line, name, raw statement) for every declaration in the c fences."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    i = 0
    while i < len(lines):
        if not re.match(r"^\s*```\s*c\s*$", lines[i]):
            i += 1
            continue
        first = i + 2  # 1-based number of the fence's first code line
        j = i + 1
        while j < len(lines) and not re.match(r"^\s*```", lines[j]):
            j += 1
        code = "\n".join(lines[i + 1:j])
        # Blank out comments and preprocessor lines, keeping the offsets.
        masked = re.sub(r"/\*.*?\*/|//[^\n]*|^[ \t]*#[^\n]*",
                        lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                        code, flags=re.S | re.M)
        for off, stmt in _split_statements(masked):
            name = _declared_name(stmt)
            if name:
                lead = len(stmt) - len(stmt.lstrip())
                line = first + code.count("\n", 0, off + lead)
                yield line, name, stmt.strip()
        i = j + 1


def check(docs, protos):
    """Print each mismatch; return the number of failures."""
    bad = total = 0
    for doc in docs:
        rel = os.path.relpath(os.path.abspath(doc), ROOT)
        checked = 0
        for line, name, stmt in doc_prototypes(doc):
            if name not in protos:
                continue
            checked += 1
            if normalise(stmt) != protos[name]:
                bad += 1
                print(f"✗ {rel}:{line}: {name} differs from the header")
                print(f"      doc:    {normalise(stmt)};")
                print(f"      header: {protos[name]};")
        if checked:
            print(f"  {rel}: {checked} public prototype(s) checked")
        total += checked
    if total == 0:
        # A page set that shows no public prototype at all means the doc
        # parser lost them, not that the pages are current.
        print("✗ no prototype of a public function found in the given DOCs")
        bad += 1
    return bad


def main(argv):
    if len(argv) < 2 or argv[1] not in ("--list", "--check"):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: public-prototypes.py --list | --check DOC...",
              file=sys.stderr)
        return 2
    protos = header_prototypes()
    if not protos:
        print(f"✗ no MMTAPI declaration parsed under {INCLUDE_DIR}",
              file=sys.stderr)
        return 2
    if argv[1] == "--list":
        for name in sorted(protos):
            print(f"{name}\t{protos[name]};")
        return 0
    docs = argv[2:]
    if not docs:
        print("✗ --check needs at least one DOC", file=sys.stderr)
        return 2
    for d in docs:
        if not os.path.isfile(d):
            print(f"✗ {d}: no such file", file=sys.stderr)
            return 2
    return 1 if check(docs, protos) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
