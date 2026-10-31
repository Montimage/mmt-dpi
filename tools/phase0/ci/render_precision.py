#!/usr/bin/env python3
"""render_precision.py -- confusion-matrix metrics for the phase0 precision gate.

Part of the MMT-DPI Master Improvement Plan, Phase 7 (M9, issue #74); the
per-class accounting correction is issue #373 (F-TEST-002).

Reads the raw TSV produced by check_precision.sh -- one row per labelled pcap:

    <pcap_rel> <actual_label> <total> <tp> <fp> <abstained> <predicted_csv> [<method_csv>]

where <predicted_csv> is the retained prediction histogram emitted by
phase0_precision (sorted `name:count` pairs, or `-`), and the optional
<method_csv> (issue #567, F-BUG-306) splits the packets given an application
verdict by classification method (`method:verdicts:tp` triples, or `-`). The script folds every
row into an actual-by-predicted CONFUSION MATRIX and derives, per class C:

    TP = C[C][C];  FP = sum_{a != C} C[a][C];  FN = sum_{p != C} C[C][p]
    precision = TP / (TP + FP);  recall = TP / (TP + FN)

A wrong prediction therefore increments the FP of the predicted class AND the
FN of the actual class -- the accounting the pre-#373 bare `fp` column could
not express. An abstention (no application verdict, recorded under the
`<abstain>` pseudo-column) counts as an FN of the actual class only.

Per classification method M (issue #567) it derives, over the labelled rows,
verdicts(M) = packets given an application verdict by method M, tp(M) = those
naming the actual label, fp(M) = the rest and precision(M) = tp(M) /
verdicts(M) -- every method of METHODS is listed, so a method no verdict used
reads n/a. Rows without a <method_csv> field contribute to no method.

With ``--abstention <abstain.tsv>`` (issue #527) it also renders the seeded
random-payload abstention set check_precision.sh runs: rows in the same raw
format whose actual label is ``<abstain>`` (phase0_precision is given a label
no protocol carries). Every packet there should get no application verdict;
the section records, per capture and overall, how many did not (accepted,
with the predicted names) and the unknown rate = abstained / total. It is
rendered after the labelled metrics and never enters their confusion matrix,
so the labelled rows are unchanged by it.

Usage:
    render_precision.py <raw.tsv>           # text report on stdout
    render_precision.py --json <raw.tsv>    # machine-readable metrics on stdout
    render_precision.py [--json] <raw.tsv> --abstention <abstain.tsv>

Exit codes: 0 ok; 2 unreadable/empty/malformed input (a bad row is a harness
failure to surface, never a silently dropped example -- F-TEST-002).
"""

import json
import sys

ABSTAIN = "<abstain>"

# Issue #567: the classification methods in ascending confidence order -- the
# MMT_CLASSIFICATION_METHOD_* values of data_defs.h, named as
# get_classification_method_name() names them.
METHODS = ("none", "port", "ip", "correlated", "hostname", "dpi")

HEADER = """\
# Phase 7 (M9, issue #74) precision/recall baseline -- labelled CI golden subset.
# Deterministic: derived from the classifier's decisions (see phase0_precision.c).
# Accounting (issue #373, F-TEST-002): counts derive from a retained
# actual-by-predicted confusion matrix -- a packet predicted as a different
# application is an FN of its actual class and an FP of the predicted class;
# an abstention (no application verdict) is an FN of its actual class only.
# Refresh with: tools/phase0/ci/check_precision.sh (then commit precision.txt).
#"""


class InputError(Exception):
    """Malformed raw TSV -- reported with file/line, never skipped."""


def _fail(path, lineno, msg):
    raise InputError("%s:%d: %s" % (path, lineno, msg))


def _parse_int(path, lineno, field, value):
    try:
        n = int(value)
    except ValueError:
        _fail(path, lineno, "field %s is not an integer: %r" % (field, value))
    if n < 0:
        _fail(path, lineno, "field %s is negative: %r" % (field, value))
    return n


def parse_raw(path):
    """Parse the raw TSV into a list of row dicts; strict -- any malformed row
    raises InputError (exit 2), so harness breakage can never drop an example."""
    rows = []
    try:
        fh = open(path, "r", encoding="utf-8")
    except OSError as e:
        raise InputError("%s: cannot read: %s" % (path, e))
    with fh:
        try:
            lines = list(fh)
        except UnicodeDecodeError as e:
            raise InputError("%s: not UTF-8 text: %s" % (path, e))
        for lineno, line in enumerate(lines, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            fields = line.split("\t")
            if len(fields) not in (7, 8):
                _fail(path, lineno,
                      "expected 7 or 8 tab-separated fields, got %d"
                      % len(fields))
            rel, actual = fields[0], fields[1].strip().lower()
            total = _parse_int(path, lineno, "total", fields[2])
            tp = _parse_int(path, lineno, "tp", fields[3])
            fp = _parse_int(path, lineno, "fp", fields[4])
            abstained = _parse_int(path, lineno, "abstained", fields[5])
            if tp + fp + abstained != total:
                _fail(path, lineno,
                      "tp+fp+abstained (%d+%d+%d) != total (%d)"
                      % (tp, fp, abstained, total))
            pred = {}
            csv = fields[6].strip()
            if csv and csv != "-":
                for pair in csv.split(","):
                    name, sep, count = pair.partition(":")
                    name = name.strip().lower()
                    if not sep or not name:
                        _fail(path, lineno,
                              "bad predicted_csv pair: %r" % pair)
                    if any(c.isspace() for c in name):
                        _fail(path, lineno,
                              "whitespace in predicted label: %r" % name)
                    pred[name] = pred.get(name, 0) + _parse_int(
                        path, lineno, "predicted_csv", count)
            if sum(pred.values()) != tp + fp:
                _fail(path, lineno,
                      "predicted histogram sums to %d, expected tp+fp=%d"
                      % (sum(pred.values()), tp + fp))
            if pred.get(actual, 0) != tp:
                _fail(path, lineno,
                      "predicted[%r]=%d != tp=%d"
                      % (actual, pred.get(actual, 0), tp))
            methods = {}
            mcsv = fields[7].strip() if len(fields) == 8 else "-"
            if mcsv and mcsv != "-":
                for triple in mcsv.split(","):
                    parts = triple.split(":")
                    if len(parts) != 3 or parts[0].strip() not in METHODS:
                        _fail(path, lineno,
                              "bad method_csv triple: %r" % triple)
                    name = parts[0].strip()
                    if name in methods:
                        _fail(path, lineno,
                              "duplicate method in method_csv: %r" % name)
                    m_verdicts = _parse_int(path, lineno, "method_csv",
                                            parts[1])
                    m_tp = _parse_int(path, lineno, "method_csv", parts[2])
                    if m_tp > m_verdicts:
                        _fail(path, lineno,
                              "method %r: tp %d > verdicts %d"
                              % (name, m_tp, m_verdicts))
                    methods[name] = {"verdicts": m_verdicts, "tp": m_tp}
            if len(fields) == 8:
                if sum(m["verdicts"] for m in methods.values()) != tp + fp:
                    _fail(path, lineno,
                          "method verdicts sum to %d, expected tp+fp=%d"
                          % (sum(m["verdicts"] for m in methods.values()),
                             tp + fp))
                if sum(m["tp"] for m in methods.values()) != tp:
                    _fail(path, lineno,
                          "method tp sums to %d, expected tp=%d"
                          % (sum(m["tp"] for m in methods.values()), tp))
            rows.append({"pcap": rel, "actual": actual, "total": total,
                         "tp": tp, "misclassified": fp, "abstained": abstained,
                         "pred": pred, "methods": methods})
    if not rows:
        raise InputError("%s: no data rows -- the harness produced nothing; "
                         "refusing to render an empty metric set" % path)
    return rows


def abstention_metrics(rows):
    """Per-capture and overall unknown rate of the abstention set."""
    for r in rows:
        if r["actual"] != ABSTAIN:
            raise InputError("%s: abstention row labelled %r, expected %r"
                             % (r["pcap"], r["actual"], ABSTAIN))
    total = sum(r["total"] for r in rows)
    abstained = sum(r["abstained"] for r in rows)
    return {"rows": rows, "total": total, "abstained": abstained,
            "accepted": total - abstained,
            "unknown_rate": (abstained / total) if total else None}


def build_metrics(rows):
    """Fold rows into the confusion matrix and derive per-class + micro metrics."""
    confusion = {}
    for r in rows:
        row = confusion.setdefault(r["actual"], {})
        for name, n in r["pred"].items():
            row[name] = row.get(name, 0) + n
        if r["abstained"]:
            row[ABSTAIN] = row.get(ABSTAIN, 0) + r["abstained"]

    classes = sorted(set(confusion.keys()) |
                     {p for row in confusion.values() for p in row
                      if p != ABSTAIN})
    per_class = []
    o_tp = o_fp = o_fn = o_total = 0
    for c in classes:
        tp = confusion.get(c, {}).get(c, 0)
        fp = sum(row.get(c, 0) for a, row in confusion.items() if a != c)
        fn = sum(n for p, n in confusion.get(c, {}).items() if p != c)
        support = sum(r["total"] for r in rows if r["actual"] == c)
        per_class.append({
            "name": c, "support": support, "tp": tp, "fp": fp, "fn": fn,
            "precision": (tp / (tp + fp)) if (tp + fp) else None,
            "recall": (tp / (tp + fn)) if (tp + fn) else None,
        })
        o_tp += tp
        o_fp += fp
        o_fn += fn
        o_total += support
    overall = {
        "total": o_total, "tp": o_tp, "fp": o_fp, "fn": o_fn,
        "accuracy": (o_tp / o_total) if o_total else None,
        "micro_precision": (o_tp / (o_tp + o_fp)) if (o_tp + o_fp) else None,
        "micro_recall": (o_tp / (o_tp + o_fn)) if (o_tp + o_fn) else None,
    }
    per_method = []
    for m in METHODS:
        verdicts = sum(r["methods"].get(m, {}).get("verdicts", 0)
                       for r in rows)
        m_tp = sum(r["methods"].get(m, {}).get("tp", 0) for r in rows)
        per_method.append({
            "name": m, "verdicts": verdicts, "tp": m_tp,
            "fp": verdicts - m_tp,
            "precision": (m_tp / verdicts) if verdicts else None,
        })
    return {"confusion": confusion, "classes": per_class, "overall": overall,
            "methods": per_method}


def _ratio(x):
    return "n/a" if x is None else "%.4f" % x


def render_text(rows, metrics):
    out = [HEADER]
    for r in rows:
        pred = ",".join("%s:%d" % (n, r["pred"][n])
                        for n in sorted(r["pred"])) or "-"
        out.append("%-28s %-8s total=%-6d tp=%-6d miscls=%-4d abstain=%-4d "
                   "recall=%-6s pred=%s"
                   % (r["pcap"], r["actual"], r["total"], r["tp"],
                      r["misclassified"], r["abstained"],
                      _ratio(r["tp"] / r["total"] if r["total"] else None),
                      pred))

    confusion = metrics["confusion"]
    out += ["", "# --- confusion matrix (actual-by-predicted) ---",
            "%-28s %-16s %s" % ("actual", "predicted", "count")]
    for actual in sorted(confusion):
        for pred in sorted(confusion[actual]):
            out.append("%-28s %-16s %d"
                       % (actual, pred, confusion[actual][pred]))

    out += ["", "# --- per-class ---",
            "%-16s %-8s %-8s %-8s %-8s %-10s %s"
            % ("class", "support", "tp", "fp", "fn", "precision", "recall")]
    for c in metrics["classes"]:
        out.append("%-16s %-8d %-8d %-8d %-8d %-10s %s"
                   % (c["name"], c["support"], c["tp"], c["fp"], c["fn"],
                      _ratio(c["precision"]), _ratio(c["recall"])))

    o = metrics["overall"]
    out += ["", "# --- overall (micro-averaged) ---",
            "total=%-6d tp=%-6d fp=%-6d fn=%-6d accuracy=%-6s "
            "micro_precision=%-6s micro_recall=%s"
            % (o["total"], o["tp"], o["fp"], o["fn"], _ratio(o["accuracy"]),
               _ratio(o["micro_precision"]), _ratio(o["micro_recall"]))]

    out += ["", "# --- per-method (issue #567): how each verdict was reached ---",
            "# verdicts = packets given an application verdict by the method;",
            "# precision = tp / verdicts. Methods in ascending confidence.",
            "%-16s %-8s %-8s %-8s %s"
            % ("method", "verdicts", "tp", "fp", "precision")]
    for m in metrics["methods"]:
        out.append("%-16s %-8d %-8d %-8d %s"
                   % (m["name"], m["verdicts"], m["tp"], m["fp"],
                      _ratio(m["precision"])))
    return "\n".join(out) + "\n"


def render_abstention(ab):
    out = ["", "# --- abstention set (issue #527): seeded random payloads ---",
           "# No capture carries an application protocol: every packet should "
           "get no",
           "# application verdict. accepted = packets given one anyway (pred "
           "names them);",
           "# unknown_rate = abstain / total. Generated by "
           "gen_tcpip_pcap.py --abstention.",
           "%-28s %-8s %-8s %-8s %-12s %s"
           % ("capture", "total", "abstain", "accepted", "unknown_rate",
              "pred")]
    for r in ab["rows"]:
        pred = ",".join("%s:%d" % (n, r["pred"][n])
                        for n in sorted(r["pred"])) or "-"
        out.append("%-28s %-8d %-8d %-8d %-12s %s"
                   % (r["pcap"], r["total"], r["abstained"],
                      r["total"] - r["abstained"],
                      _ratio(r["abstained"] / r["total"] if r["total"]
                             else None), pred))
    out.append("abstention total=%-6d abstain=%-6d accepted=%-6d "
               "unknown_rate=%s"
               % (ab["total"], ab["abstained"], ab["accepted"],
                  _ratio(ab["unknown_rate"])))
    # Issue #567: every accepted packet there is a false positive -- name the
    # method that accepted it.
    by_method = {}
    for r in ab["rows"]:
        for name, m in r["methods"].items():
            by_method[name] = by_method.get(name, 0) + m["verdicts"]
    out.append("abstention accepted_by_method=%s"
               % (",".join("%s:%d" % (m, by_method[m]) for m in METHODS
                           if by_method.get(m)) or "-"))
    return "\n".join(out) + "\n"


def main(argv):
    args = list(argv)
    as_json = "--json" in args
    if as_json:
        args.remove("--json")
    abstention_tsv = None
    if "--abstention" in args:
        i = args.index("--abstention")
        if i + 1 >= len(args):
            args = []
        else:
            abstention_tsv = args[i + 1]
            del args[i:i + 2]
    if len(args) != 1:
        sys.stderr.write("Usage: render_precision.py [--json] <raw.tsv> "
                         "[--abstention <abstain.tsv>]\n")
        return 2
    try:
        rows = parse_raw(args[0])
        metrics = build_metrics(rows)
        ab = (abstention_metrics(parse_raw(abstention_tsv))
              if abstention_tsv else None)
    except InputError as e:
        sys.stderr.write("x render_precision: %s\n" % e)
        return 2
    if as_json:
        doc = {"rows": rows, "confusion": metrics["confusion"],
               "classes": metrics["classes"], "overall": metrics["overall"],
               "methods": metrics["methods"]}
        if ab is not None:
            doc["abstention"] = ab
        json.dump(doc, sys.stdout, indent=1, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(rows, metrics))
        if ab is not None:
            sys.stdout.write(render_abstention(ab))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
