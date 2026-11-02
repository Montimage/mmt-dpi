#!/usr/bin/env python3
"""gen-ip-range-data.py -- build the IP-range data files from published cloud feeds (issue #565).

tools/refresh_cdn_ranges.sh downloads each provider's published IP-range feed
into a new empty directory and records, in that directory's MANIFEST, the URL,
the fetch date and the sha256 of every file. This script reads that directory
-- it never touches the network -- and writes:

  data/ip_ranges.txt      the source of the compiled-in IPv4 table
                          (tools/gen-ip-range-table.py turns it into the .inc):
                          its hand-maintained part is kept verbatim, its feed
                          part is rewritten from the feeds;
  data/ip_ranges.cdn.txt  the IPv6 prefixes of the same feeds, in the
                          MMT_DPI_IP_RANGES_FILE format (the compiled-in table
                          is IPv4 only, docs/External-Attribution.md).

Labels -- cloud tenancy and CDN edges are never labelled as a first-party app:
  PROTO_CLOUDFRONT    AWS prefixes of service CLOUDFRONT or CLOUDFRONT_ORIGIN_FACING
  PROTO_AWS           every other AWS prefix (any service, the AMAZON superset
                      included), minus the CloudFront ones
  PROTO_GOOGLE_CLOUD  Google Cloud customer ranges (cloud.json)
  PROTO_GOOGLE        Google's own ranges: goog.json minus cloud.json
  PROTO_AZURE         the Azure service tag AzureCloud (all public Azure space)
  PROTO_CLOUDFLARE    Cloudflare's edge (ips-v4 / ips-v6)
  PROTO_FASTLY        Fastly's edge (public-ip-list)
Each label's prefixes are collapsed (adjacent and nested ones merged) and
sorted by address; "minus" removes the address space, so a provider's own
specific label wins over its generic one whatever the prefix lengths.

Refusals (exit 1, nothing written): a feed missing from the MANIFEST or listed
twice, a URL that is not the feed's, a file whose sha256 differs from the
recorded one, a malformed feed, a prefix two labels list identically, or a
feed prefix the hand-maintained part already lists. Nested prefixes of
different labels are allowed: the longest prefix wins (gen-ip-range-table.py).

The downloaded files are untrusted data: they are parsed (json, ipaddress)
and never executed, and a file above 64 MiB is refused.

Usage:
  python3 -I tools/gen-ip-range-data.py --feeds DIR            # write both files
  python3 -I tools/gen-ip-range-data.py --feeds DIR --check    # exit 1 when stale
  python3 -I tools/gen-ip-range-data.py --list-feeds           # name, file, URL
  python3 -I tools/gen-ip-range-data.py --azure-url PAGE       # the ServiceTags
                       JSON URL named by Microsoft's download page (a saved file)
  options: --data FILE, --cdn FILE (defaults: the repository's)

Exit: 0 = written / current, 1 = invalid input or stale output, 2 = usage or I/O.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(ROOT, "data", "ip_ranges.txt")
CDN = os.path.join(ROOT, "data", "ip_ranges.cdn.txt")

MAX_BYTES = 64 << 20
AZURE_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
AZURE_URL_RE = re.compile(r"https://download\.microsoft\.com/download/[0-9A-Za-z/-]+/"
                          r"ServiceTags_Public_(\d{8})\.json")

# name, file in the feeds directory, URL (None: resolved from AZURE_PAGE)
FEEDS = (
    ("aws", "aws.json", "https://ip-ranges.amazonaws.com/ip-ranges.json"),
    ("google", "goog.json", "https://www.gstatic.com/ipranges/goog.json"),
    ("google-cloud", "cloud.json", "https://www.gstatic.com/ipranges/cloud.json"),
    ("azure", "azure.json", None),
    ("cloudflare-v4", "cloudflare-v4.txt", "https://www.cloudflare.com/ips-v4"),
    ("cloudflare-v6", "cloudflare-v6.txt", "https://www.cloudflare.com/ips-v6"),
    ("fastly", "fastly.json", "https://api.fastly.com/public-ip-list"),
)

# label, what it covers (one comment line in the data files)
LABELS = (
    ("PROTO_CLOUDFRONT", "AWS CloudFront edge (CDN): aws services CLOUDFRONT, CLOUDFRONT_ORIGIN_FACING"),
    ("PROTO_AWS", "AWS cloud tenancy: every other aws prefix, minus CloudFront"),
    ("PROTO_GOOGLE_CLOUD", "Google Cloud customer ranges (tenancy): google-cloud"),
    ("PROTO_GOOGLE", "Google's own services: google minus google-cloud"),
    ("PROTO_AZURE", "Azure cloud tenancy: azure service tag AzureCloud"),
    ("PROTO_CLOUDFLARE", "Cloudflare edge (CDN): cloudflare-v4, cloudflare-v6"),
    ("PROTO_FASTLY", "Fastly edge (CDN): fastly"),
)

MANUAL_MARK = "# === hand-maintained entries"
FEED_MARK = "# === feed entries"
VERSION_RE = re.compile(r"^#\s*version:\s*(\d{4}-\d{2}-\d{2})\s*$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class InputError(Exception):
    pass


def _date(text, where):
    if not DATE_RE.match(text):
        raise InputError("%s: %r is not a YYYY-MM-DD date" % (where, text))
    try:
        datetime.datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise InputError("%s: %r is not a YYYY-MM-DD date" % (where, text))
    return text


def read_manifest(feeds):
    """{name: (sha256, date, url)} after checking every recorded fact."""
    path = os.path.join(feeds, "MANIFEST")
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    known = {name: url for name, _file, url in FEEDS}
    got, errors = {}, []
    for no, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = "MANIFEST:%d" % no
        fields = line.split()
        if len(fields) != 4:
            errors.append('%s: expected "<name> <sha256> <YYYY-MM-DD> <url>"' % where)
            continue
        name, sha, date, url = fields
        if name not in known:
            errors.append("%s: unknown feed %r" % (where, name))
            continue
        if name in got:
            errors.append("%s: feed %r listed twice" % (where, name))
            continue
        if not SHA_RE.match(sha):
            errors.append("%s: %r is not a lowercase sha256" % (where, sha))
        try:
            _date(date, where)
        except InputError as e:
            errors.append(str(e))
        want = known[name]
        if (want is None and not AZURE_URL_RE.fullmatch(url)) or (want is not None and url != want):
            errors.append("%s: %s URL %r is not the published feed's" % (where, name, url))
        got[name] = (sha, date, url)
    for name in known:
        if name not in got:
            errors.append("MANIFEST: feed %r is missing" % name)
    if errors:
        raise InputError("\n".join(errors))
    return got


def load_feed(feeds, name, filename, sha):
    path = os.path.join(feeds, filename)
    if os.path.islink(path) or not os.path.isfile(path):
        raise InputError("%s: %s is not a regular file" % (name, filename))
    if os.path.getsize(path) > MAX_BYTES:
        raise InputError("%s: %s is larger than %d bytes" % (name, filename, MAX_BYTES))
    with open(path, "rb") as f:
        raw = f.read()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != sha:
        raise InputError("%s: sha256 of %s is %s, the MANIFEST records %s"
                         % (name, filename, actual, sha))
    return raw


def _json(raw, name):
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise InputError("%s: not JSON (%s)" % (name, e))
    if not isinstance(doc, dict):
        raise InputError("%s: the top level is not an object" % name)
    return doc


def _net(text, name):
    if not isinstance(text, str):
        raise InputError("%s: prefix %r is not a string" % (name, text))
    try:
        net = ipaddress.ip_network(text.strip(), strict=True)
    except ValueError as e:
        raise InputError("%s: %r is not a network prefix (%s)" % (name, text, e))
    if net.prefixlen == 0:
        raise InputError("%s: %r covers the whole address space" % (name, text))
    return net


def _list(doc, key, name):
    value = doc.get(key)
    if not isinstance(value, list):
        raise InputError("%s: %r is not a list" % (name, key))
    return value


def _str_field(doc, key):
    value = doc.get(key)
    return str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else "-"


def parse_aws(raw):
    doc = _json(raw, "aws")
    cdn, rest = [], []
    for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for entry in _list(doc, key, "aws"):
            if not isinstance(entry, dict):
                raise InputError("aws: a %s entry is not an object" % key)
            net = _net(entry.get(field), "aws")
            service = entry.get("service")
            if service in ("CLOUDFRONT", "CLOUDFRONT_ORIGIN_FACING"):
                cdn.append(net)
            else:
                rest.append(net)
    meta = "syncToken %s, createDate %s" % (_str_field(doc, "syncToken"), _str_field(doc, "createDate"))
    return cdn, rest, meta


def parse_google(raw, name):
    doc = _json(raw, name)
    nets = []
    for entry in _list(doc, "prefixes", name):
        if not isinstance(entry, dict):
            raise InputError("%s: a prefixes entry is not an object" % name)
        text = entry.get("ipv4Prefix", entry.get("ipv6Prefix"))
        nets.append(_net(text, name))
    meta = "syncToken %s, creationTime %s" % (_str_field(doc, "syncToken"), _str_field(doc, "creationTime"))
    return nets, meta


def parse_azure(raw):
    doc = _json(raw, "azure")
    tags = [v for v in _list(doc, "values", "azure")
            if isinstance(v, dict) and v.get("name") == "AzureCloud"]
    if len(tags) != 1:
        raise InputError("azure: expected one AzureCloud service tag, found %d" % len(tags))
    props = tags[0].get("properties")
    if not isinstance(props, dict):
        raise InputError("azure: the AzureCloud tag has no properties")
    nets = [_net(p, "azure") for p in _list(props, "addressPrefixes", "azure")]
    meta = "changeNumber %s, cloud %s" % (_str_field(doc, "changeNumber"), _str_field(doc, "cloud"))
    return nets, meta


def parse_lines(raw, name):
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise InputError("%s: not ASCII text" % name)
    return [_net(t, name) for t in text.split()]


def parse_fastly(raw):
    doc = _json(raw, "fastly")
    return [_net(p, "fastly") for key in ("addresses", "ipv6_addresses")
            for p in _list(doc, key, "fastly")]


def minus(nets, removed):
    """Address space of nets outside removed, as collapsed prefixes."""
    removed = collapse(removed, 4) + collapse(removed, 6)
    out = []
    for net in nets:
        parts = [net]
        for r in removed:
            if r.version != net.version or not r.overlaps(net):
                continue
            nxt = []
            for p in parts:
                if p.subnet_of(r):
                    continue
                if r.subnet_of(p):
                    nxt.extend(p.address_exclude(r))
                else:
                    nxt.append(p)
            parts = nxt
        out.extend(parts)
    return out


def collapse(nets, version):
    return sorted(ipaddress.collapse_addresses(n for n in nets if n.version == version))


def build_labels(feeds, manifest):
    raw = {name: load_feed(feeds, name, filename, manifest[name][0])
           for name, filename, _url in FEEDS}
    cdn, aws_rest, aws_meta = parse_aws(raw["aws"])
    goog, goog_meta = parse_google(raw["google"], "google")
    cloud, cloud_meta = parse_google(raw["google-cloud"], "google-cloud")
    azure, azure_meta = parse_azure(raw["azure"])
    cf = parse_lines(raw["cloudflare-v4"], "cloudflare-v4") + parse_lines(raw["cloudflare-v6"], "cloudflare-v6")
    fastly = parse_fastly(raw["fastly"])
    metas = {"aws": aws_meta, "google": goog_meta, "google-cloud": cloud_meta, "azure": azure_meta}
    sets = {
        "PROTO_CLOUDFRONT": cdn,
        "PROTO_AWS": minus(aws_rest, cdn),
        "PROTO_GOOGLE_CLOUD": cloud,
        "PROTO_GOOGLE": minus(goog, cloud),
        "PROTO_AZURE": azure,
        "PROTO_CLOUDFLARE": cf,
        "PROTO_FASTLY": fastly,
    }
    labels = {v: {label: collapse(nets, v) for label, nets in sets.items()} for v in (4, 6)}
    return labels, metas


def split_data(path):
    """(version, manual block lines) of the current data file."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    starts = [i for i, l in enumerate(lines) if l.startswith(MANUAL_MARK)]
    ends = [i for i, l in enumerate(lines) if l.startswith(FEED_MARK)]
    if len(starts) != 1 or len(ends) != 1 or starts[0] > ends[0]:
        raise InputError("%s: needs one %r line followed by one %r line" % (path, MANUAL_MARK, FEED_MARK))
    version = None
    for line in lines[:starts[0]]:
        m = VERSION_RE.match(line)
        if m:
            version = _date(m.group(1), path)
    manual = lines[starts[0] + 1:ends[0]]
    while manual and not manual[-1].strip():
        manual.pop()
    return version, manual


def manual_prefixes(manual):
    out = {}
    for line in manual:
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        try:
            out[ipaddress.ip_network(fields[0], strict=True)] = fields[1] if len(fields) > 1 else "?"
        except ValueError:
            continue  # gen-ip-range-table.py names the fault
    return out


def check_overlaps(labels, manual):
    errors = []
    seen = dict(manual)
    for label, _desc in LABELS:
        for net in labels[4][label]:
            if net in seen:
                errors.append("%s is listed by %s and %s" % (net, seen[net], label))
            else:
                seen[net] = label
    v6 = {}
    for label, _desc in LABELS:
        for net in labels[6][label]:
            if net in v6:
                errors.append("%s is listed by %s and %s" % (net, v6[net], label))
            else:
                v6[net] = label
    if errors:
        raise InputError("\n".join(errors))


def provenance(manifest, metas):
    out = []
    for name, filename, _url in FEEDS:
        sha, date, url = manifest[name]
        out.append("# feed %s: %s" % (name, url))
        extra = (", " + metas[name]) if name in metas else ""
        out.append("#   fetched %s, sha256 %s%s" % (date, sha, extra))
    return out


HEADER = """\
# MMT-DPI IPv4 prefix -> protocol table (issues #557, #565)
#
# version: {version}
#
# The compiled-in IPv4 attribution ranges behind get_proto_id_from_address()
# (src/mmt_tcpip/lib/mmt_tcpip_classif_utils.c). The C table
# src/mmt_tcpip/lib/mmt_tcpip_classif_proto_ip_address.inc is generated from
# this file -- never edit it by hand.
#
# Format: one "<network>/<prefix> <PROTO_ID>" entry per line; '#' starts a
# comment line.
#   <network>  dotted-quad IPv4 network address, host bits zero
#   <prefix>   prefix length, 1 .. 32
#   <PROTO_ID> a PROTO_* id #defined in src/mmt_tcpip/include/mmt_tcpip_protocols.h
# Prefixes may nest and their order carries no meaning: an address takes the
# protocol of the longest listed prefix that contains it. A network/prefix is
# listed at most once.
#
# The file has two parts:
#   - the hand-maintained entries: providers that publish no machine-readable
#     feed. Edit them by hand, set "version:" to the date of the change, then
#       python3 tools/gen-ip-range-table.py           # regenerate the .inc
#       python3 tools/gen-ip-range-table.py --check   # what the core_engine suite runs
#   - the feed entries: generated by tools/gen-ip-range-data.py from the
#     published provider feeds that tools/refresh_cdn_ranges.sh downloads; the
#     source URL, fetch date and sha256 of every feed are recorded with them.
#     Never edit them by hand: rerun tools/refresh_cdn_ranges.sh.
# Either way, rerun both phase0 gates (tools/phase0/README.md): a relabel is a
# classification change.
"""


def render_data(version, manual, labels, manifest, metas):
    out = HEADER.format(version=version).splitlines()
    out += ["", MANUAL_MARK + " ===", *manual, ""]
    out += [FEED_MARK + ": generated by tools/gen-ip-range-data.py, do not edit ==="]
    out += provenance(manifest, metas)
    for label, desc in LABELS:
        nets = labels[4][label]
        out += ["", "# %s -- %s (%d prefixes)" % (label, desc, len(nets))]
        out += ["%s %s" % (n, label) for n in nets]
    return "\n".join(out) + "\n"


def render_cdn(version, labels, manifest, metas):
    out = [
        "# MMT-DPI -- IPv6 CDN/cloud IP-range attribution (issues #75, #565)",
        "# Generated by tools/gen-ip-range-data.py from the published provider",
        "# feeds tools/refresh_cdn_ranges.sh downloads; do not edit. Inert unless",
        "# MMT_DPI_IP_RANGES_FILE points at it. The IPv4 prefixes of the same feeds,",
        "# with the same labels, are compiled in (data/ip_ranges.txt). Review each",
        "# provider's terms of use before redistributing.",
        "# version: %s" % version,
    ]
    out += provenance(manifest, metas)
    for label, desc in LABELS:
        nets = labels[6][label]
        if not nets:
            continue
        name = label[len("PROTO_"):]
        out += ["", "# %s -- %s (%d prefixes)" % (name, desc, len(nets))]
        # The loader splits on whitespace: keep a space after a long prefix.
        out += ["%-20s %s" % (n, name) for n in nets]
    return "\n".join(out) + "\n"


def azure_url(page):
    with open(page, "rb") as f:
        raw = f.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InputError("%s is larger than %d bytes" % (page, MAX_BYTES))
    urls = {m.group(0): m.group(1) for m in AZURE_URL_RE.finditer(raw.decode("utf-8", "replace"))}
    if not urls:
        raise InputError("%s names no ServiceTags_Public_YYYYMMDD.json URL" % page)
    return max(urls, key=lambda u: (urls[u], u))


def write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--feeds", metavar="DIR", help="directory with MANIFEST and the feed files")
    ap.add_argument("--check", action="store_true", help="compare instead of writing")
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--cdn", default=CDN)
    ap.add_argument("--list-feeds", action="store_true")
    ap.add_argument("--azure-url", metavar="PAGE")
    args = ap.parse_args()

    try:
        if args.list_feeds:
            for name, filename, url in FEEDS:
                print("%s %s %s" % (name, filename, url or AZURE_PAGE))
            return 0
        if args.azure_url:
            print(azure_url(args.azure_url))
            return 0
        if not args.feeds:
            ap.error("--feeds DIR is required")
        manifest = read_manifest(args.feeds)
        labels, metas = build_labels(args.feeds, manifest)
        current, manual = split_data(args.data)
        check_overlaps(labels, manual_prefixes(manual))
        version = max([d for _s, d, _u in manifest.values()] + ([current] if current else []))
        outputs = ((args.data, render_data(version, manual, labels, manifest, metas)),
                   (args.cdn, render_cdn(version, labels, manifest, metas)))
    except InputError as e:
        print(str(e), file=sys.stderr)
        print("✗ invalid feed input -- nothing written", file=sys.stderr)
        return 1
    except OSError as e:
        print("✗ %s" % e, file=sys.stderr)
        return 2

    try:
        if args.check:
            stale = []
            for path, text in outputs:
                with open(path, encoding="utf-8") as f:
                    if f.read() != text:
                        stale.append(path)
            if stale:
                print("✗ stale: %s -- regenerate: python3 -I tools/gen-ip-range-data.py --feeds DIR"
                      % ", ".join(stale), file=sys.stderr)
                return 1
            print("✓ IP-range data current, version %s" % version)
            return 0
        for path, text in outputs:
            write(path, text)
    except OSError as e:
        print("✗ %s" % e, file=sys.stderr)
        return 2
    counts = ", ".join("%s %d/%d" % (label[len("PROTO_"):], len(labels[4][label]), len(labels[6][label]))
                       for label, _d in LABELS)
    print("wrote %s and %s, version %s (IPv4/IPv6 prefixes: %s)" % (args.data, args.cdn, version, counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
