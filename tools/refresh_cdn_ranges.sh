#!/usr/bin/env bash
#
# refresh_cdn_ranges.sh — regenerate the IP-range data from each provider's
# published, machine-readable IP-range feed (issues #75, #83, #565).
#
# 1. Downloads every feed tools/gen-ip-range-data.py --list-feeds names into
#    a new empty directory and records, in its MANIFEST, one line per feed:
#    "<name> <sha256> <fetch date, UTC> <url>".
# 2. Runs tools/gen-ip-range-data.py on that directory (offline): it rewrites
#    the feed part of data/ip_ranges.txt (the compiled-in IPv4 table's
#    source; its hand-maintained part is kept) and data/ip_ranges.cdn.txt
#    (the IPv6 prefixes, for MMT_DPI_IP_RANGES_FILE), recording each feed's
#    URL, fetch date and sha256 next to its entries.
# 3. Regenerates the C table with tools/gen-ip-range-table.py.
#
# Only this script touches the network; the build and the tests read the
# committed data files. The download directory is kept: pass it back with
# --feeds DIR to rebuild the same files byte-for-byte without a download
# (each file's sha256 is checked against the MANIFEST first).
#
# Usage:
#     tools/refresh_cdn_ranges.sh               # download, then rebuild
#     tools/refresh_cdn_ranges.sh --feeds DIR   # rebuild from a kept download
#     git diff data/                            # review, then rerun both
#                                               # phase0 gates (tools/phase0/README.md)
#
# Requirements: curl, python3, sha256sum. Review each provider's terms of use
# before redistributing the generated ranges.
#
# Feeds and labels (cloud tenancy and CDN edges never get a first-party app
# label; the rules are in tools/gen-ip-range-data.py):
#   AWS ip-ranges.json          -> CLOUDFRONT (CDN), AWS (everything else)
#   Google goog.json/cloud.json -> GOOGLE_CLOUD (cloud.json), GOOGLE (goog minus cloud)
#   Azure ServiceTags_Public    -> AZURE (service tag AzureCloud); the weekly file's
#                                  URL is read from Microsoft's download page
#   Cloudflare ips-v4/ips-v6    -> CLOUDFLARE
#   Fastly public-ip-list       -> FASTLY
# The downloaded files are untrusted data: they are parsed, never executed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN_DATA="$REPO_ROOT/tools/gen-ip-range-data.py"
GEN_TABLE="$REPO_ROOT/tools/gen-ip-range-table.py"

feeds=""
case "${1:-}" in
    "") ;;
    --feeds)
        [ $# -eq 2 ] || { echo "usage: $0 [--feeds DIR]" >&2; exit 2; }
        feeds="$2" ;;
    *) echo "usage: $0 [--feeds DIR]" >&2; exit 2 ;;
esac

need="python3"
[ -n "$feeds" ] || need="curl python3 sha256sum"
for tool in $need; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: '$tool' is required but not found in PATH" >&2
        exit 1
    fi
done

fetch() { # <url> <file>
    curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$2" "$1"
}

if [ -z "$feeds" ]; then
    feeds="$(mktemp -d "${TMPDIR:-/tmp}/mmt-ip-feeds.XXXXXX")"
    today="$(date -u +%Y-%m-%d)"
    manifest="$feeds/MANIFEST"
    printf '# IP-range feeds downloaded by tools/refresh_cdn_ranges.sh\n' > "$manifest"
    while read -r name file url; do
        if [ "$name" = "azure" ]; then
            # The weekly ServiceTags file has a dated URL: read it from the page.
            fetch "$url" "$feeds/azure-download-page.html"
            url="$(python3 -I "$GEN_DATA" --azure-url "$feeds/azure-download-page.html")"
        fi
        echo "fetching $name: $url" >&2
        fetch "$url" "$feeds/$file"
        sha="$(sha256sum "$feeds/$file" | cut -d' ' -f1)"
        printf '%s %s %s %s\n' "$name" "$sha" "$today" "$url" >> "$manifest"
    done < <(python3 -I "$GEN_DATA" --list-feeds)
    echo "feeds kept in $feeds (rebuild offline: $0 --feeds $feeds)" >&2
fi

python3 -I "$GEN_DATA" --feeds "$feeds"
python3 -I "$GEN_TABLE"
