#!/bin/bash
# Issue #565: the feed part of data/ip_ranges.txt (and the IPv6 runtime file
# data/ip_ranges.cdn.txt) is built by tools/gen-ip-range-data.py from the
# published provider feeds tools/refresh_cdn_ranges.sh downloads. These checks
# run the builder on fixture feeds -- no network -- and prove it labels cloud
# tenancy and CDN edges apart from first-party services, keeps the
# hand-maintained entries verbatim, is byte-for-byte deterministic, refuses a
# feed whose sha256, URL or content does not match, and that the committed
# data files record every feed's URL, fetch date and sha256.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GEN="$PROJECT_DIR/tools/gen-ip-range-data.py"
TABLE="$PROJECT_DIR/tools/gen-ip-range-table.py"
fails=0
checks=0

ok() { checks=$((checks + 1)); echo "  ✓ $1"; }
ko() { checks=$((checks + 1)); fails=$((fails + 1)); echo "  ✗ $1"; }

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 1; }

T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT
F="$T/feeds"
mkdir "$F"

AZURE_URL="https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20261026.json"
cat > "$F/aws.json" <<'EOF'
{"syncToken": "1", "createDate": "2026-11-02-00-00-00",
 "prefixes": [
  {"ip_prefix": "10.0.0.0/14", "service": "AMAZON"},
  {"ip_prefix": "10.1.0.0/16", "service": "AMAZON"},
  {"ip_prefix": "10.1.0.0/16", "service": "CLOUDFRONT"},
  {"ip_prefix": "10.2.0.0/16", "service": "EC2"},
  {"ip_prefix": "10.8.0.0/24", "service": "CLOUDFRONT_ORIGIN_FACING"}],
 "ipv6_prefixes": [
  {"ipv6_prefix": "2001:db8:a::/48", "service": "AMAZON"},
  {"ipv6_prefix": "2001:db8:1::/48", "service": "CLOUDFRONT"}]}
EOF
cat > "$F/goog.json" <<'EOF'
{"syncToken": "2", "creationTime": "2026-11-02T00:00:00",
 "prefixes": [{"ipv4Prefix": "172.16.0.0/12"}, {"ipv4Prefix": "172.16.1.0/24"},
              {"ipv6Prefix": "2001:db8:5::/48"}]}
EOF
cat > "$F/cloud.json" <<'EOF'
{"syncToken": "2", "creationTime": "2026-11-02T00:00:00",
 "prefixes": [{"ipv4Prefix": "172.16.0.0/14", "service": "Google Cloud"}]}
EOF
cat > "$F/azure.json" <<'EOF'
{"changeNumber": 7, "cloud": "Public", "values": [
 {"name": "AzureCloud", "properties": {"addressPrefixes": ["192.168.0.0/16", "2001:db8:2::/48"]}},
 {"name": "AzureCloud.westeurope", "properties": {"addressPrefixes": ["192.168.1.0/24"]}},
 {"name": "AzureFrontDoor.Frontend", "properties": {"addressPrefixes": ["198.18.0.0/15"]}}]}
EOF
printf '100.64.0.0/12\n' > "$F/cloudflare-v4.txt"
printf '2001:db8:3::/48\n' > "$F/cloudflare-v6.txt"
printf '{"addresses": ["100.80.0.0/16"], "ipv6_addresses": ["2001:db8:4::/48"]}\n' > "$F/fastly.json"

manifest() { # rewrite MANIFEST from the files on disk
    : > "$F/MANIFEST"
    while read -r name file url; do
        [ "$name" = "azure" ] && url="$AZURE_URL"
        printf '%s %s 2026-11-02 %s\n' "$name" "$(sha256sum "$F/$file" | cut -d' ' -f1)" \
            "$url" >> "$F/MANIFEST"
    done < <(python3 -I "$GEN" --list-feeds)
}
manifest

cat > "$T/data.txt" <<'EOF'
# version: 2026-10-01
# === hand-maintained entries ===
# a provider without a feed
1.2.3.0/24 PROTO_ALPHA

# === feed entries ===
stale lines the builder replaces
EOF
cp "$T/data.txt" "$T/data.orig"
cat > "$T/protos.h" <<'EOF'
#define PROTO_ALPHA 10
#define PROTO_AWS 35
#define PROTO_GOOGLE 134
#define PROTO_CLOUDFRONT 593
#define PROTO_FASTLY 608
#define PROTO_CLOUDFLARE 662
#define PROTO_AZURE 663
#define PROTO_GOOGLE_CLOUD 667
EOF

build() { python3 -I "$GEN" --feeds "$F" --data "$T/data.txt" --cdn "$T/cdn.txt" "$@"; }

if build > /dev/null; then
    ok "builds the data files from fixture feeds"
else
    ko "builds the data files from fixture feeds"
fi
cat > "$T/want4.txt" <<'EOF'
1.2.3.0/24 PROTO_ALPHA
10.1.0.0/16 PROTO_CLOUDFRONT
10.8.0.0/24 PROTO_CLOUDFRONT
10.0.0.0/16 PROTO_AWS
10.2.0.0/15 PROTO_AWS
172.16.0.0/14 PROTO_GOOGLE_CLOUD
172.20.0.0/14 PROTO_GOOGLE
172.24.0.0/13 PROTO_GOOGLE
192.168.0.0/16 PROTO_AZURE
100.64.0.0/12 PROTO_CLOUDFLARE
100.80.0.0/16 PROTO_FASTLY
EOF
if grep -v -e '^#' -e '^$' "$T/data.txt" | diff -u "$T/want4.txt" -; then
    ok "labels CloudFront vs AWS, google_cloud vs google (goog minus cloud), AzureCloud only"
else
    ko "labels CloudFront vs AWS, google_cloud vs google (goog minus cloud), AzureCloud only"
fi
cat > "$T/want6.txt" <<'EOF'
2001:db8:1::/48      CLOUDFRONT
2001:db8:a::/48      AWS
2001:db8:5::/48      GOOGLE
2001:db8:2::/48      AZURE
2001:db8:3::/48      CLOUDFLARE
2001:db8:4::/48      FASTLY
EOF
if grep -v -e '^#' -e '^$' "$T/cdn.txt" | diff -u "$T/want6.txt" -; then
    ok "writes the IPv6 prefixes to the runtime file"
else
    ko "writes the IPv6 prefixes to the runtime file"
fi
if grep -qx '# a provider without a feed' "$T/data.txt" && grep -qx '# version: 2026-11-02' "$T/data.txt" \
    && grep -q '^# feed aws: https://ip-ranges.amazonaws.com/ip-ranges.json$' "$T/data.txt" \
    && grep -q "^#   fetched 2026-11-02, sha256 $(sha256sum "$F/aws.json" | cut -d' ' -f1), syncToken 1," "$T/data.txt" \
    && grep -q "^# feed azure: $AZURE_URL\$" "$T/cdn.txt"; then
    ok "keeps the hand-maintained part, dates the file and records URL, date and sha256"
else
    ko "keeps the hand-maintained part, dates the file and records URL, date and sha256"
fi
if python3 "$TABLE" --data "$T/data.txt" --header "$T/protos.h" --output "$T/out.inc" > /dev/null; then
    ok "the result is valid gen-ip-range-table.py input"
else
    ko "the result is valid gen-ip-range-table.py input"
fi
cp "$T/data.txt" "$T/data.1"; cp "$T/cdn.txt" "$T/cdn.1"
build > /dev/null
if cmp -s "$T/data.txt" "$T/data.1" && cmp -s "$T/cdn.txt" "$T/cdn.1" && build --check > /dev/null; then
    ok "a rebuild is byte-for-byte identical and --check passes"
else
    ko "a rebuild is byte-for-byte identical and --check passes"
fi
sed -i 's/^172.20.0.0\/14 PROTO_GOOGLE$/172.20.0.0\/14 PROTO_AWS/' "$T/data.txt"
rc=0; build --check > /dev/null 2> "$T/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -q "stale" "$T/err.txt"; then
    ok "--check flags a hand-edited feed entry"
else
    ko "--check flags a hand-edited feed entry (exit $rc)"
fi
cp "$T/data.1" "$T/data.txt"

# expect_reject NAME PATTERN: the builder must exit 1, write nothing and name
# the fault (PATTERN, an extended regex) on stderr.
expect_reject() {
    local name="$1" pattern="$2" rc=0
    cp "$T/data.txt" "$T/data.before"
    python3 -I "$GEN" --feeds "$F" --data "$T/data.txt" --cdn "$T/cdn.txt" \
        > /dev/null 2> "$T/err.txt" || rc=$?
    if [ "$rc" -eq 1 ] && cmp -s "$T/data.txt" "$T/data.before" && cmp -s "$T/cdn.txt" "$T/cdn.1" \
        && grep -Eq "$pattern" "$T/err.txt"; then
        ok "rejects $name"
    else
        ko "rejects $name (exit $rc): $(cat "$T/err.txt")"
    fi
}

printf ' ' >> "$F/fastly.json"
expect_reject "a feed whose sha256 differs from the MANIFEST" "fastly: sha256 of fastly.json is"
manifest
grep -v '^google-cloud ' "$F/MANIFEST" > "$T/m" && mv "$T/m" "$F/MANIFEST"
expect_reject "a MANIFEST missing a feed" "feed 'google-cloud' is missing"
manifest
sed -i 's#https://www.cloudflare.com/ips-v4#https://evil.example/ips-v4#' "$F/MANIFEST"
expect_reject "a feed URL that is not the published one" "cloudflare-v4 URL .* is not the published feed's"
manifest
sed 's/100.64.0.0\/12/100.64.0.1\/12/' "$F/cloudflare-v4.txt" > "$T/c" && mv "$T/c" "$F/cloudflare-v4.txt"
manifest
expect_reject "a malformed feed prefix" "cloudflare-v4: '100.64.0.1/12' is not a network prefix"
printf '100.64.0.0/12\n' > "$F/cloudflare-v4.txt"
manifest
printf '{"addresses": "100.80.0.0/16", "ipv6_addresses": []}\n' > "$F/fastly.json"
manifest
expect_reject "a feed of the wrong shape" "fastly: 'addresses' is not a list"
printf '{"addresses": ["100.80.0.0/16"], "ipv6_addresses": ["2001:db8:4::/48"]}\n' > "$F/fastly.json"
manifest
sed 's/^1.2.3.0\/24 PROTO_ALPHA$/100.64.0.0\/12 PROTO_ALPHA/' "$T/data.1" > "$T/data.txt"
expect_reject "a feed prefix the hand-maintained part already lists" \
    "100.64.0.0/12 is listed by PROTO_ALPHA and PROTO_CLOUDFLARE"
cp "$T/data.1" "$T/data.txt"
grep -v '^# === hand-maintained' "$T/data.1" > "$T/data.txt"
expect_reject "a data file without the hand-maintained marker" "needs one '# === hand-maintained entries' line"
cp "$T/data.1" "$T/data.txt"

printf '<a href="%s">old</a> <a href="%s">new</a> %s\n' \
    "${AZURE_URL/20261026/20261019}" "$AZURE_URL" "https://example.com/ServiceTags_Public_20991231.json" \
    > "$T/page.html"
if [ "$(python3 -I "$GEN" --azure-url "$T/page.html")" = "$AZURE_URL" ]; then
    ok "--azure-url picks the newest ServiceTags URL on download.microsoft.com"
else
    ko "--azure-url picks the newest ServiceTags URL on download.microsoft.com"
fi
printf '<html>nothing here</html>\n' > "$T/page.html"
rc=0; python3 -I "$GEN" --azure-url "$T/page.html" > /dev/null 2>&1 || rc=$?
if [ "$rc" -eq 1 ]; then ok "--azure-url fails on a page without the link"; else ko "--azure-url fails on a page without the link (exit $rc)"; fi

rc=0; bash "$PROJECT_DIR/tools/refresh_cdn_ranges.sh" --bogus > /dev/null 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then ok "refresh_cdn_ranges.sh rejects an unknown option"; else ko "refresh_cdn_ranges.sh rejects an unknown option (exit $rc)"; fi

# The committed data files: every feed's URL, fetch date and sha256 is
# recorded in both, under the same version, and no first-party "amazon"
# label is left in the compiled-in table.
prov=1
version="$(sed -n 's/^# version: //p' "$PROJECT_DIR/data/ip_ranges.txt")"
while read -r name _file url; do
    for f in data/ip_ranges.txt data/ip_ranges.cdn.txt; do
        line="$(grep -A1 "^# feed $name: https://" "$PROJECT_DIR/$f" | tail -n 1)"
        if [ "$url" != "https://www.microsoft.com/en-us/download/details.aspx?id=56519" ]; then
            grep -qx "# feed $name: $url" "$PROJECT_DIR/$f" || prov=0
        fi
        echo "$line" | grep -Eq '^#   fetched [0-9]{4}-[0-9]{2}-[0-9]{2}, sha256 [0-9a-f]{64}' || prov=0
    done
done < <(python3 -I "$GEN" --list-feeds)
if [ "$prov" -eq 1 ] && [ -n "$version" ] \
    && grep -qx "# version: $version" "$PROJECT_DIR/data/ip_ranges.cdn.txt" \
    && ! grep -q ' PROTO_AMAZON$' "$PROJECT_DIR/data/ip_ranges.txt"; then
    ok "committed data files record every feed's URL, date and sha256 (version $version)"
else
    ko "committed data files record every feed's URL, date and sha256"
fi

if [ "$fails" -ne 0 ]; then
    echo "IP-range feed builder: $fails/$checks checks failed"
    exit 1
fi
echo "IP-range feed builder: all $checks checks passed"
