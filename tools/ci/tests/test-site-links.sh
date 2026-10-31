#!/usr/bin/env bash
#
# test-site-links.sh — self-test for the site-navigation guards of
# tools/ci/check-site-links.sh (issue #579, F-UX-008/F-UX-009/F-UX-017).
#
# The real docs tree and built site pass by construction, so this self-test
# proves the guards can fail: it runs the REAL checker on a fixture source
# tree (a _config.yml, a docs index with `permalink: /docs/`, two guides) and
# a fixture built site (index.html, docs/index.html, one guide page), each
# copied fresh per scenario, without Jekyll.
#
# Scenario -> expected checker exit:
#   clean fixture source tree                                       -> 0
#   a guide with a literal [TOC] line                               -> 1
#   a guide without `layout: default`                               -> 1
#   a guide without a `title:`                                      -> 1
#   a guide without front matter                                    -> 1
#   no docs index (no page with `permalink: /docs/`)                -> 1
#   a docs-index label naming another title                         -> 1
#   a docs-index label that is a whole-word part of the title       -> 0
#   a docs-index label matching only part of a title word           -> 1
#   _layouts/ Liquid hrefs (templates are not scanned as pages)     -> 0
#   clean fixture built site                                        -> 0
#   a built page rendering <p>[TOC]</p>                             -> 1
#   a built page without a link to the site root                    -> 1
#   a built page without a link to the docs index                   -> 1
#   the real source tree (docs)                                     -> 0
#
# Usage: bash tools/ci/tests/test-site-links.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
CHECKER="${REPO_ROOT}/tools/ci/check-site-links.sh"
[ -f "${CHECKER}" ] || { echo "✗ missing ${CHECKER}" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

checks=0
failures=0
pass() { checks=$((checks + 1)); echo "  ✓ $1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); echo "  ✗ $1" >&2; }

# expect DESC WANT DIR [NEEDLE] — runs the real checker on DIR; NEEDLE, when
# given, must appear in its output (the finding the scenario plants).
expect() {
    local desc="$1" want="$2" dir="$3" needle="${4:-}"
    local got=0 out
    out="$(bash "${CHECKER}" "${dir}" 2>&1)" || got=$?
    if [ "${got}" -ne "${want}" ]; then
        fail "${desc} (exit ${got}, want ${want})"
        printf '%s\n' "${out}" | sed 's/^/      /' >&2
    elif [ -n "${needle}" ] && ! grep -qF -- "${needle}" <<<"${out}"; then
        fail "${desc} (no '${needle}' in the output)"
        printf '%s\n' "${out}" | sed 's/^/      /' >&2
    else
        pass "${desc}"
    fi
}

# --- fixture source tree ---------------------------------------------------
SRC="${WORK}/src.orig"
mkdir -p "${SRC}"
printf 'title: Fixture\nbaseurl: /fixture\n' >"${SRC}/_config.yml"
cat >"${SRC}/index.html" <<'EOF'
<!doctype html><html><body><a href="docs/">Docs</a> <a href="Guide-One.html">One</a></body></html>
EOF
cat >"${SRC}/README.md" <<'EOF'
---
layout: default
title: "Fixture Documentation"
permalink: /docs/
---

# Fixture Documentation

## Section ##
* [Guide One](./Guide-One.md)
* [Two](./Guide-Two.md)
EOF
cat >"${SRC}/Guide-One.md" <<'EOF'
---
layout: default
title: "Guide One"
---

# Guide One

* TOC
{:toc}

## Part
EOF
cat >"${SRC}/Guide-Two.md" <<'EOF'
---
layout: default
title: "Guide Two"
---

# Guide Two
EOF
mkdir -p "${SRC}/docs"   # the index.html `docs/` link target

# fresh_src — a scratch copy of the clean fixture source tree.
fresh_src() { rm -rf "${WORK}/src"; cp -r "${SRC}" "${WORK}/src"; }

echo "-- source tree --"
fresh_src
expect "clean fixture source tree passes" 0 "${WORK}/src" "every guide is navigable"

fresh_src
sed -i 's/^\* TOC$/[TOC]/; /^{:toc}$/d' "${WORK}/src/Guide-One.md"
expect "a literal [TOC] line fails" 1 "${WORK}/src" "Guide-One.md:8: literal [TOC] marker"

fresh_src
sed -i '/^layout: default$/d' "${WORK}/src/Guide-Two.md"
expect "a guide without layout: default fails" 1 "${WORK}/src" "lacks \`layout: default\`"

fresh_src
sed -i '/^title:/d' "${WORK}/src/Guide-Two.md"
expect "a guide without a title fails" 1 "${WORK}/src" "lacks a \`title:\`"

fresh_src
sed -i '1,/^---$/{/^---$/!d}; 1,2{/^---$/d}' "${WORK}/src/Guide-Two.md"
expect "a guide without front matter fails" 1 "${WORK}/src" "Guide-Two.md: no front matter"

fresh_src
sed -i '/^permalink: \/docs\/$/d' "${WORK}/src/README.md"
expect "a tree without a docs index fails" 1 "${WORK}/src" "expected one docs index (permalink: /docs/), found 0"

fresh_src
sed -i 's/\[Guide One\]/[Getting Started]/' "${WORK}/src/README.md"
expect "a docs-index label naming another title fails" 1 "${WORK}/src" \
       "label 'Getting Started' does not name the title of Guide-One.md"

fresh_src
sed -i 's/^title: "Guide One"$/title: "The Guide One, Revised"/' "${WORK}/src/Guide-One.md"
expect "a label that is a whole-word part of the title passes" 0 "${WORK}/src"

fresh_src
sed -i 's/^title: "Guide Two"$/title: "Twofold"/' "${WORK}/src/Guide-Two.md"
expect "a label matching only part of a title word fails" 1 "${WORK}/src" \
       "label 'Two' does not name the title of Guide-Two.md"

fresh_src
mkdir -p "${WORK}/src/_layouts" "${WORK}/src/_includes"
printf '%s\n' '<a href="{{ "/docs/" | relative_url }}">Docs</a>' >"${WORK}/src/_layouts/default.html"
printf '%s\n' '<a href="{{ site.baseurl }}/missing.html">x</a>' >"${WORK}/src/_includes/nav.html"
expect "_layouts/ and _includes/ templates are not scanned as pages" 0 "${WORK}/src"

# --- fixture built site ----------------------------------------------------
SITE="${WORK}/site.orig"
mkdir -p "${SITE}/docs"
cat >"${SITE}/index.html" <<'EOF'
<!doctype html><html><body><a href="docs/">Docs</a></body></html>
EOF
cat >"${SITE}/docs/index.html" <<'EOF'
<!doctype html><html><body><a href="/fixture/">Home</a> <a href="/fixture/docs/">Docs</a> <a href="../Guide-One.html">Guide One</a></body></html>
EOF
cat >"${SITE}/Guide-One.html" <<'EOF'
<!doctype html><html><body><a href="/fixture/">Home</a> <a href="/fixture/docs/">Docs</a><h2 id="part">Part</h2></body></html>
EOF

fresh_site() { rm -rf "${WORK}/site"; cp -r "${SITE}" "${WORK}/site"; }

echo "-- built site --"
fresh_site
expect "clean fixture built site passes" 0 "${WORK}/site" "across 3 page(s)"

fresh_site
sed -i 's|<h2 id="part">|<p>[TOC]</p><h2 id="part">|' "${WORK}/site/Guide-One.html"
expect "a page rendering <p>[TOC]</p> fails" 1 "${WORK}/site" "Guide-One.html: renders a literal [TOC] marker"

fresh_site
sed -i 's|<a href="/fixture/">Home</a> ||' "${WORK}/site/Guide-One.html"
expect "a page without a site-root link fails" 1 "${WORK}/site" "Guide-One.html: no link to the site root"

fresh_site
sed -i 's|<a href="/fixture/docs/">Docs</a>||' "${WORK}/site/Guide-One.html"
expect "a page without a docs-index link fails" 1 "${WORK}/site" "Guide-One.html: no link to the docs index"

echo "-- real tree --"
expect "the real docs source tree passes" 0 "${REPO_ROOT}/docs"

echo ""
if [ "${failures}" -eq 0 ]; then
    echo "✓ site-links self-test: ${checks}/${checks} checks passed"
else
    echo "✗ site-links self-test: ${failures} of ${checks} checks failed" >&2
    exit 1
fi
