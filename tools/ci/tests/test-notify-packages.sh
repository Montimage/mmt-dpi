#!/usr/bin/env bash
# test-notify-packages.sh — self-test for the Montimage/packages release
# notification (issue #76).
#
# (1) tools/ci/check-release-verification.sh passes on the repository's
#     release workflow and fails on mutated copies of it: no notify step, a
#     step before the publish, a step not gated to tags or run under
#     always(), a step without continue-on-error, a run: with its own exit,
#     the token in run: instead of env:, the token in a second step, and a
#     sparse checkout without the helper.
# (2) tools/ci/notify-packages.sh, driven with a stub `gh` on PATH (no
#     network, no token): an empty token warns, calls nothing and exits 0;
#     a token sends one POST to repos/Montimage/packages/dispatches with
#     event_type=mmt-dpi-release and the tag, the token only as GH_TOKEN and
#     never printed, nor traced under an inherited xtrace; a refused
#     dispatch warns and exits 0; no tag exits 2.
#
# Usage: bash tools/ci/tests/test-notify-packages.sh
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECKER="${REPO_ROOT}/tools/ci/check-release-verification.sh"
HELPER="${REPO_ROOT}/tools/ci/notify-packages.sh"
WORKFLOW="${REPO_ROOT}/.github/workflows/release-packages.yml"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

pass=0
fail=0
ok()  { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

echo "=== notify-packages self-test ==="

# --- (1) the static check ----------------------------------------------------
if out="$(bash "$CHECKER" 2>&1)"; then
    ok "checker passes on the repository's release workflow"
else
    bad "checker fails on the repository's release workflow:"
    printf '%s\n' "$out" | grep '✗' | sed 's/^/      /'
fi

# Fixtures: mutated copies of the workflow, one per broken contract, written
# by name into $WORK/fixtures; each must make the checker exit 1 naming the
# notify contract. A mutation that changes nothing fails the self-test.
mkdir -p "$WORK/fixtures"
python3 - "$WORKFLOW" "$WORK/fixtures" <<'PY' || bad "fixture generation failed"
import sys

src, out = sys.argv[1], sys.argv[2]
wf = open(src, encoding="utf-8").read()

NAME = "      - name: Notify Montimage/packages (APT repository rebuild)\n"
IF = "        if: startsWith(github.ref, 'refs/tags/v')\n"
COE = "        continue-on-error: true\n"
ENV = ("        env:\n"
       "          PACKAGES_DISPATCH_TOKEN: ${{ secrets.PACKAGES_DISPATCH_TOKEN }}\n")
RUN = '        run: bash src/tools/ci/notify-packages.sh "$GITHUB_REF_NAME"\n'
PUBLISH = "      - name: Create and publish the GitHub Release\n"
SPARSE = "            tools/ci/notify-packages.sh\n"

mutations = {
    "removed": [(RUN, "        run: echo skipped\n")],
    "before-publish": [
        (NAME + IF + COE + ENV + RUN, ""),
        (PUBLISH, NAME + IF + COE + ENV + RUN + PUBLISH),
    ],
    "not-tag-gated": [(NAME + IF, NAME)],
    "always": [(NAME + IF, NAME +
                "        if: always() && startsWith(github.ref, 'refs/tags/v')\n")],
    "failure-or": [(NAME + IF, NAME +
                    "        if: failure() || startsWith(github.ref, 'refs/tags/v')\n")],
    "no-continue-on-error": [(IF + COE, IF)],
    "own-exit": [(RUN, RUN[:-1] + " || exit 1\n")],
    "token-in-run": [(ENV + RUN,
                      '        run: PACKAGES_DISPATCH_TOKEN="${{ secrets.PACKAGES_DISPATCH_TOKEN }}"'
                      ' bash src/tools/ci/notify-packages.sh "$GITHUB_REF_NAME"\n')],
    "token-in-second-step": [(PUBLISH + "        env:\n", PUBLISH + "        env:\n"
                              "          LEAK: ${{ secrets.PACKAGES_DISPATCH_TOKEN }}\n")],
    "not-checked-out": [(SPARSE, "")],
}
for name, edits in mutations.items():
    s = wf
    for old, new in edits:
        if s.count(old) != 1:
            sys.exit(f"fixture {name}: anchor not found exactly once: {old!r}")
        s = s.replace(old, new)
    open(f"{out}/{name}.yml", "w", encoding="utf-8").write(s)
PY

for fixture in "$WORK"/fixtures/*.yml; do
    label="$(basename "$fixture" .yml)"
    out="$(timeout 60 bash "$CHECKER" --workflow "$fixture" 2>&1)"; rc=$?
    if [ "$rc" -eq 1 ] && printf '%s\n' "$out" | grep -q '✗ .*\(notify\|PACKAGES_DISPATCH_TOKEN\)'; then
        ok "fixture ${label}: checker rejects it"
    else
        bad "fixture ${label}: checker exit $rc, want 1 with a notify violation"
        printf '%s\n' "$out" | tail -5 | sed 's/^/      /'
    fi
done
[ "$(find "$WORK/fixtures" -name '*.yml' | wc -l)" -eq 10 ] \
    || bad "expected 10 fixtures, got $(find "$WORK/fixtures" -name '*.yml' | wc -l)"

# --- (2) the helper, against a stub gh -------------------------------------
mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Records each call; fails when STUB_GH_RC is non-zero.
{
    printf 'GH_TOKEN=%s\n' "${GH_TOKEN:-}"
    printf 'PACKAGES_DISPATCH_TOKEN=%s\n' "${PACKAGES_DISPATCH_TOKEN:-}"
    printf 'ARG %s\n' "$@"
} >> "$STUB_GH_LOG"
if [ "${STUB_GH_RC:-0}" -ne 0 ]; then
    echo "gh: Not Found (HTTP 404)" >&2
    exit "$STUB_GH_RC"
fi
STUB
chmod +x "$WORK/bin/gh"
export STUB_GH_LOG="$WORK/gh.log"
SECRET="tok-$$-not-a-real-token"

run_helper() {   # run_helper <token> <gh rc> [args...]; sets out, rc
    local token="$1" ghrc="$2"
    shift 2
    : > "$STUB_GH_LOG"
    out="$(PATH="$WORK/bin:$PATH" STUB_GH_RC="$ghrc" \
        PACKAGES_DISPATCH_TOKEN="$token" bash "$HELPER" "$@" 2>&1)"
    rc=$?
}

run_helper "" 0 v9.9.9
if [ "$rc" -eq 0 ] && [ ! -s "$STUB_GH_LOG" ] \
        && printf '%s\n' "$out" | grep -q '^::warning title=APT repository not notified::PACKAGES_DISPATCH_TOKEN is not set' \
        && printf '%s\n' "$out" | grep -q 'gh workflow run apt-repo.yml -R Montimage/packages'; then
    ok "empty token: warning with the manual trigger, no API call, exit 0"
else
    bad "empty token: rc=$rc, out: $out"
fi

run_helper "$SECRET" 0 v9.9.9
log="$(cat "$STUB_GH_LOG")"
if [ "$rc" -eq 0 ] \
        && printf '%s\n' "$log" | grep -qx 'ARG api' \
        && printf '%s\n' "$log" | grep -qx 'ARG POST' \
        && printf '%s\n' "$log" | grep -qx 'ARG repos/Montimage/packages/dispatches' \
        && printf '%s\n' "$log" | grep -qx 'ARG event_type=mmt-dpi-release' \
        && printf '%s\n' "$log" | grep -qx 'ARG client_payload\[tag\]=v9.9.9' \
        && printf '%s\n' "$log" | grep -qx "GH_TOKEN=${SECRET}" \
        && printf '%s\n' "$log" | grep -qx 'PACKAGES_DISPATCH_TOKEN=' \
        && [ "$(grep -c '^GH_TOKEN=' "$STUB_GH_LOG")" -eq 1 ]; then
    ok "token set: one POST dispatches mmt-dpi-release with the tag, token as GH_TOKEN only"
else
    bad "token set: rc=$rc, gh calls:"; sed 's/^/      /' "$STUB_GH_LOG"
fi
if printf '%s\n' "$out" | grep -qF "$SECRET"; then
    bad "token set: the helper printed the token"
else
    ok "token set: the token never appears in the output"
fi

run_helper "$SECRET" 1 v9.9.9
if [ "$rc" -eq 0 ] \
        && printf '%s\n' "$out" | grep -q '^::warning title=APT repository not notified::the mmt-dpi-release dispatch to Montimage/packages for v9.9.9 failed' \
        && ! printf '%s\n' "$out" | grep -qF "$SECRET"; then
    ok "refused dispatch: warning, exit 0, token not printed"
else
    bad "refused dispatch: rc=$rc, out: $out"
fi

# Inherited xtrace (bash -x): the helper turns it off before the token is
# read. Control: a copy without that line must trace the token, so the probe
# is shown to detect a leak.
traced() {   # traced <script>: 0 when bash -x output holds the token
    : > "$STUB_GH_LOG"
    PATH="$WORK/bin:$PATH" PACKAGES_DISPATCH_TOKEN="$SECRET" \
        bash -x "$1" v9.9.9 2>&1 | grep -qF "$SECRET"
}
grep -v '^{ set +x; } 2>/dev/null$' "$HELPER" > "$WORK/no-set-x.sh"
if ! traced "$WORK/no-set-x.sh"; then
    bad "inherited xtrace: the control copy leaked nothing — the probe tests nothing"
elif traced "$HELPER"; then
    bad "inherited xtrace: the helper traced the token"
else
    ok "inherited xtrace: the token is not traced (a copy without set +x leaks it)"
fi

run_helper "$SECRET" 0
if [ "$rc" -eq 2 ] && [ ! -s "$STUB_GH_LOG" ]; then
    ok "no tag: usage error (exit 2), no API call"
else
    bad "no tag: rc=$rc"
fi

echo "notify-packages self-test: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
