#!/usr/bin/env bash
#
# local-gates.sh — run the pull-request gates on this machine, before pushing
# (issue #553, F-CI-010).
#
# One command for what the required lint, verify-helpers and doc-validators
# jobs of .github/workflows/c-cpp.yml check on a pull request. The gate list
# is not copied here: the script reads those jobs' `run:` steps from the
# workflow and runs them in order, each with its job's and its own `env:`, so
# a step added to, changed in or removed from a job changes what this runs.
# Skipped, because the gates image (below) already provides what they set up:
#   - `uses:` steps (checkout, caches, artifact upload, Ruby, bootstrap-deps);
#   - the steps named in SETUP_STEPS — a name there that no longer exists in
#     its job is an error (exit 2), so a renamed step cannot drop out unseen.
# `${{ … }}` expressions are answered as on a pull request (EXPRESSIONS and
# CONDITIONS below); any other expression is an error (exit 2), never a guess.
#
# Tiers:
#   --fast (default)  the lint, verify-helpers and doc-validators jobs
#   --full            --fast, then `bash tests/run_all_tests.sh` and the two
#                     phase0 gates (golden classification fingerprint,
#                     labelled-pcap precision/recall) — the pre-push tier
#
# Where the steps run: by default in a container built FROM the lint job's
# digest-pinned image (jobs.lint.container.image), holding shellcheck from
# its apt, cppcheck built by tools/ci/install-cppcheck.sh (the release the
# findings ratchet was measured with), the SDK build dependencies
# (tools/ci/install-build-deps.sh), PyYAML, jq, ccache, and Ruby with the
# gems of docs/Gemfile.lock. The image is built on first use and tagged with
# a digest of its inputs, so later runs reuse it and a changed input
# rebuilds it. The checkout is bind-mounted at its own path and the steps run
# as your user, so what they write is yours. docker or podman is required
# (MMT_CONTAINER_RUNTIME names one); without either the script exits 2.
# --host runs the steps on this machine instead, which then needs that
# toolchain itself (and python3 with PyYAML to read the workflow).
# Known difference: Ubuntu 24.04's Ruby is 3.2; CI's verify-helpers job sets
# up Ruby 3.4 for the docs-site build.
#
# The steps write what they write in CI: docs/_site, .cppcheck-build/ (the
# lint job's per-file cppcheck results, reused by the next run),
# cppcheck-report.xml, and an SDK build — docs_onboarding (verify-helpers)
# and the --full suites run `make -C sdk clean` first, like every
# SDK-building suite. In the container, Jekyll's docs/.jekyll-cache is a
# fresh tmpfs, as on a CI checkout.
#
# Usage: bash tools/ci/local-gates.sh [--fast|--full] [--host] [--list] [--keep-going]
#   --list        print the steps the tier runs (`<job> :: <step>`) and exit
#   --keep-going  run every step and list all failures (default: stop at the
#                 first failing step)
# Environment:
#   MMT_CONTAINER_RUNTIME  docker or podman (default: the first one found)
#   MMT_CCACHE, CCACHE_DIR passed to the --full suites in the container,
#                          with the cache directory mounted (opt-in compiler
#                          cache, docs/AGENT_ENVIRONMENT.md §2)
# Exit: 0 = every gate passed, 1 = a gate failed, 2 = helper broken or a
#       prerequisite missing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="${MMT_GATES_WORKFLOW:-$ROOT/.github/workflows/c-cpp.yml}"
SELF="tools/ci/local-gates.sh"

usage() {
    sed -n '/^# Usage:/,/^# Exit:/p' "$ROOT/$SELF" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

TIER=fast HOST=0 LIST=0 KEEP_GOING=0 IN_CONTAINER=0
for arg in "$@"; do
    case "$arg" in
        --fast) TIER=fast ;;
        --full) TIER=full ;;
        --host) HOST=1 ;;
        --list) LIST=1 ;;
        --keep-going) KEEP_GOING=1 ;;
        --in-container) HOST=1; IN_CONTAINER=1 ;;
        -h|--help) usage ;;
        *) echo "✗ unknown argument: $arg" >&2; usage ;;
    esac
done

[ -f "$WORKFLOW" ] || { echo "✗ workflow not found: $WORKFLOW" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

# --- container mode: build the gates image, re-run this script inside ------
if [ "$HOST" -eq 0 ]; then
    runtime="${MMT_CONTAINER_RUNTIME:-}"
    if [ -z "$runtime" ]; then
        for c in docker podman; do
            if command -v "$c" >/dev/null 2>&1; then runtime="$c"; break; fi
        done
    fi
    if [ -z "$runtime" ] || ! command -v "$runtime" >/dev/null 2>&1; then
        echo "✗ no container runtime: install docker or podman (or set MMT_CONTAINER_RUNTIME)," >&2
        echo "  or run the gates on this machine with --host" >&2
        exit 2
    fi
    # The lint job's image — one source, read without PyYAML (none on the host
    # is needed): the first `image:` line inside the `lint:` job.
    image="$(python3 - "$WORKFLOW" <<'PYEOF'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"^  lint:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M | re.S)
img = m and re.search(r"^\s+image:\s*\"?([^\"\s#]+)", m.group(1), re.M)
print(img.group(1) if img else "")
PYEOF
)"
    case "$image" in
        *@sha256:*) ;;
        *) echo "✗ the lint job's container image is not digest-pinned: '${image}'" >&2; exit 2 ;;
    esac
    ctx="$(mktemp -d)"
    cp "$ROOT/tools/ci/install-build-deps.sh" "$ROOT/tools/ci/install-cppcheck.sh" \
       "$ROOT/docs/Gemfile" "$ROOT/docs/Gemfile.lock" "$ctx/"
    cat > "$ctx/Dockerfile" <<EOF
FROM ${image}
RUN echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
COPY install-build-deps.sh install-cppcheck.sh /opt/mmt-gates/
RUN bash /opt/mmt-gates/install-build-deps.sh ubuntu-24.04 deb \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \\
      curl gawk shellcheck python3-yaml jq pkg-config ccache ruby ruby-dev zlib1g-dev libssl-dev libyaml-dev libffi-dev \\
 && rm -rf /var/lib/apt/lists/*
RUN bash /opt/mmt-gates/install-cppcheck.sh
COPY Gemfile Gemfile.lock /opt/mmt-gates/docs/
ENV BUNDLE_PATH=/opt/mmt-gates/bundle
RUN cd /opt/mmt-gates/docs \\
 && gem install --no-document bundler -v "\$(sed -n '/^BUNDLED WITH/{n;s/ //gp}' Gemfile.lock)" \\
 && BUNDLE_FROZEN=true bundle install \\
 && chmod -R a+rX /opt/mmt-gates
# The hosted runners' locale: Ruby reads the docs-site scripts as UTF-8.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
EOF
    tag="mmt-dpi-local-gates:$(cat "$ctx"/* | sha256sum | cut -c1-16)"
    if ! "$runtime" image inspect "$tag" >/dev/null 2>&1; then
        echo "● building the gates image $tag (once per change of its inputs) ..."
        "$runtime" build -t "$tag" "$ctx" || { rm -rf -- "$ctx"; echo "✗ gates image build failed" >&2; exit 2; }
    fi
    rm -rf -- "$ctx"
    run_args=(run --rm --init -w "$ROOT" -v "$ROOT:$ROOT" -e HOME=/tmp/local-gates-home)
    # A linked worktree's git directory lives outside the checkout.
    # (Outside a git checkout there is nothing to add; the git-reading
    # gates then fail as they would in CI.)
    common=""
    if gitdir="$(cd "$ROOT" && git rev-parse --git-common-dir 2>/dev/null)"; then
        common="$(cd "$ROOT" && cd "$gitdir" && pwd)"
    fi
    case "$common/" in "/"|"$ROOT"/*) ;; *) run_args+=(-v "$common:$common") ;; esac
    if [ "$(basename "$runtime")" = podman ]; then
        run_args+=(--userns=keep-id)
    else
        run_args+=(-u "$(id -u):$(id -g)")
    fi
    if [ -n "${MMT_CCACHE:-}" ]; then
        cache="${CCACHE_DIR:-$HOME/.cache/ccache}"
        mkdir -p "$cache"
        run_args+=(-e "MMT_CCACHE=$MMT_CCACHE" -e "CCACHE_DIR=$cache" -v "$cache:$cache")
    fi
    # Jekyll's cache starts empty, as on a fresh CI checkout, and a cache the
    # host left behind (another user's files included) is neither read nor
    # written.
    # The mountpoint is created here, as the caller: the runtime would
    # otherwise create a missing one as root inside the checkout.
    mkdir -p "$ROOT/docs/.jekyll-cache"
    run_args+=(--tmpfs "$ROOT/docs/.jekyll-cache:mode=1777")
    [ -t 1 ] && run_args+=(-t)
    inner=(--in-container "--$TIER")
    [ "$LIST" -eq 1 ] && inner+=(--list)
    [ "$KEEP_GOING" -eq 1 ] && inner+=(--keep-going)
    exec "$runtime" "${run_args[@]}" "$tag" bash "$ROOT/$SELF" "${inner[@]}"
fi

if [ "$IN_CONTAINER" -eq 1 ]; then
    mkdir -p "$HOME"
fi

# --- read the steps from the workflow ---------------------------------------
python3 -c 'import yaml' 2>/dev/null || {
    echo "✗ python3 PyYAML is required to read $WORKFLOW (apt: python3-yaml)" >&2
    exit 2
}
STEPS_DIR="$(mktemp -d)"
trap 'rm -rf -- "$STEPS_DIR"' EXIT
python3 - "$WORKFLOW" "$TIER" "$STEPS_DIR" <<'PYEOF' || exit 2
import os, re, shlex, sys
import yaml

workflow, tier, out = sys.argv[1:4]
JOBS = ["lint", "verify-helpers", "doc-validators"]
# Runner set-up the gates image already provides.
SETUP_STEPS = {
    "lint": [
        "Install git, shellcheck and the cppcheck build prerequisites",
        "Mark the checkout as a safe git directory",
        "Build the pinned cppcheck release from source",
    ],
}
# `${{ … }}` values, answered as on a pull request into main.
EXPRESSIONS = {
    "github.event_name == 'pull_request' && 'pr' || 'full'": "pr",
}
# Step `if:` conditions, answered as on a pull request that changes code.
CONDITIONS = {
    "needs.changes.outputs.code == 'false'": False,
}
EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def die(msg):
    print(f"✗ {msg}", file=sys.stderr)
    sys.exit(2)


def norm(expr):
    return " ".join(expr.split())


def resolve(value, where):
    def sub(m):
        key = norm(m.group(1))
        if key not in EXPRESSIONS:
            die(f"{where}: unknown expression ${{{{ {key} }}}} — teach "
                "tools/ci/local-gates.sh (EXPRESSIONS) its pull-request value")
        return EXPRESSIONS[key]
    return EXPR.sub(sub, str(value))


def condition(cond, where):
    key = norm(EXPR.sub(lambda m: m.group(1), str(cond)))
    if key not in CONDITIONS:
        die(f"{where}: unknown step condition `if: {cond}` — teach "
            "tools/ci/local-gates.sh (CONDITIONS) its pull-request value")
    return CONDITIONS[key]


with open(workflow, encoding="utf-8") as fh:
    jobs = (yaml.safe_load(fh) or {}).get("jobs") or {}

steps = []
for job in JOBS:
    spec = jobs.get(job)
    if not isinstance(spec, dict):
        die(f"job {job} not found in {workflow}")
    job_env = {k: resolve(v, f"{job} env {k}") for k, v in (spec.get("env") or {}).items()}
    names = [s.get("name") for s in spec.get("steps") or []]
    for stale in SETUP_STEPS.get(job, []):
        if stale not in names:
            die(f"{job}: set-up step '{stale}' (SETUP_STEPS) is not in the job "
                "any more — update tools/ci/local-gates.sh")
    for i, st in enumerate(spec.get("steps") or [], 1):
        name = (st.get("name") or st.get("uses")
                or (str(st.get("run") or "").strip().splitlines() or ["?"])[0])
        where = f"{job} step {i} ({name})"
        if "uses" in st or name in SETUP_STEPS.get(job, []):
            continue
        if "run" not in st:
            die(f"{where}: neither `uses:` nor `run:`")
        if "if" in st and not condition(st["if"], where):
            continue
        if st.get("shell") not in (None, "bash"):
            die(f"{where}: shell {st.get('shell')!r} is not supported")
        env = dict(job_env)
        env.update({k: resolve(v, f"{where} env {k}") for k, v in (st.get("env") or {}).items()})
        steps.append((job, name, env, resolve(st["run"], where)))

if tier == "full":
    for name, cmd in (
        ("unit-test suites", "bash tests/run_all_tests.sh"),
        ("golden classification fingerprint", "bash tools/phase0/ci/check_classification.sh"),
        ("labelled-pcap precision/recall", "bash tools/phase0/ci/check_precision.sh"),
    ):
        steps.append(("pre-push", name, {}, cmd + "\n"))

with open(os.path.join(out, "steps.tsv"), "w", encoding="utf-8") as idx:
    for n, (job, name, env, run) in enumerate(steps, 1):
        path = os.path.join(out, f"{n:03d}.sh")
        with open(path, "w", encoding="utf-8") as fh:
            for k, v in env.items():
                fh.write(f"export {k}={shlex.quote(str(v))}\n")
            fh.write(run if run.endswith("\n") else run + "\n")
        idx.write(f"{job}\t{name.replace(chr(9), ' ')}\t{path}\n")
PYEOF

if [ "$LIST" -eq 1 ]; then
    while IFS=$'\t' read -r job name _; do
        printf '%s :: %s\n' "$job" "$name"
    done < "$STEPS_DIR/steps.tsv"
    exit 0
fi

# --- run them -----------------------------------------------------------------
cd "$ROOT"
export GITHUB_WORKSPACE="$ROOT"
failed=()
results=()
while IFS=$'\t' read -r job name script; do
    echo ""
    echo "▶ ${job} :: ${name}"
    start=$SECONDS
    set +e
    # As a GitHub `run:` step: bash -e -o pipefail, no profile.
    bash --noprofile --norc -eo pipefail "$script" </dev/null
    rc=$?
    set -e
    secs=$((SECONDS - start))
    if [ "$rc" -eq 0 ]; then
        results+=("  ✓ ${job} :: ${name} (${secs}s)")
    else
        results+=("  ✗ ${job} :: ${name} (exit ${rc}, ${secs}s)")
        failed+=("${job} :: ${name}")
        [ "$KEEP_GOING" -eq 1 ] || break
    fi
done < "$STEPS_DIR/steps.tsv"

echo ""
echo "local gates (${TIER}):"
printf '%s\n' "${results[@]}"
if [ "${#failed[@]}" -gt 0 ]; then
    echo "✗ ${#failed[@]} gate step(s) failed" >&2
    exit 1
fi
echo "✓ every ${TIER} gate passed"
