# Contributing to MMT-DPI

Thank you for your interest in contributing to MMT-DPI! This guide will help you get started.

## How to Contribute

1. **Fork** the repository
2. **Create a feature branch** from `main` (`git checkout -b feat/your-feature`)
3. **Make your changes** and test them
4. **Commit** using [Conventional Commits](#commit-conventions)
5. **Open a Pull Request** against `main`

## Development Setup

### Prerequisites

Linux only, with GCC and GNU Make. The reference toolchain, the package list
and the `apt-get` line are maintained in one place:
[Agent Environment Notes §1 Toolchain Requirements](docs/AGENT_ENVIRONMENT.md#1-toolchain-requirements).

### Build from Source

```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi

# Build
cd sdk
make -j$(nproc)

# Install locally
sudo make install

# Run tests (no install needed — suites compile standalone against src/)
bash ../tests/run_all_tests.sh
```

### Verify Your Changes

After building, test with the included examples:

```bash
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./extract_all -t /path/to/capture.pcap
```

## Branching Strategy

- `main` - Stable release branch (protected)
- `dev` - Development integration branch
- `feat/*` - Feature branches
- `hotfix/*` - Hotfix branches

Always branch from `main` for new features and bug fixes.

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <description>

[optional body]
```

**Types:**
- `feat` - New feature or protocol support
- `fix` - Bug fix
- `docs` - Documentation changes
- `refactor` - Code restructuring without behavior change
- `test` - Adding or updating tests
- `build` - Build system or dependency changes
- `perf` - Performance improvements

**Examples:**
```
feat: Add QUIC IETF RFC 9000 classification
fix: Resolve memory leak in FTP protocol handler
docs: Update compilation instructions for ARM
```

## Pull Request Process

1. Ensure your code compiles without warnings on Linux (`make -C sdk`)
2. Run the test suite: `bash tests/run_all_tests.sh` (expected result: [Agent Environment Notes §3 Testing](docs/AGENT_ENVIRONMENT.md#3-testing))
3. Update documentation if you changed APIs or added protocols
4. Fill out the PR template completely
5. Request review from at least one maintainer

PRs require **1 approving review** from a code owner before merging — the
intended setting recorded in [`.github/CODEOWNERS`](.github/CODEOWNERS); see
below for how it is applied and checked.

### Required checks and review

Branch protection on `main` requires the status-check contexts listed in
[`.github/required-checks.txt`](.github/required-checks.txt) — the reviewed
record of the gates a PR must pass, spelled exactly as the check runs report.
The `verify-helpers` job runs `tools/ci/check-required-checks.sh`, which fails
when a listed context names no workflow job, or names a job that never reports
on a pull request into `main` (a path-filtered workflow, a tag- or
schedule-only job) — such a context would leave every PR waiting forever.
Path-filtered work reports through an always-running aggregate instead:
`packages-gate` in `release-packages.yml` passes when a PR touches no
packaging path and otherwise requires every package leg.

A docs-only PR — every changed file under `docs/` or a Markdown file at the
repository root — skips the C jobs of `c-cpp.yml` and `phase0-baseline.yml`
(issue #552). The `changes` job classifies the diff with
`tools/ci/classify-changes.sh`; a job skipped by its `if:` reports success, and
the matrix jobs run with their steps skipped so each leg still reports its own
context. The docs jobs (`doc-validators`, which then also runs the
`docs_lifecycle` suite, `verify-helpers`, `version-agreement`, `pre-commit`,
`secret-scan`, `site-onboarding` and `build`) always run.

Renaming a job whose check is required: update `.github/required-checks.txt`
in the same PR, and swap the context in branch protection when that PR merges.

`main` merges through a merge queue once a maintainer applies the ruleset
below (issue #657, recorded in [`docs/DECISIONS.md`](docs/DECISIONS.md)). A PR
then does not have to be up to date with `main`: "Merge when ready" adds it to
the queue, which tests the merge result once, on a `merge_group` run, before
it lands. The `changes` jobs skip nothing on that run, so the queue runs the
full check set. Every workflow that reports a required context therefore also
triggers on `merge_group`, and `check-required-checks.sh` fails a context that
a merge-queue run would not report: no `merge_group` trigger, or a job-level
`if:` that keeps the job off it.

The file does not change protection by itself. A maintainer with admin access
applies it (after the PR that changed it has merged, so every context exists):

```bash
# Required status checks: exactly the committed list, from GitHub Actions. Not
# strict (up to date before merging): the merge queue tests each merge result.
jq -Rn '{strict: false, checks: [inputs | select(test("^\\s*(#|$)") | not)
        | {context: ., app_id: 15368}]}' .github/required-checks.txt \
  | gh api -X PATCH repos/montimage-projects/mmt-dpi/branches/main/protection/required_status_checks --input -
# Merge queue on main: a repository ruleset (classic protection has no merge
# queue setting). Squash is the only merge method the repository allows; the
# 120-minute response timeout clears the longest required job chain (80 min).
gh api -X POST repos/montimage-projects/mmt-dpi/rulesets --input - <<'JSON'
{"name": "main merge queue", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
 "rules": [{"type": "merge_queue", "parameters": {
   "merge_method": "SQUASH", "grouping_strategy": "ALLGREEN",
   "max_entries_to_build": 5, "min_entries_to_merge": 1,
   "max_entries_to_merge": 5, "min_entries_to_merge_wait_minutes": 5,
   "check_response_timeout_minutes": 120}}]}
JSON
# Check: the merge queue applies to main (read-only; prints merge_queue).
gh api repos/montimage-projects/mmt-dpi/rules/branches/main --jq '.[].type'
# Reviews: 1 approving code-owner review, stale approvals dismissed.
gh api -X PATCH repos/montimage-projects/mmt-dpi/branches/main/protection/required_pull_request_reviews \
  -F required_approving_review_count=1 -F require_code_owner_reviews=true -F dismiss_stale_reviews=true
# Check: live protection against the committed list (read-only).
bash tools/ci/check-required-checks.sh --live montimage-projects/mmt-dpi
```

A deliberate relaxation of the review setting is recorded by editing the
"Intended setting" lines of `.github/CODEOWNERS` and this section in the same
change.

## Coding Standards

- Follow the existing C code style in the project
- Use 4-space indentation (no tabs)
- Keep functions focused and reasonably sized
- Add comments for non-obvious logic
- Use the existing macro and type conventions (`uint32_t`, `mmt_handler_t`, etc.)
- Avoid compiler-specific extensions when possible

## Adding a New Protocol

See the [Add New Protocol](docs/Add-New-Protocol.md) guide for detailed instructions on implementing protocol classification and attribute extraction.

## Testing

- Test your changes against pcap files with relevant traffic
- Verify with Valgrind for memory leaks: `valgrind --leak-check=full ./your_test`
- Ensure no regressions in existing protocol classification

## Security and Secret Scanning

- **Never commit secrets** (API keys, tokens, private keys, credentials). CI runs [Gitleaks](https://github.com/gitleaks/gitleaks) on every push/PR (`.github/workflows/c-cpp.yml:secret-scan` with config `.gitleaks.toml`, which extends gitleaks' default ruleset); run the same full-history scan locally with `bash tools/ci/run-gitleaks.sh` (pinned v8.30.1). The staged-changes check runs via `pre-commit` (`.pre-commit-config.yaml:gitleaks` → `gitleaks git --staged`). Install hooks with `pre-commit install` and run `pre-commit run --all-files` before pushing.
- If you suspect a secret was committed, follow [SECURITY.md](SECURITY.md) and notify maintainers **privately** (GitHub Security Advisory or `contact@montimage.eu`) — do not open a public issue — and rotate the credential immediately.

## Reporting Issues

- Use the [Bug Report](https://github.com/montimage-projects/mmt-dpi/issues/new?template=bug_report.md) template for bugs
- Use the [Feature Request](https://github.com/montimage-projects/mmt-dpi/issues/new?template=feature_request.md) template for enhancements
- Include pcap samples (if possible) when reporting classification issues
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) — use **private** disclosure (Security → Report a vulnerability or `contact@montimage.eu`), never a public issue

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
