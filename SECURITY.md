# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest (`main`) | :white_check_mark: |
| latest release tag | :white_check_mark: |
| older releases | :x: — please upgrade and re-test |

## Reporting a Vulnerability

We take security vulnerabilities seriously. Please use **private** disclosure so we can fix the issue before it is publicly known.

### Preferred: GitHub private vulnerability reporting

1. Go to the **Security** tab of this repository → **Report a vulnerability**  
   Direct link: <https://github.com/montimage-projects/mmt-dpi/security/advisories/new>
2. Fill in the advisory form (description, impact, reproduction steps). Only repository maintainers can see the draft advisory.
3. We will triage the draft and respond within 48 hours.

This is the preferred channel because it auto-creates a draft GitHub Security Advisory and lets us collaborate on a fix and CVE request in one place.

### Alternative: Email

If you cannot use GitHub advisories, email [contact@montimage.eu](mailto:contact@montimage.eu) with subject `Security report — mmt-dpi`.

**Do NOT** open a public GitHub issue for security vulnerabilities.

### What to Include

- Type of vulnerability (e.g., buffer overflow, information disclosure) and severity estimate
- Full paths of affected source files and the location of the affected code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact of the issue
- Whether the issue has already been disclosed elsewhere

### What to Expect

- Acknowledgment of your report within **48 hours**
- Regular updates on our progress (at least every 7 days until resolved)
- A coordinated disclosure timeline — we aim to ship a fix within **90 days** and will agree on a public disclosure date with you
- Credit in the security advisory (if desired)
- A CVE will be requested via the GitHub advisory workflow when appropriate

### Disclosure Policy

- Please give us reasonable time to investigate and ship a fix before any public disclosure.
- We will notify you when the issue is fixed and when the advisory/CVE is published.
- We follow coordinated disclosure; we will not take legal action against researchers who follow this policy and act in good faith.

## Scope

In scope: the MMT-DPI library and its first-party SDK/plugins shipped in this repository (`src/`, `sdk/`, `rules/`, `src/mmt_security/`) and the packaging/installer scripts (`install.sh`, `mmt-dpi.spec`, `debian/`, `tools/ci/build-package.sh`). Out of scope: third-party dependencies and external infrastructure — please report those to the upstream project.

## Security Best Practices for Contributors

- Never commit secrets, API keys, or credentials — this repository is scanned by [Gitleaks](https://github.com/gitleaks/gitleaks) in CI (`.github/workflows/c-cpp.yml:secret-scan`) and via the local pre-commit hook (`.pre-commit-config.yaml:gitleaks`).
- Use environment variables for sensitive configuration
- Follow secure coding practices (see `docs/DEVELOPMENT.md` and `docs/AGENT_ENVIRONMENT.md` §5–§7 for sanitizer profiles)
- If you suspect a secret was committed, notify maintainers privately (same channels as above) and rotate the credential immediately

## Automated Secret Scanning

- **CI:** every push and pull request runs the `secret-scan` job in `.github/workflows/c-cpp.yml`. It scans the full git history with `gitleaks/gitleaks-action` (v3.0.0, pinned by commit SHA); where that action cannot run — it needs a `GITLEAKS_LICENSE` secret on organization accounts — `tools/ci/run-gitleaks.sh` runs the pinned gitleaks **v8.30.1** binary, verified by SHA-256 before use, and `tools/ci/assert-gitleaks-ran.sh` fails the job if neither scanner ran. Any finding fails the workflow.
- **Detection rules:** `.gitleaks.toml` extends gitleaks' built-in default ruleset (`[extend] useDefault = true`) and adds only `[[allowlists]]` for non-secret fixtures. `tools/ci/check-gitleaks-allowlist.sh` fails the job if the rules are dropped or an allowlist entry stops matching a tracked file, and `tools/ci/tests/test-gitleaks-canary.sh` plants a synthetic AWS key in a throwaway repository and asserts `tools/ci/run-gitleaks.sh` exits non-zero.
- **Local:** `bash tools/ci/run-gitleaks.sh` runs the CI scan on your checkout; `pre-commit run --all-files` runs the `gitleaks git --staged` hook (gitleaks v8.30.1, `.pre-commit-config.yaml`) with the same `.gitleaks.toml`. Install hooks with `pre-commit install`.
- False positives are suppressed by fingerprint (`<commit>:<path>:<rule>:<line>`) in `.gitleaksignore` at the repository root, one per line with a comment explaining why — only after triage confirms the finding is not a secret.

## Past Advisories

Published advisories and CVEs for this repository are listed under <https://github.com/montimage-projects/mmt-dpi/security/advisories>.
