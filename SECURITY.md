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

This is the preferred channel because it keeps the report encrypted at rest, auto-creates a draft GitHub Security Advisory, and lets us collaborate on a fix and CVE request in one place.

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

In scope: the MMT-DPI library and its first-party SDK/plugins shipped in this repository (`src/`, `sdk/`, `rules/`, `src/mmt_security/`) and the packaging/installer scripts (`install.sh`, `dist/ZIP/`, `tools/ci/build-package.sh`). Out of scope: third-party dependencies and external infrastructure — please report those to the upstream project.

## Security Best Practices for Contributors

- Never commit secrets, API keys, or credentials — this repository is scanned by [Gitleaks](https://github.com/gitleaks/gitleaks) in CI (`.github/workflows/c-cpp.yml:secret-scan`) and via the local pre-commit hook (`.pre-commit-config.yaml:gitleaks`).
- Use environment variables for sensitive configuration
- Follow secure coding practices (see `docs/DEVELOPMENT.md` and `docs/AGENT_ENVIRONMENT.md` §5–§7 for sanitizer profiles)
- If you suspect a secret was committed, notify maintainers privately (same channels as above) and rotate the credential immediately

## Automated Secret Scanning

- **CI:** every push and pull request runs `gitleaks detect --no-banner --redact --verbose` via `gitleaks/gitleaks-action@v2` (see `c-cpp.yml:secret-scan`). The job fails the workflow if a new secret is detected.
- **Local:** `pre-commit run --all-files` runs the same `gitleaks protect --staged --redact --verbose` check before commit. Install hooks with `pre-commit install`.
- False positives can be allowlisted in `.gitleaksignore` at the repository root (one fingerprint per line — add a comment explaining why).

## Past Advisories

Published advisories and CVEs for this repository are listed under <https://github.com/montimage-projects/mmt-dpi/security/advisories>.
