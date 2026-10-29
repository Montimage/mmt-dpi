---
layout: default
title: "Things need to be done before releasing a new stable version"
---

# Things need to be done before releasing a new stable version

## Update the new version number

`VERSION` in `rules/common.mk` is the single version source: the build passes
it to every object (`-DVERSION`) and names the libraries after it
(`sdk/lib/libmmt_core.so.<VERSION>`). `bash scripts/validate-release-prep.sh`
compares every site below with it and fails on any disagreement; it runs on
every pull request (the `version-agreement` job in
`.github/workflows/c-cpp.yml`) and again in the release workflow's
`verify-tag` job, which also requires the pushed tag to equal `v<VERSION>`
and its commit to be on `main` — an ancestor of `origin/main`
(`tools/ci/check-release-tag.sh`).

**The release workflow is the only publisher.** Never create a GitHub
Release by hand (`gh release create`, the web UI's *Draft a new release*,
an upload of assets): pushing the tag is the whole publication step. Once
every gate passes, the `release` job of
`.github/workflows/release-packages.yml` creates the Release with
`tools/ci/publish-release.sh` — as a draft carrying every package, SBOM and
`SHA256SUMS` (each covered by the build-provenance attestation), then
published — and it **refuses to
run when a Release for the tag already exists**. When any job of a tag run
fails, the `release-alert` job opens (or comments on) an issue titled
`Release workflow failed for vx.y.z`; nothing is published, so fix the
cause and re-run the workflow, or delete the tag and push it again. Do not
publish around a failed run.

**Declared version** — bump these together, at the start of the release
cycle, to the version being prepared; each must equal `VERSION` exactly:

| Site | What the check reads |
|------|----------------------|
| `rules/common.mk` | `VERSION := x.y.z` (the source) |
| `src/mmt_core/public_include/mmt_core.h` | `#define VERSION "x.y.z"` (fallback for consumers that do not pass `-DVERSION`) |
| `mmt-dpi.spec` | `Version: x.y.z` (with a matching top `%changelog` entry `- x.y.z-1`) |
| `CHANGELOG.md` | the topmost `Version x.y.z (...)` heading — `(unreleased)` until the tag, then the release date |
| `debian/changelog` | the first entry's upstream version — checked only when the file exists |

**Published release** — the one-command installer pins the latest
*published* tag, so these lag `VERSION` between the bump and the tag (a
tagged commit cannot pin its own commit SHA). They must all name the same
tag as `install.sh`, and that tag must be at or below `v<VERSION>` and have a
dated `CHANGELOG.md` entry:

| Site | What the check reads |
|------|----------------------|
| `install.sh` | `RELEASE_TAG="vx.y.z"` (with `RELEASE_TAG_SHA`, the peeled commit the tag resolves to — `tools/ci/check-release-tag.sh` fails when it is not) |
| `README.md` | `Current release: [vx.y.z]` and `` pinned release tag (`vx.y.z`) `` |
| `docs/_includes/quick-start.md` | `` pinned release tag (`vx.y.z`) `` |
| `docs/index.html` | the hero eyebrow `vx.y.z · Apache-2.0 · …` |
| `.github/workflows/c-cpp.yml` | `ABI_BASELINE: vx.y.z` of the `abi-diff` job (issue #536) |
| `tools/ci/abi-diff.sh` | `baseline_ref=vx.y.z`, the script's default baseline |

**ABI and SOVERSION** (issue #536) — every shared library carries the
SONAME `lib<name>.so.<SOVERSION>` (`SOVERSION` at the end of
`rules/common.mk`), independent of `VERSION`. Bump `SOVERSION` in the pull
request that makes an incompatible change to an installed library (a public
struct layout, a removed or re-typed export), and record the break in the
`CHANGELOG.md` section of the next version: the required `abi-diff` job
compares the libraries with the `ABI_BASELINE` tag and fails on an
incompatible change whose SONAME did not move. A compatible change (an
added export) keeps `SOVERSION`.

Release order:

1. Bump the declared-version sites and open the new
   `Version x.y.z (unreleased)` section in `CHANGELOG.md`.
2. When cutting the release, replace `(unreleased)` with the release date
   in a pull request, merge it, then tag that merged commit **on `main`**
   `vx.y.z` (never a release branch: a tag that is not an ancestor of
   `origin/main` fails `verify-tag`) and push the tag. The workflow
   publishes the Release.
3. After the tag is published, update the published-release sites in one
   follow-up PR: run `bash tools/ci/check-release-tag.sh --write-pin vx.y.z`,
   which writes `RELEASE_TAG` and `RELEASE_TAG_SHA` from the peeled tag
   (`git rev-parse vx.y.z^{commit}`, never the annotated tag object), then
   update the README/site mentions and the ABI baseline (`ABI_BASELINE` of
   the `abi-diff` job and `tools/ci/abi-diff.sh`'s `baseline_ref`; the job
   downloads that tag's ubuntu-24.04 `.deb`) — `version-agreement` fails
   until all of them name the same tag.
4. Once that follow-up PR is merged, the published one-liner installs the
   new tag: run the **Install smoke** workflow
   (`.github/workflows/install-smoke.yml`, *Run workflow*, `source:
   published`) and check that every `supported` leg passed. The workflow
   also runs by itself after the tag run and weekly, but the run after the
   tag still exercises the previous pin until step 3 lands. A failing
   supported leg on a scheduled or post-release run opens (or comments on)
   an issue titled `Install smoke matrix failing`.

### Cutting v1.9.1 (issue #493)

`VERSION` is already `1.9.1` and `CHANGELOG.md` opens with
`Version 1.9.1 (unreleased)` (#483, #592), while `install.sh` still pins
`v1.9.0`. Neither the date nor the repin can land before the tag exists:
`--write-pin` needs the tag's peeled commit. In order:

1. **Date the changelog.** A PR replacing `(unreleased)` with the release
   date in `CHANGELOG.md`; merge it once `version-agreement` is green.
2. **Tag that merged commit on `main`:**
   `git fetch origin main && git tag -a v1.9.1 -m "MMT-DPI 1.9.1" origin/main`,
   then `git merge-base --is-ancestor v1.9.1 origin/main && echo "on main"`.
3. **Push the tag:** `git push origin v1.9.1`. This starts
   `release-packages.yml`; do not create the Release by hand.
4. **Check the tag run:** `verify-tag`, `release-gates` and
   `Publish GitHub Release` all succeeded (none skipped);
   `gh release view v1.9.1 --json assets --jq '.assets | length'` is at
   least 12 (10 packages, `SHA256SUMS`, the SBOM); and
   `gh attestation verify mmt-dpi_*_ubuntu-24.04_x86_64.deb --repo montimage-projects/mmt-dpi`
   passes on a downloaded `.deb`. The verified bootstrap set (issue #498) is
   there too: `install.sh`, `manifest.json`, `mmt-dpi.intoto.jsonl` and one
   `mmt-dpi[-security]_<distro>_<amd64|arm64>.<deb|rpm>` alias per package,
   and the `Bootstrap smoke` workflow run that follows the tag run is green.
5. **Repin the installer** in a follow-up PR:
   `bash tools/ci/check-release-tag.sh --write-pin v1.9.1`, then update
   `Current release: [v1.9.1]` and `` pinned release tag (`v1.9.1`) `` in
   `README.md` / `docs/_includes/quick-start.md` (then
   `bash tools/ci/check-doc-includes.sh --write`) and the hero eyebrow in
   `docs/index.html`; `bash scripts/validate-release-prep.sh` must pass.
6. **Run the smoke matrix** against the published one-liner once that PR is
   merged (step 4 of *Release order* above).

## Verify the classification

<!-- FLAG: unverified — `mmt-test/wall_e` and `mmt-test/data-sets/` directories
     do not exist in this repository. The classification verification step
     referenced external tooling that is not present in the repo. -->

## Check the memory leak

Run the `extract_all` example under Valgrind on sample pcaps:

```bash
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
valgrind --leak-check=full --show-reachable=yes ./extract_all -t src/examples/google-fr.pcap
```

A sample pcap (`src/examples/google-fr.pcap`) is included for smoke testing.

## Clean code

- Remove all log messages

- Update command for function/variable/ ...

- Remove unused source code/ files/ ...

## Set a tag for the new version

Tag the release commit on `main`, then push the tag — that push starts
the release workflow, which creates and publishes the GitHub Release
(see *The release workflow is the only publisher* above):

```
git fetch origin main
git tag -a v1.4 -m "my version 1.4" origin/main
git merge-base --is-ancestor v1.4 origin/main && echo "on main"
```

Sharing tag:

```
git push origin v1.4
```

Checkout a tag:

```
git checkout -b new_branch_name v1.5
```

## Update the documents

- Update `ChangeLog` (`CHANGELOG.md` is the single canonical changelog — the
  hand-maintained `changelog.html` duplicate was removed in #232)

- Update `wiki`

---

Created by @luongnv89 on 12 July 2016