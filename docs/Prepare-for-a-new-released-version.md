---
layout: default
title: "Preparing a New Release"
---

# Preparing a New Release

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
run when a Release a person made for the tag already exists**, deleting
nothing. Re-running a tag run after the workflow published exits 0 ("already
published") when the Release holds every asset, so it raises no alert
(issue #595). When any job of a tag run
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
   publishes the Release. Tag the merged commit by its SHA
   (`sha=$(gh pr view <N> --json mergeCommit --jq .mergeCommit.oid)`, then
   `git tag -a vx.y.z -m "MMT-DPI x.y.z" "$sha"`), not the `main` tip, which
   may have moved since. Then check that the Release holds **exactly** the
   expected assets: for each package in its `manifest.json`, the alias
   (`file`), the package (`source`) and its `.sbom.json`; plus `install.sh`,
   `manifest.json`, `SHA256SUMS`, `mmt-dpi.intoto.jsonl` and the source
   tarball (and its `.asc` once the signing key is provisioned). There are two
   packages (`mmt-dpi`, `mmt-dpi-security`) per leg of the `package` matrix of
   `release-packages.yml`. v1.10.0 had 18 legs, 36 packages and 113 assets,
   so a count floor would pass a Release missing most of its SBOMs:

   ```bash
   t=vx.y.z; d=$(mktemp -d)
   gh release download "$t" --repo Montimage/mmt-dpi -p manifest.json -D "$d"
   diff <(gh release view "$t" --repo Montimage/mmt-dpi --json assets --jq '.assets[].name' | LC_ALL=C sort) \
        <({ jq -r '.packages[] | .file, .source, .source + ".sbom.json"' "$d/manifest.json"
            printf '%s\n' install.sh manifest.json SHA256SUMS mmt-dpi.intoto.jsonl "mmt-dpi-${t#v}.tar.gz"; } | LC_ALL=C sort) \
     && echo "asset set complete: $(jq '.packages | length' "$d/manifest.json") packages"
   ```
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
2. **Tag that merged commit on `main`** by its SHA, not the `main` tip:
   `sha=$(gh pr view <N> --json mergeCommit --jq .mergeCommit.oid)` for the
   step-1 PR, `git fetch origin main && git tag -a v1.9.1 -m "MMT-DPI 1.9.1" "$sha"`,
   then `git merge-base --is-ancestor v1.9.1 origin/main && echo "on main"`.
3. **Push the tag:** `git push origin v1.9.1`. This starts
   `release-packages.yml`; do not create the Release by hand.
4. **Check the tag run:** `verify-tag`, `release-gates` and
   `Publish GitHub Release` all succeeded (none skipped);
   the Release holds exactly the expected assets (the check in step 2 of
   *Release order* above, with `t=v1.9.1`); and
   `gh attestation verify mmt-dpi_*_ubuntu-24.04_x86_64.deb --repo Montimage/mmt-dpi`
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

### Landing 1.10.0 in Montimage/mmt-dpi (issue #751)

The 1.10.0 cycle moves the `montimage-projects/mmt-dpi` tree into the public
`Montimage/mmt-dpi` through the draft PR Montimage/mmt-dpi#41
(`release/v1.10.0` → `main`, a fast-forward from the merge base `af338b16`).
Every step below changes `Montimage/mmt-dpi` and is run by a maintainer, in
this order. Each step lists its prerequisites, the command, and the check
that proves it worked. Before step 1, confirm the `gh` admin access of
[AGENT_ENVIRONMENT.md §8](./AGENT_ENVIRONMENT.md#8-working-tree-gate-and-access-notes)
against `Montimage/mmt-dpi`. The commands run from a clone of the fork with
both repositories as remotes:

```bash
git remote add upstream git@github.com:Montimage/mmt-dpi.git  # once
git fetch origin && git fetch upstream --tags
```

State read on 2026-11-07, from GET calls only:

- upstream `release/v1.10.0` is at `92121095`, which lags the fork;
- the upstream tags `v1.9.0` (`ba757a84`) and `v1.9.1` (`7c150ef4`) name the
  rewritten commits. The fork's own `v1.9.1` is `1b4aad29`, which has the same
  tree (`256e1177`);
- the upstream Releases stop at `v1.8.0`, which has been Latest since
  2026-11-07. There is no `v1.9.1` Release;
- the `v1.9.1` tag run failed and opened upstream issue #42;
- `main` protection requires 1 review and no status check, with push
  restricted to `luongnv89` and `nhnghia`. There are no rulesets, all three
  merge methods are allowed, and Pages is not enabled.

The recorded decisions are in [DECISIONS.md](DECISIONS.md) (the issue #751
entries).

**1. Push `release/v1.10.0` to upstream.**
- **Prerequisites:** push access, and upstream's branch head an ancestor of
  the fork's (`git merge-base --is-ancestor upstream/release/v1.10.0 origin/release/v1.10.0`).
- **Command** (fast-forward only, never `--force`):
  `git push upstream origin/release/v1.10.0:refs/heads/release/v1.10.0`
- **Check:** `git ls-remote upstream refs/heads/release/v1.10.0` prints
  `git rev-parse origin/release/v1.10.0`, and
  `gh api repos/Montimage/mmt-dpi/compare/main...release/v1.10.0 --jq '[.ahead_by, .behind_by]'`
  shows `0` behind.

**2. Re-check #41 after the push.**
- **Command:**
  `gh pr view 41 --repo Montimage/mmt-dpi --json headRefOid --jq .headRefOid`
  must print the pushed SHA. Then
  `gh pr checks 41 --repo Montimage/mmt-dpi --watch`, and list what is not
  green with
  `gh pr checks 41 --repo Montimage/mmt-dpi | awk -F'\t' '$2 != "pass" && $2 != "skipping"'`.
- **Expected:**
  - `Labelled-pcap precision/recall …` passes: #747 skips the accuracy-corpus
    ratchet when the base has no pending list.
  - The open CodeQL alerts on the PR ref are exactly #8, #9, #10 and #15. The
    asn1c results are filtered and the strcat is gone (#748, #749). Check with
    `gh api "repos/Montimage/mmt-dpi/code-scanning/alerts?ref=refs/pull/41/merge&state=open&per_page=100" --jq '.[] | "\(.number) \(.rule.id) \(.rule.security_severity_level)"'`.
    The default-branch list says nothing about #41.
  - `abi-diff` stays red until step 3.
  - The three `Bootstrap smoke` legs stay red. Steps 3–4 explain why.

**3. Create the upstream v1.9.1 Release from the fork's 21 assets.**
- **Why by hand:** this is a recorded one-time exception to *The release
  workflow is the only publisher*.
  - The upstream tag run cannot be repaired. `verify-tag` needs `7c150ef4` on
    `main`. `release-gates` needs `Golden classification fingerprint unchanged`
    check runs at `7c150ef4`, and `phase0-baseline.yml` never records them for
    a tag. The tag's tree pins a `centos-stream9` digest that quay.io has
    dropped, so its package build fails.
  - Do not run `tools/ci/publish-release.sh` by hand either. It looks the
    draft up by the `github-actions[bot]` author, so run by a person it strands
    its draft and exits 2.
- **Prerequisites:** step 1 is done; the trees are equal
  (`git rev-parse '7c150ef4^{tree}' '1b4aad29^{tree}'` prints `256e1177…`
  twice); no upstream Release for `v1.9.1` exists.
- **Command:**

  ```bash
  d=$(mktemp -d)
  gh release download v1.9.1 --repo montimage-projects/mmt-dpi --dir "$d"
  (cd "$d" && ls | wc -l && sha256sum --check SHA256SUMS)   # 21, all OK
  gh attestation verify "$d"/mmt-dpi_1.9.1_1b4aad29_ubuntu-24.04_x86_64.deb \
    --repo montimage-projects/mmt-dpi
  cat > "$d.notes" <<'EOF'
  MMT-DPI 1.9.1. The assets are those of the montimage-projects/mmt-dpi
  v1.9.1 Release, which its release workflow built from 1b4aad29. That commit
  has the same tree as this tag, 7c150ef4. Their provenance is attested in that
  repository: gh attestation verify <file> --repo montimage-projects/mmt-dpi
  EOF
  gh release create v1.9.1 "$d"/* --repo Montimage/mmt-dpi --verify-tag \
    --title v1.9.1 --notes-file "$d.notes" --latest
  ```

- **Check:**
  - `gh release view v1.9.1 --repo Montimage/mmt-dpi --json isDraft,assets --jq '[.isDraft, (.assets | length)]'`
    prints `[false,21]`.
  - The asset digests match the fork's:
    `diff <(gh release view v1.9.1 --repo Montimage/mmt-dpi --json assets --jq '.assets[] | "\(.name) \(.digest)"' | sort) <(gh release view v1.9.1 --repo montimage-projects/mmt-dpi --json assets --jq '.assets[] | "\(.name) \(.digest)"' | sort)`
    prints nothing.
- **Limits:**
  - The asset names carry `1b4aad29`.
  - `gh attestation verify --repo Montimage/mmt-dpi` fails on these assets,
    because their attestation lives in the fork only.
  - The `Bootstrap smoke` fixture (`tools/ci/make-bootstrap-fixture.sh`)
    downloads the Latest Release's bundle from the upstream attestations API,
    which answers 404 for these digests and for v1.8.0's. The smoke stays red
    on #41 and turns green with the first Release the upstream workflow
    publishes (step 10). It is not a required check.
  - A Release published by a person raises `release: published`. That runs
    `install-smoke.yml` from the tag's tree, which pins images dropped since
    then (at least the `centos-stream9` one). Expect that run to fail and to
    open an upstream issue titled `Install smoke matrix failing`. Close that
    issue with #42 in step 5.

**4. Re-check #41 after the v1.9.1 Release.**
- **Command:** re-run the failed jobs of the PR's latest `c-cpp.yml` run:

  ```bash
  run=$(gh run list --repo Montimage/mmt-dpi --workflow c-cpp.yml \
    --branch release/v1.10.0 --event pull_request --limit 1 \
    --json databaseId --jq '.[0].databaseId')
  gh run rerun "$run" --repo Montimage/mmt-dpi --failed
  ```

- **Check:** `gh pr checks 41 --repo Montimage/mmt-dpi --watch` ends with
  `abi-diff` passing. Its symbol leg now finds the `v1.9.1` `SHA256SUMS` and
  the ubuntu-24.04 `.deb`. What is still not green is CodeQL (step 6) and the
  three bootstrap legs (step 3).

**5. Close the release alert, upstream issue #42** (and the
`Install smoke matrix failing` issue of step 3, if it was opened).
- **Prerequisites:** step 3 is done.
- **Command:** `gh issue close 42 --repo Montimage/mmt-dpi --comment "v1.9.1 is published from the fork's assets, as a recorded exception (docs/DECISIONS.md, issue #751). The v1.9.1 tag run cannot pass upstream."`
- **Check:** `gh issue view 42 --repo Montimage/mmt-dpi --json state --jq .state`
  prints `CLOSED`.

**6. Dismiss the four CodeQL alerts as "Won't fix".**
- **Prerequisites:** step 2 lists exactly #8, #9, #10 and #15 as open. Their
  reasons are in the issue #749 entry of [DECISIONS.md](DECISIONS.md). The
  follow-up #756 (`secure_getenv`) is not a blocker.
- **Command:**

  ```bash
  for a in 8 9 10 15; do
    gh api -X PATCH "repos/Montimage/mmt-dpi/code-scanning/alerts/$a" \
      -f state=dismissed -f "dismissed_reason=won't fix" \
      -f "dismissed_comment=Operator-set path, outside the remote-input threat model: docs/DECISIONS.md, issue #749 entry"
  done
  ```

- **Check:**
  - The step 2 alert query prints nothing.
  - `gh pr checks 41 --repo Montimage/mmt-dpi | grep CodeQL` passes. If it is
    still red, re-run the `codeql` job of the PR's `c-cpp.yml` run
    (recompute `run` as in step 4 in a new shell, then
    `job=$(gh run view "$run" --repo Montimage/mmt-dpi --json jobs --jq '.jobs[] | select(.name == "codeql") | .databaseId'); gh run rerun --job "$job" --repo Montimage/mmt-dpi`).

**7. Enable GitHub Pages (workflow build).**
- **Why before the merge:** `pages.yml` deploys on the merge's push to `main`.
- **Command:** `gh api -X POST repos/Montimage/mmt-dpi/pages -f build_type=workflow`
- **Check:** `gh api repos/Montimage/mmt-dpi/pages --jq '[.build_type, .html_url]'`
  prints `workflow` and `https://montimage.github.io/mmt-dpi/`. After step 8,
  the `pages.yml` run on `main` succeeds, and
  `curl -fsSI https://montimage.github.io/mmt-dpi/` answers 200. If Pages was
  enabled after the merge, deploy with
  `gh workflow run pages.yml --repo Montimage/mmt-dpi --ref main`.

**8. Merge #41, never squash or rebase.**
- **Why:** squash and rebase both create new commits. The tags would then
  leave `main`'s ancestry, and `tools/ci/check-release-tag.sh` requires the
  tagged commit to be an ancestor of `origin/main`.
- **Prerequisites:**
  - `gh pr ready 41 --repo Montimage/mmt-dpi`.
  - `behind_by` is still `0` (step 1's compare).
  - The fork's branch has not moved since #41 was tested:
    `git rev-parse origin/release/v1.10.0` equals
    `gh pr view 41 --repo Montimage/mmt-dpi --json headRefOid --jq .headRefOid`.
  - The preferred push needs the admin bypass, with or without an approval:
    `enforce_admins` off and the pusher on the push-restriction list
    (`gh api repos/Montimage/mmt-dpi/branches/main/protection --jq '[.enforce_admins.enabled, [.restrictions.users[].login]]'`).
    The fallback needs an approving review by a maintainer other than the
    author.
- **Command, preferred** (a true fast-forward of the tested head):
  `git fetch upstream && git push upstream upstream/release/v1.10.0:refs/heads/main`.
  GitHub marks #41 merged on its own.
- **Command, fallback** (a merge commit, which keeps every commit and tag in
  the ancestry):
  `gh pr merge 41 --repo Montimage/mmt-dpi --merge`.
- **Check:**
  - `gh pr view 41 --repo Montimage/mmt-dpi --json state --jq .state` prints
    `MERGED`.
  - After `git fetch upstream`,
    `git merge-base --is-ancestor 7c150ef4 upstream/main && echo "v1.9.1 on main"`
    prints its message.

**9. Require the status checks on `main`.**
- **Prerequisites:** step 8 is done. The merge-queue ruleset of the same
  `CONTRIBUTING.md` block uses `"merge_method": "SQUASH"`, so it is applied
  only now, after #41 has landed. Steps 9 and 10 read
  `.github/required-checks.txt`, the workflows and `tools/ci/base-images.txt`
  from the working tree, so run them from the merged tree
  (`git fetch upstream && git switch --detach upstream/main`), not from a
  fork branch.
- **Command:** the `jq … | gh api -X PATCH …/protection/required_status_checks`
  line of `CONTRIBUTING.md` (*Required checks and review*), which reads
  `.github/required-checks.txt`. Today no status check is required. If that
  PATCH answers 404, add status checks with `PUT …/branches/main/protection`
  instead, carrying the current review count, `enforce_admins` and push
  restrictions read from the GET above, so nothing else changes. Then apply
  the rest of that block: the merge-queue ruleset and the review settings.
  Once protection no longer requires them, delete the stubs of
  `.github/retired-checks.txt`.
- **Check:**
  - `bash tools/ci/check-required-checks.sh --live Montimage/mmt-dpi` passes.
  - `gh api repos/Montimage/mmt-dpi/rules/branches/main --jq '.[].type'`
    prints `merge_queue`.

**10. Tag v1.10.0** (the *Release order* above, on upstream).
- **Prerequisites:**
  - A PR replaces `Version 1.10.0 (unreleased)` with the date at the sites
    `bash scripts/validate-release-prep.sh` reads, and it merges.
  - Every gate `release-gates` reads has a completed, green run on the new
    `main` head:
    `sha=$(gh api repos/Montimage/mmt-dpi/commits/main --jq .sha); GH_TOKEN=$(gh auth token) GITHUB_REPOSITORY=Montimage/mmt-dpi bash tools/ci/check-release-gates.sh --skip-same-run "$sha"`.
    The v1.9.1 run failed partly because these were still queued.
  - `bash tools/ci/refresh-base-images.sh --check` reports no `missing` pin.
    A dropped quay.io digest is what broke v1.9.1's package build. The script
    also exits 1 on `drift`, which still pulls, so read its verdicts: repin
    first only when a pin is `missing`.
- **Command:**
  `git fetch upstream main && git tag -a v1.10.0 -m "MMT-DPI 1.10.0" upstream/main && git merge-base --is-ancestor v1.10.0 upstream/main && git push upstream v1.10.0`.
  This starts `release-packages.yml`. Do not create this Release by hand.
- **Check:**
  - `verify-tag`, `release-gates` and `Publish GitHub Release` succeeded.
  - `gh release view v1.10.0 --repo Montimage/mmt-dpi --json assets --jq '.assets | length'`
    counts the packages, SBOMs, `SHA256SUMS` and the bootstrap set.
  - `gh attestation verify <downloaded .deb> --repo Montimage/mmt-dpi` passes.
  - The `Bootstrap smoke` run that follows the tag run is green.
- **Then:** steps 3–4 of *Release order*. Run
  `bash tools/ci/check-release-tag.sh --write-pin v1.10.0`, move
  `ABI_BASELINE` and `baseline_ref` to `v1.10.0`, and update the README and
  site pins, all in one PR. Then run the **Install smoke** workflow with
  `source: published`. Its supported legs include `opensuse-leap-16.0`, whose
  pin is one of the pins fork PR #743 refreshes.

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