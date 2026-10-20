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
(`tools/ci/check-release-tag.sh`).

**Declared version** — bump these together, at the start of the release
cycle, to the version being prepared; each must equal `VERSION` exactly:

| Site | What the check reads |
|------|----------------------|
| `rules/common.mk` | `VERSION := x.y.z` (the source) |
| `src/mmt_core/public_include/mmt_core.h` | `#define VERSION "x.y.z"` (fallback for consumers that do not pass `-DVERSION`) |
| `dist/ZIP/mmt-install-common.sh` | `VERSION="${VERSION:-x.y.z}"` (`make zip` restamps it) |
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

Release order:

1. Bump the declared-version sites and open the new
   `Version x.y.z (unreleased)` section in `CHANGELOG.md`.
2. When cutting the release, replace `(unreleased)` with the release date,
   then tag that commit `vx.y.z`.
3. After the tag is published, update the published-release sites in one
   follow-up PR: run `bash tools/ci/check-release-tag.sh --write-pin vx.y.z`,
   which writes `RELEASE_TAG` and `RELEASE_TAG_SHA` from the peeled tag
   (`git rev-parse vx.y.z^{commit}`, never the annotated tag object), then
   update the README/site mentions.

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

```
git tag -a v1.4 -m "my version 1.4"
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