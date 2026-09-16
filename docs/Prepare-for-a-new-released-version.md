---
layout: default
title: "Things need to be done before releasing a new stable version"
---

# Things need to be done before releasing a new stable version

## Update the new version number

Update the new version number in these files:

```
dist/ZIP/install.sh
rules/common.mk
src/mmt_core/public_include/mmt_core.h
```

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