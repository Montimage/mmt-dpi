# Dependency advisory status

- Commit: `69e4b707416780a191ed3e91ac84d8176e8e8992`
- Measured: 2026-09-23T03:42:44Z → 2026-09-23T03:43:55Z (UTC)
- Command: `bash tools/ci/check-dependency-advisories.sh`
- **Verdict: FAIL — confirmed unresolved High/Critical advisory (blocks M1); assessment also incomplete** (exit 1)

## Scanners and database dates

| Surface | Scanner | Database date | Queried (UTC) |
|---|---|---|---|
| gems | OSV https://api.osv.dev/v1/query (RubyGems) | Tue, 22 Sep 2026 23:48:33 GMT | 2026-09-23T03:42:54Z |
| gems | GitHub Advisory Database https://api.github.com/advisories (rubygems, reviewed) | live (HTTP Date Wed, 23 Sep 2026 03:43:05 GMT) | 2026-09-23T03:43:05Z |
| actions | GitHub Advisory Database https://api.github.com/advisories (actions, reviewed) | live (HTTP Date Wed, 23 Sep 2026 03:43:09 GMT) | 2026-09-23T03:43:09Z |
| native | OSV https://api.osv.dev/v1/query (Debian:12) | Wed, 23 Sep 2026 01:04:40 GMT | 2026-09-23T03:43:55Z |
| native | OSV https://api.osv.dev/v1/query (Rocky Linux:9) | Tue, 22 Sep 2026 18:49:00 GMT | 2026-09-23T03:43:55Z |
| native | OSV https://api.osv.dev/v1/query (Ubuntu:22.04:LTS) | Wed, 23 Sep 2026 02:25:09 GMT | 2026-09-23T03:43:55Z |
| native | OSV https://api.osv.dev/v1/query (Ubuntu:24.04:LTS) | Wed, 23 Sep 2026 02:25:09 GMT | 2026-09-23T03:43:55Z |

## Not Assessed

- quay.io/centos/centos:stream9@sha256:cfee9f59eb4d66295690829cebb75c6c97ca199c8929f8f933d88745280cbab4: CentOS Stream publishes no security advisories (no OSV ecosystem, no errata feed); revisions not resolved (docker run quay.io/centos/centos:stream9@sha256:cfee9f59eb4d66295690829cebb75c6c97ca199c8929f8f933d88745280cbab4: exit 125: Run 'docker run --help' for more information)

## Affected advisories

Severity is the highest of every available rating (advisory label, distro priority, CVSS v3 base score); each rating is listed. Targets are the pinned images of the distro table below.

| Severity | Surface | Target | Package @ installed | Advisory | Aliases | Ratings | Disposition | Fixed in |
|---|---|---|---|---|---|---|---|---|
| NOT ASSESSED | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2010-4756 | CVE-2010-4756 | none | unfixed | — |
| NOT ASSESSED | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-6368 | CVE-2026-6368 | none | unfixed | — |
| NOT ASSESSED | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-6791 | CVE-2026-6791 | none | unfixed | — |
| CRITICAL | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2019-1010022 | CVE-2019-1010022 | CRITICAL (CVSS 9.8); CRITICAL (CVSS 9.8 via CVE-2019-1010022) | unfixed | — |
| CRITICAL | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-5450 | CVE-2026-5450 | CRITICAL (CVSS 9.8); CRITICAL (CVSS 9.8 via CVE-2026-5450) | unfixed | — |
| CRITICAL | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-6653 | CVE-2026-6653 | CRITICAL (CVSS 9.8) | unfixed | — |
| HIGH | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2018-20796 | CVE-2018-20796 | HIGH (CVSS 7.5); HIGH (CVSS 7.5 via CVE-2018-20796) | unfixed | — |
| HIGH | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2019-1010023 | CVE-2019-1010023 | HIGH (CVSS 8.8); HIGH (CVSS 8.8 via CVE-2019-1010023) | unfixed | — |
| HIGH | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2019-9192 | CVE-2019-9192 | HIGH (CVSS 7.5); HIGH (CVSS 7.5 via CVE-2019-9192) | unfixed | — |
| HIGH | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-19499 | CVE-2026-19499 | HIGH (CVSS 7.7); HIGH (CVSS 7.7 via CVE-2026-19499) | unfixed | — |
| HIGH | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-5435 | CVE-2026-5435 | HIGH (CVSS 7.3) | unfixed | — |
| HIGH | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-5928 | CVE-2026-5928 | HIGH (CVSS 7.5); HIGH (CVSS 7.5 via CVE-2026-5928) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-11979 | CVE-2026-11979 | HIGH (CVSS 7.8) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-74860 | CVE-2026-74860 | HIGH (CVSS 8.5) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86138 | CVE-2026-86138 | HIGH (CVSS 7.8); MEDIUM (CVSS 6.9 via CVE-2026-86138) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86139 | CVE-2026-86139 | HIGH (CVSS 7.8); MEDIUM (CVSS 6.9 via CVE-2026-86139) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86140 | CVE-2026-86140 | HIGH (CVSS 7.8); HIGH (CVSS 8.0 via CVE-2026-86140) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86142 | CVE-2026-86142 | HIGH (CVSS 7.8); MEDIUM (CVSS 6.9 via CVE-2026-86142) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86143 | CVE-2026-86143 | HIGH (CVSS 7.3); MEDIUM (CVSS 6.9 via CVE-2026-86143) | unfixed | — |
| HIGH | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86144 | CVE-2026-86144 | HIGH (CVSS 7.8); MEDIUM (CVSS 5.6 via CVE-2026-86144) | unfixed | — |
| HIGH | native | ubuntu:22.04 | glibc @ 2.35-0ubuntu3.15 | UBUNTU-CVE-2016-20013 | CVE-2016-20013 | HIGH (CVSS 7.5); LOW (Ubuntu priority) | unfixed | — |
| HIGH | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-11979 | CVE-2026-11979 | HIGH (CVSS 7.8); LOW (Ubuntu priority) | unfixed | — |
| HIGH | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-86138 | CVE-2026-86138 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86138) | unfixed | — |
| HIGH | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-86139 | CVE-2026-86139 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86139) | unfixed | — |
| HIGH | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-86142 | CVE-2026-86142 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86142) | unfixed | — |
| HIGH | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-86143 | CVE-2026-86143 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.3); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86143) | unfixed | — |
| HIGH | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-86144 | CVE-2026-86144 | MEDIUM (CVSS 5.6); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 5.6 via CVE-2026-86144) | unfixed | — |
| HIGH | native | ubuntu:24.04 | glibc @ 2.39-0ubuntu8.9 | UBUNTU-CVE-2016-20013 | CVE-2016-20013 | HIGH (CVSS 7.5); LOW (Ubuntu priority) | unfixed | — |
| HIGH | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-11979 | CVE-2026-11979 | HIGH (CVSS 7.8); LOW (Ubuntu priority) | unfixed | — |
| HIGH | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-86138 | CVE-2026-86138 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86138) | unfixed | — |
| HIGH | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-86139 | CVE-2026-86139 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86139) | unfixed | — |
| HIGH | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-86142 | CVE-2026-86142 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86142) | unfixed | — |
| HIGH | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-86143 | CVE-2026-86143 | MEDIUM (CVSS 6.9); HIGH (CVSS 7.3); MEDIUM (Ubuntu priority); MEDIUM (CVSS 6.9 via CVE-2026-86143) | unfixed | — |
| HIGH | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-86144 | CVE-2026-86144 | MEDIUM (CVSS 5.6); HIGH (CVSS 7.8); MEDIUM (Ubuntu priority); MEDIUM (CVSS 5.6 via CVE-2026-86144) | unfixed | — |
| MEDIUM | native | debian:12 | gcc-12 @ 12.2.0-14+deb12u1 | DEBIAN-CVE-2022-27943 | CVE-2022-27943 | MEDIUM (CVSS 5.5) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2019-1010024 | CVE-2019-1010024 | MEDIUM (CVSS 5.3); MEDIUM (CVSS 5.3 via CVE-2019-1010024) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2019-1010025 | CVE-2019-1010025 | MEDIUM (CVSS 5.3); MEDIUM (CVSS 5.3 via CVE-2019-1010025) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-18374 | CVE-2026-18374 | MEDIUM (CVSS 4.9) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-19542 | CVE-2026-19542 | MEDIUM (CVSS 5.6); MEDIUM (CVSS 5.6 via CVE-2026-19542) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-6238 | CVE-2026-6238 | MEDIUM (CVSS 6.5) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-77117 | CVE-2026-77117 | MEDIUM (CVSS 5.9); MEDIUM (CVSS 5.9 via CVE-2026-77117) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-80489 | CVE-2026-80489 | MEDIUM (CVSS 5.9); MEDIUM (CVSS 5.9 via CVE-2026-80489) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-8674 | CVE-2026-8674 | MEDIUM (CVSS 5.3); MEDIUM (CVSS 5.3 via CVE-2026-8674) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-86805 | CVE-2026-86805 | MEDIUM (CVSS 6.3) | unfixed | — |
| MEDIUM | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-89092 | CVE-2026-89092 | MEDIUM (CVSS 4.2) | unfixed | — |
| MEDIUM | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-76781 | CVE-2026-76781 | MEDIUM (CVSS 5.5); MEDIUM (CVSS 5.5 via CVE-2026-76781) | unfixed | — |
| MEDIUM | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86137 | CVE-2026-86137 | MEDIUM (CVSS 6.1); LOW (CVSS 2.9 via CVE-2026-86137) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | gcc-12 @ 12.3.0-1ubuntu1~22.04.3 | UBUNTU-CVE-2022-27943 | CVE-2022-27943 | MEDIUM (CVSS 5.5); LOW (Ubuntu priority) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | glibc @ 2.35-0ubuntu3.15 | UBUNTU-CVE-2026-18374 | CVE-2026-18374 | MEDIUM (CVSS 4.9); MEDIUM (Ubuntu priority) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | glibc @ 2.35-0ubuntu3.15 | UBUNTU-CVE-2026-8674 | CVE-2026-8674 | MEDIUM (CVSS 5.3); MEDIUM (Ubuntu priority); MEDIUM (CVSS 5.3 via CVE-2026-8674) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | glibc @ 2.35-0ubuntu3.15 | UBUNTU-CVE-2026-89092 | CVE-2026-89092 | MEDIUM (CVSS 4.2); MEDIUM (Ubuntu priority) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2025-26434 | CVE-2025-26434 | MEDIUM (CVSS 5.5); MEDIUM (Ubuntu priority) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-76781 | CVE-2026-76781 | MEDIUM (CVSS 5.5); MEDIUM (Ubuntu priority); MEDIUM (CVSS 5.5 via CVE-2026-76781) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-86137 | CVE-2026-86137 | LOW (CVSS 2.9); MEDIUM (CVSS 6.1); MEDIUM (Ubuntu priority); LOW (CVSS 2.9 via CVE-2026-86137) | unfixed | — |
| MEDIUM | native | ubuntu:22.04 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | UBUNTU-CVE-2026-86141 | CVE-2026-86141 | LOW (CVSS 2.9); LOW (CVSS 3.3); MEDIUM (Ubuntu priority); LOW (CVSS 2.9 via CVE-2026-86141) | unfixed | — |
| MEDIUM | native | ubuntu:24.04 | glibc @ 2.39-0ubuntu8.9 | UBUNTU-CVE-2026-18374 | CVE-2026-18374 | MEDIUM (CVSS 4.9); MEDIUM (Ubuntu priority) | unfixed | — |
| MEDIUM | native | ubuntu:24.04 | glibc @ 2.39-0ubuntu8.9 | UBUNTU-CVE-2026-8674 | CVE-2026-8674 | MEDIUM (CVSS 5.3); MEDIUM (Ubuntu priority); MEDIUM (CVSS 5.3 via CVE-2026-8674) | unfixed | — |
| MEDIUM | native | ubuntu:24.04 | glibc @ 2.39-0ubuntu8.9 | UBUNTU-CVE-2026-89092 | CVE-2026-89092 | MEDIUM (CVSS 4.2); MEDIUM (Ubuntu priority) | unfixed | — |
| MEDIUM | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2025-26434 | CVE-2025-26434 | MEDIUM (CVSS 5.5); MEDIUM (Ubuntu priority) | unfixed | — |
| MEDIUM | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-76781 | CVE-2026-76781 | MEDIUM (CVSS 5.5); MEDIUM (Ubuntu priority); MEDIUM (CVSS 5.5 via CVE-2026-76781) | unfixed | — |
| MEDIUM | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-86137 | CVE-2026-86137 | LOW (CVSS 2.9); MEDIUM (CVSS 6.1); MEDIUM (Ubuntu priority); LOW (CVSS 2.9 via CVE-2026-86137) | unfixed | — |
| MEDIUM | native | ubuntu:24.04 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | UBUNTU-CVE-2026-86141 | CVE-2026-86141 | LOW (CVSS 2.9); LOW (CVSS 3.3); MEDIUM (Ubuntu priority); LOW (CVSS 2.9 via CVE-2026-86141) | unfixed | — |
| LOW | native | debian:12 | glibc @ 2.36-9+deb12u14 | DEBIAN-CVE-2026-95818 | CVE-2026-95818 | LOW (CVSS 3.6) | unfixed | — |
| LOW | native | debian:12 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | DEBIAN-CVE-2026-86141 | CVE-2026-86141 | LOW (CVSS 3.3); LOW (CVSS 2.9 via CVE-2026-86141) | unfixed | — |

## Release distro dependencies (platform linux/arm64)

Upstream base = upstream version inside the distro revision; `Feed records` = advisories the distro feed holds for the source package (queried by source name); `Fixed by backport` counts those the distro fixed without moving that base.

| Image | Package | Revision | Source @ revision | Upstream base | Feed records | Fixed by backport | Affected |
|---|---|---|---|---|---|---|---|
| `ubuntu:22.04@sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7` | libc6 | 2.35-0ubuntu3.15 | glibc @ 2.35-0ubuntu3.15 | 2.35 | 40 | 36 | 4 |
| `ubuntu:22.04@sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7` | libstdc++6 | 12.3.0-1ubuntu1~22.04.3 | gcc-12 @ 12.3.0-1ubuntu1~22.04.3 | 12.3.0 | 3 | 2 | 1 |
| `ubuntu:22.04@sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7` | libgcc-s1 | 12.3.0-1ubuntu1~22.04.3 | gcc-12 @ 12.3.0-1ubuntu1~22.04.3 | 12.3.0 | 3 | 2 | 1 |
| `ubuntu:22.04@sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7` | libxml2 | 2.9.13+dfsg-1ubuntu0.13 | libxml2 @ 2.9.13+dfsg-1ubuntu0.13 | 2.9.13 | 50 | 40 | 10 |
| `ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254` | libc6 | 2.39-0ubuntu8.9 | glibc @ 2.39-0ubuntu8.9 | 2.39 | 40 | 35 | 4 |
| `ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254` | libstdc++6 | 14.2.0-4ubuntu2~24.04.1 | gcc-14 @ 14.2.0-4ubuntu2~24.04.1 | 14.2.0 | 0 | 0 | 0 |
| `ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254` | libgcc-s1 | 14.2.0-4ubuntu2~24.04.1 | gcc-14 @ 14.2.0-4ubuntu2~24.04.1 | 14.2.0 | 0 | 0 | 0 |
| `ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254` | libxml2 | 2.9.14+dfsg-1.3ubuntu3.9 | libxml2 @ 2.9.14+dfsg-1.3ubuntu3.9 | 2.9.14 | 39 | 29 | 10 |
| `debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443` | libc6 | 2.36-9+deb12u14 | glibc @ 2.36-9+deb12u14 | 2.36 | 169 | 26 | 22 |
| `debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443` | libstdc++6 | 12.2.0-14+deb12u1 | gcc-12 @ 12.2.0-14+deb12u1 | 12.2.0 | 2 | 1 | 1 |
| `debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443` | libgcc-s1 | 12.2.0-14+deb12u1 | gcc-12 @ 12.2.0-14+deb12u1 | 12.2.0 | 2 | 1 | 1 |
| `debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443` | libxml2 | 2.9.14+dfsg-1.3~deb12u6 | libxml2 @ 2.9.14+dfsg-1.3~deb12u6 | 2.9.14 | 126 | 28 | 12 |
| `rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` | glibc | 0:2.34-275.el9_8 | glibc @ 0:2.34-275.el9_8 | 2.34 | 9 | 9 | 0 |
| `rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` | libstdc++ | 0:11.5.0-14.el9 | gcc @ 0:11.5.0-14.el9 | 11.5.0 | 1 | 1 | 0 |
| `rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` | libgcc | 0:11.5.0-14.el9 | gcc @ 0:11.5.0-14.el9 | 11.5.0 | 1 | 1 | 0 |
| `rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` | libxml2 | 0:2.9.13-14.el9_8.4 | libxml2 @ 0:2.9.13-14.el9_8.4 | 2.9.13 | 11 | 11 | 0 |

## Resolved docs gems (docs/Gemfile.lock)

| Gem | Version | Affected |
|---|---|---|
| addressable | 2.9.0 | 0 |
| base64 | 0.3.0 | 0 |
| bigdecimal | 4.1.3 | 0 |
| colorator | 1.1.0 | 0 |
| concurrent-ruby | 1.3.8 | 0 |
| csv | 3.3.6 | 0 |
| em-websocket | 0.5.3 | 0 |
| eventmachine | 1.2.7 | 0 |
| ffi | 1.17.4 | 0 |
| forwardable-extended | 2.6.0 | 0 |
| google-protobuf | 4.35.1 | 0 |
| http_parser.rb | 0.8.1 | 0 |
| i18n | 1.15.2 | 0 |
| jekyll | 4.4.1 | 0 |
| jekyll-relative-links | 0.8.0 | 0 |
| jekyll-remote-theme | 0.5.2 | 0 |
| jekyll-sass-converter | 3.1.0 | 0 |
| jekyll-seo-tag | 2.9.0 | 0 |
| jekyll-watch | 2.2.1 | 0 |
| json | 2.21.2 | 0 |
| kramdown | 2.5.2 | 0 |
| kramdown-parser-gfm | 1.1.0 | 0 |
| liquid | 4.0.4 | 0 |
| listen | 3.10.0 | 0 |
| logger | 1.7.0 | 0 |
| mercenary | 0.4.0 | 0 |
| openssl | 4.0.2 | 0 |
| pathutil | 0.16.2 | 0 |
| public_suffix | 6.0.2 | 0 |
| rake | 13.4.2 | 0 |
| rb-fsevent | 0.11.2 | 0 |
| rb-inotify | 0.11.1 | 0 |
| rexml | 3.4.4 | 0 |
| rouge | 4.7.0 | 0 |
| rubyzip | 3.6.0 | 0 |
| safe_yaml | 1.0.5 | 0 |
| sass-embedded | 1.102.0 | 0 |
| terminal-table | 3.0.2 | 0 |
| unicode-display_width | 2.6.0 | 0 |
| webrick | 1.9.2 | 0 |

## Pinned GitHub Actions

| Action | Release (pin comment) | Commit | Affected |
|---|---|---|---|
| actions/attest-build-provenance | 4.2.2 | 4d101475d8b2 | 0 |
| actions/cache | 6.1.0 | 55cc8345863c | 0 |
| actions/checkout | 7.0.1 | 3d3c42e5aac5 | 0 |
| actions/configure-pages | 6.0.0 | 45bfe0192ca1 | 0 |
| actions/deploy-pages | 5.0.1 | 368f82528645 | 0 |
| actions/download-artifact | 8.0.1 | 3e5f45b2cfb9 | 0 |
| actions/jekyll-build-pages | 1.0.13 | 44a6e6beabd4 | 0 |
| actions/upload-artifact | 7.0.1 | 043fb46d1a93 | 0 |
| actions/upload-pages-artifact | 5.0.0 | fc324d354710 | 0 |
| anchore/sbom-action | 0.24.2 | 3ad7283483fc | 0 |
| docker/setup-qemu-action | 4.3.0 | 1f40c72289ef | 0 |
| github/codeql-action | 4.38.0 | b96794f015df | 0 |
| gitleaks/gitleaks-action | 3.0.0 | e0c47f4f8be3 | 0 |
| ruby/setup-ruby | 1.323.0 | 984c0c890880 | 0 |
| softprops/action-gh-release | 3.0.3 | efb35369e0ad | 0 |

