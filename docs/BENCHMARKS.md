---
layout: default
title: "Benchmarks: 1.10.0 against Montimage/mmt-dpi main"
---

# Benchmarks: 1.10.0 against Montimage/mmt-dpi main

The landing page's 1.10.0 figures come from one head-to-head run, recorded
here with its conditions and raw output. 1.10.0 is **unreleased**: the
current release is still the one the [landing page](index.html#quick-start) installs.

## What was compared

| | Baseline | Candidate |
|---|---|---|
| Tree | `Montimage/mmt-dpi` `main` at `af338b16` (`git describe`: `v1.8.0-40-gaf338b16`) | `release/v1.10.0`, measured at `54bdae50` |
| SDK build | default profile (`-O3`), and `BUILD=asan` for the sanitizer run | same |

`54bdae50` is not on the published branch. Its tree is identical to
`90b7a8cf` on `release/v1.10.0` (`git diff 54bdae50 90b7a8cf` is empty), and
nothing under `src/`, `rules/`, `data/` or `tools/phase0/` has changed on the
branch since. The baseline is upstream `main`, **not** the v1.9.1 release,
which is not an ancestor of `af338b16`.

Host: one Docker `ubuntu:24.04` container on aarch64, GCC 13.3.0,
valgrind 3.22, 10 CPUs. Both trees were built, run and measured in that
container, with the same driver sources (the candidate's
`tools/phase0/phase0_classify.c`) and the same inputs
([`env.txt`](benchmarks/1.10.0-vs-af338b16/env.txt)). Wall-clock figures
hold for this host only; compare ratios, not absolute rates, with another
machine.

## Throughput and memory

`tools/phase0/capture_perf.sh --iterations 20` against each tree's
installed SDK: an in-memory, single-thread replay of `bigFlows.pcap`
(791,615 packets), run twice, alternating baseline and candidate. Modes as in
the file headers: `bare` fetches no attribute, `attrs8` fetches eight per
packet through a packet handler. `library_rss_kib` is the SDK's resident
memory on top of the preloaded trace.

| `bigFlows.pcap` | Baseline (round 1 / 2) | 1.10.0 (round 1 / 2) | Change |
|---|---|---|---|
| `bare`, packets/s | 1,197,620 / 1,346,984 | 3,036,670 / 3,057,165 | ×2.5 / ×2.3 |
| `attrs8`, packets/s | 1,107,672 / 1,187,583 | 2,248,058 / 2,272,861 | ×2.0 / ×1.9 |
| `bare`, library RSS (KiB) | 40,848 / 40,700 | 18,028 / 18,008 | −56% |

The baseline's rate varied about 12% between rounds, the candidate's under
1%. Raw output: [`throughput_up_1.txt`](benchmarks/1.10.0-vs-af338b16/throughput_up_1.txt),
[`throughput_up_2.txt`](benchmarks/1.10.0-vs-af338b16/throughput_up_2.txt),
[`throughput_cand_1.txt`](benchmarks/1.10.0-vs-af338b16/throughput_cand_1.txt),
[`throughput_cand_2.txt`](benchmarks/1.10.0-vs-af338b16/throughput_cand_2.txt)
(the `smallFlows.pcap` and fetch-all rows are there too).

The committed same-host reference that the CI gates use is a separate file,
`tools/phase0/baseline/perf/throughput.txt`; this run does not replace it.

## Robustness under hostile input

2,011 inputs: 2,000 deterministic mutants of the 21 CI pcaps
(`tools/ci/fuzz/mutate.py`, seeds 224001–226000) plus the 11 committed fuzz
regressions (`tools/ci/fuzz/regressions/`). Each tree's `BUILD=asan` SDK ran
each input through the same ASan + UBSan driver
(`-fsanitize=address,undefined -fno-sanitize-recover=all`, 20 s timeout).
A finding is a sanitizer report or a timeout.

| | Baseline | 1.10.0 |
|---|---|---|
| ASan memory errors (heap-buffer-overflow 7, memcpy-param-overlap 2, heap-use-after-free 1) | 10 | 0 |
| Hangs past 20 s | 16 | 0 |
| UBSan reports (misaligned access 72, out-of-bounds index 1, null argument 1) | 74 | 0 |
| **Total** | **100** | **0** |

Raw output: one line per finding in
[`sanitizer_findings_up.txt`](benchmarks/1.10.0-vs-af338b16/sanitizer_findings_up.txt);
[`sanitizer_findings_cand.txt`](benchmarks/1.10.0-vs-af338b16/sanitizer_findings_cand.txt)
is empty because the candidate had none.

valgrind memcheck over `smallFlows.pcap` (14,261 packets): the baseline
loses 171 bytes in 4 blocks (2 errors) and allocates 22.8 MB in total; 1.10.0
loses nothing (0 errors) and allocates 4.4 MB
([`valgrind_smallflows_up.txt`](benchmarks/1.10.0-vs-af338b16/valgrind_smallflows_up.txt),
[`valgrind_smallflows_cand.txt`](benchmarks/1.10.0-vs-af338b16/valgrind_smallflows_cand.txt)).

## Not claimed

- Instructions per packet. 1.10.0 is cheaper per packet on `smallFlows.pcap`,
  but costs more on the tiny CI pcaps, which are almost all new flows: there it
  does more per-flow work (QUIC Initial decryption, TLS ClientHello
  reassembly, JA4, corroboration of weak signatures).
- Classification accuracy. The reviewed accuracy corpus was written together
  with the 1.10.0 fixes, so a comparison on it favours 1.10.0 by construction.
- x86-64. This run was aarch64 only.
