#!/usr/bin/env python3
#
# mutate.py — deterministic single-mutant generator for the CI fuzz gate
# (issue #224, F-SEC-009).
#
# Given a seed file and an integer seed, writes exactly one mutated copy.
# The same (seed_file, seed) pair always produces the same mutant, so a
# crash found in CI reproduces locally with the printed seed.
#
# Mutations are byte-level and format-agnostic: bit/byte flips, truncation,
# extension, byte insertion/deletion and chunk zeroing. That is deliberate —
# the goal is hostile *structure* drift (length fields, headers, payloads),
# not just payload noise, and it works identically on pcaps and XML.
#
# Usage:
#   mutate.py <seed_file> <out_file> --seed N [--max-ops K]
#
# Exit codes: 0 = mutant written, 2 = usage/IO error.

import argparse
import random
import sys


def _flip_bit(data: bytearray, rng: random.Random) -> None:
    if not data:
        return
    i = rng.randrange(len(data))
    data[i] ^= 1 << rng.randrange(8)


def _flip_byte(data: bytearray, rng: random.Random) -> None:
    if not data:
        return
    i = rng.randrange(len(data))
    data[i] = rng.randrange(256)


def _truncate(data: bytearray, rng: random.Random) -> None:
    if len(data) < 2:
        return
    del data[rng.randrange(1, len(data)):]


def _extend(data: bytearray, rng: random.Random) -> None:
    # Append up to 64 bytes of PRNG or repeated-seed content.
    n = rng.randrange(1, 65)
    if data and rng.random() < 0.5:
        chunk = bytes(rng.choice(data) for _ in range(n))
    else:
        chunk = bytes(rng.randrange(256) for _ in range(n))
    data.extend(chunk)


def _insert(data: bytearray, rng: random.Random) -> None:
    n = rng.randrange(1, 33)
    i = rng.randrange(len(data) + 1)
    data[i:i] = bytes(rng.randrange(256) for _ in range(n))


def _delete(data: bytearray, rng: random.Random) -> None:
    if len(data) < 2:
        return
    i = rng.randrange(len(data))
    del data[i:i + rng.randrange(1, min(64, len(data) - i) + 1)]


def _zero_chunk(data: bytearray, rng: random.Random) -> None:
    if not data:
        return
    i = rng.randrange(len(data))
    for j in range(i, min(len(data), i + rng.randrange(1, 65))):
        data[j] = 0


def _dup_chunk(data: bytearray, rng: random.Random) -> None:
    if not data:
        return
    i = rng.randrange(len(data))
    n = rng.randrange(1, min(64, len(data) - i) + 1)
    data[i:i] = data[i:i + n]


_OPS = [
    _flip_bit, _flip_byte, _truncate, _extend,
    _insert, _delete, _zero_chunk, _dup_chunk,
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic single-mutant generator")
    ap.add_argument("seed_file")
    ap.add_argument("out_file")
    ap.add_argument("--seed", type=int, required=True,
                    help="integer seed; same input + seed => same mutant")
    ap.add_argument("--max-ops", type=int, default=8,
                    help="number of mutation ops to apply (default 8)")
    args = ap.parse_args()

    try:
        with open(args.seed_file, "rb") as fp:
            data = bytearray(fp.read())
    except OSError as exc:
        print(f"mutate.py: cannot read {args.seed_file}: {exc}", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    for _ in range(max(1, args.max_ops)):
        rng.choice(_OPS)(data, rng)

    try:
        with open(args.out_file, "wb") as fp:
            fp.write(data)
    except OSError as exc:
        print(f"mutate.py: cannot write {args.out_file}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
