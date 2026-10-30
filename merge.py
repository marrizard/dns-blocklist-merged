#!/usr/bin/env python3
"""Fetch several DNS blocklists, normalize to one rule per host, dedupe, and emit
a single merged list for AdGuard Home / Pi-hole.

Every list is normalized to the same canonical form (||host^) so that
    *.ads.example.com     (Hagezi / OISD wildcard syntax)
    ||ads.example.com^    (AdGuard / EasyList syntax)
    ads.example.com       (1Hosts bare-domain syntax)
    0.0.0.0 ads.example.com   (hosts syntax)
collapses to ONE rule instead of four.

Safety: if any source fails, returns junk, or shrinks suspiciously, the whole
build aborts and the previously published list stays live.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import re
import sys
import time
import urllib.error
import urllib.request

MIN_RULES_PER_SOURCE = 1_000
MIN_TOTAL_RULES = 100_000
TIMEOUT = 180
RETRIES = 3
UA = "blocklist-merge/1.0 (+https://github.com/)"

HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+(\S+)$", re.I)
ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9_.*-]+)\^?$", re.I)
WILDCARD_RE = re.compile(r"^\*\.([a-z0-9_][a-z0-9_.-]*)$", re.I)
BARE_RE = re.compile(
    r"^([a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)+)$",
    re.I,
)
COSMETIC_RE = re.compile(r"##|#@#|#\?#|#\$#|#%#")


def fetch(url: str) -> str:
    last = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw = resp.read()
            if raw[:2] == b"\x1f\x8b":
                raw = gzip.decompress(raw)
            text = raw.decode("utf-8", errors="replace")
            if not text.strip():
                raise ValueError("empty response")
            if text.lstrip()[:1] == "<":
                raise ValueError("got HTML, not a blocklist")
            return text
        except Exception as exc:  # noqa: BLE001
            last = exc
            if attempt < RETRIES:
                time.sleep(2 * attempt)
    raise RuntimeError(f"{url}: {last}")


def parse(text: str):
    """Yield (hosts, verbatim, allow) for one list body."""
    hosts, verbatim, allow = set(), set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0] in "!#[" or line.startswith("//"):
            continue
        if COSMETIC_RE.search(line):
            continue
        if line.startswith("@@"):
            allow.add(line)
            continue

        m = HOSTS_RE.match(line) or ADBLOCK_RE.match(line) or WILDCARD_RE.match(line) or BARE_RE.match(line)
        if not m:
            verbatim.add(line)
            continue

        host = m.group(1).lower().rstrip(".")
        if "*" in host:
            verbatim.add(line)
            continue
        if not host or "." not in host:
            continue  # localhost / broadcasthost / ip6-allnodes style noise
        hosts.add(host)
    return hosts, verbatim, allow


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lists", default="lists.txt")
    ap.add_argument("--out", default="merged-blocklist.txt")
    ap.add_argument("--info", default="build-info.txt")
    ap.add_argument("--allow-failures", type=int, default=0,
                    help="tolerate this many unreachable sources (default 0)")
    args = ap.parse_args()

    with open(args.lists, encoding="utf-8") as fh:
        urls = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]

    if not urls:
        print("no lists configured", file=sys.stderr)
        return 1

    seen: set[str] = set()
    verbatim: set[str] = set()
    allow: set[str] = set()
    stats = []
    failures: list[tuple[str, str]] = []
    raw_total = 0

    for url in urls:
        try:
            text = fetch(url)
        except Exception as exc:  # noqa: BLE001
            print(f"FAILED: {url}\n  {exc}", file=sys.stderr)
            failures.append((url, str(exc)))
            continue

        hosts, verb, allow_this, = parse(text)
        if len(hosts) < MIN_RULES_PER_SOURCE:
            msg = f"only {len(hosts)} usable rules (min {MIN_RULES_PER_SOURCE})"
            print(f"FAILED: {url}: {msg}", file=sys.stderr)
            failures.append((url, msg))
            continue

        before = len(seen)
        seen |= hosts
        verbatim |= verb
        allow |= allow_this

        added = len(seen) - before
        dup = 0.0 if not hosts else 100.0 * (len(hosts) - added) / len(hosts)
        raw_total += len(hosts)
        stats.append((url, len(hosts), added, dup))
        print(f"{added:>8} new / {len(hosts):>8} rules  ({dup:5.1f}% dup)  {url}")

    if len(failures) > args.allow_failures:
        print(
            f"ABORT: {len(failures)} source(s) failed, allowed {args.allow_failures}. "
            "Keeping the previously published list.",
            file=sys.stderr,
        )
        for url, why in failures:
            print(f"  {url}: {why}", file=sys.stderr)
        return 1

    if len(seen) < MIN_TOTAL_RULES:
        print(
            f"ABORT: merged list has only {len(seen)} rules (min {MIN_TOTAL_RULES})",
            file=sys.stderr,
        )
        return 1

    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("! Merged + deduped. Canonical form: ||host^\n")
        for host in sorted(seen):
            fh.write(f"||{host}^\n")
        for rule in sorted(verbatim):
            fh.write(f"{rule}\n")
        for rule in sorted(allow):
            fh.write(f"{rule}\n")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(args.info, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"built: {stamp}\n")
        fh.write(f"unique rules: {len(seen)}\n")
        fh.write(f"raw rules read: {raw_total}\n")
        fh.write(f"duplicate share: {0 if not raw_total else round(100.0 * (raw_total - len(seen)) / raw_total, 1)}%\n")
        fh.write(f"verbatim rules kept: {len(verbatim)}\n")
        fh.write(f"exceptions kept: {len(allow)}\n\n")
        for url, parsed, added, dup in stats:
            fh.write(f"{added:>8} new / {parsed:>8} rules ({dup:5.1f}% dup)  {url}\n")
        if failures:
            fh.write(f"\nWARNING: {len(failures)} source(s) unreachable this run:\n")
            for url, why in failures:
                fh.write(f"  {url}: {why}\n")

    print(f"wrote {args.out}: {len(seen)} unique rules from {raw_total} raw")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
