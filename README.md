# dns-blocklist-merged

Fetches several public DNS blocklists, normalizes every entry to one canonical
form, removes duplicates across lists, and publishes a single merged list for
AdGuard Home.

Because all four common list syntaxes collapse to the same rule, entries that
were previously stored several times (once per list, once per syntax) end up
stored once:

| Source syntax | Example | Becomes |
|---|---|---|
| wildcard | `*.ads.example.com` | `\|\|ads.example.com^` |
| adblock | `\|\|ads.example.com^` | `\|\|ads.example.com^` |
| bare domain | `ads.example.com` | `\|\|ads.example.com^` |
| hosts | `0.0.0.0 ads.example.com` | `\|\|ads.example.com^` |

Exceptions (`@@`) are never converted into blocks; cosmetic rules are dropped
(meaningless at DNS level).

## How it works

- `merge.py` — the whole build. Idempotent, no dependencies beyond the stdlib.
- `lists.txt` — the sources, one URL per line. Edit this to add or drop lists.
- `.github/workflows/rebuild.yml` — runs every Monday 04:00 UTC, on demand, or
  when `lists.txt` changes; force-pushes the result to the `lists` branch as a
  single squashed commit (so the repo does not grow ~26 MB per week).
- `lists` branch — `merged-blocklist.txt` + `build-info.txt`. This is what you
  point AdGuard at.

Fail-safe: if a source fails to download, returns HTML, or yields zero usable
rules, the build aborts and the previously published list stays live. Up to
`--allow-failures 3` transient failures are tolerated and recorded in
`build-info.txt`.

## Using it in AdGuard Home

Add one filter, URL:

```
https://raw.githubusercontent.com/OWNER/REPO/lists/merged-blocklist.txt
```

Then delete the original six lists so they are not counted twice. Set the
filter update interval to 24 h (Filters -> any list -> Edit -> update interval).

The repo must be **public** — `raw.githubusercontent.com` has no auth for
private repos, so AdGuard cannot fetch a private one.

## Trimming

All six sources land around 1.24M unique rules / ~26 MB. Commenting out the
last two (`1Hosts Xtra`, `StevenBlack`) gives roughly 540k rules. `1Hosts Xtra`
alone contributes ~655k mostly-unique hosts, so it is the single biggest lever
on size — and the usual source of false positives.

## Running locally

```bash
python merge.py --out merged-blocklist.txt --info build-info.txt
```
