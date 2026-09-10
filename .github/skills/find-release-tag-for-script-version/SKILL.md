---
name: find-release-tag-for-script-version
description: >
  Given a released script name and its version string (e.g., HealthChecker
  26.03.12.1424), find the earliest GitHub release tag whose ScriptVersions.csv
  lists that File + Version. Use this skill when you need to reproduce, debug,
  or diff a specific reported script version against its source.
---

# Find Release Tag for a Script Version

CSS-Exchange script versions (e.g., `26.03.12.1424`) are per-script build
stamps generated from the newest commit timestamp of the script's sources.
They are NOT repo tags, and the same version routinely appears in multiple
consecutive releases (a script whose sources have not changed keeps its
version across releases).

The published `ScriptVersions.csv` asset on each GitHub release maps
`File → Version + SHA256Hash` for that release. It is the authoritative source
for "which release first shipped this build."

## What this skill answers (and does not)

**Answers:** the earliest GitHub release whose `ScriptVersions.csv` lists the
requested `File` + `Version` pair.

**Does not answer:**
- Which release produced a specific set of bytes. The same `File + Version`
  can appear in multiple releases with **different** SHA256Hash values
  (signing/timestamp differences). If you need byte identity, compare the
  SHA256Hash column against your local artifact.
- Which source commit produced a given version. The version is a minute-
  precision maximum of the script's dependency commit timestamps; two
  different source states can (rarely) map to the same version and a single
  source state can span versions.

## Coverage limits

- `ScriptVersions.csv` was not published on releases before
  `v21.04.14.1849`. Earlier versions cannot be resolved by this method.
- Draft and prerelease releases are excluded.

## When to Use This

- A user reports "HealthChecker 26.03.12.1424" and you need the source
- Reproducing a bug against the same source snapshot that was released
- Diffing a script between two reported versions

## Do NOT

- Guess based on commit timestamps or tag names alone
- Assume a tag name matches the script version (they rarely do)
- Skip the CSV verification step

## Process

1. **List releases** (not local tags) via `gh release list` and filter to
   date-shaped tags on or after the script version's date. Local `git tag -l`
   is unreliable — it can include non-release tags and can miss tags a
   shallow clone hasn't fetched.

2. **Walk ascending by tag date.** The first release whose CSV lists the
   File + Version pair is the earliest confirmed release. Walk direction is
   always forward — a later release cannot precede its own tag date.

3. **Download `ScriptVersions.csv`** from each candidate:

   ```powershell
   gh release download <tag> --repo github.com/microsoft/CSS-Exchange -p "ScriptVersions.csv" -O <path> --clobber
   ```

   Note the explicit `github.com/` host prefix — this pins the request to
   github.com even when `GH_HOST` or `GH_ENTERPRISE_TOKEN` is set in the
   caller's environment, preventing accidental credential redirection to an
   enterprise host.

4. **Verify File + Version match.** Match → record the tag and SHA256Hash.

5. **Interpret the result Status** (see below) before acting on it.

## Helper Script

`Find-ReleaseTagForScriptVersion.ps1` in this skill's directory automates the
walk and returns a structured result.

```powershell
.\.github\skills\find-release-tag-for-script-version\Find-ReleaseTagForScriptVersion.ps1 `
    -ScriptName HealthChecker `
    -Version 26.03.12.1424
```

Requires:
- `gh` on PATH, authenticated. Defaults to `microsoft/CSS-Exchange`; override
  with `-Repository owner/repo`.

## Result fields

| Field | Meaning |
|---|---|
| `Script` | Normalized script filename (adds `.ps1` if missing). |
| `Version` | The queried version string, echoed back unchanged. |
| `Repository` | The `owner/repo` value used (from `-Repository`; defaults to `microsoft/CSS-Exchange`). Callers use this to gate release-tag allowlists on downstream skills. |
| `ConfirmedTag` | Release tag whose `ScriptVersions.csv` matched the file+version, or `$null` when not found. |
| `ConfirmedCommitSha` | 40-hex commit SHA the tag points at, resolved via GitHub API. `$null` if `ConfirmedTag` is `$null` or the API lookup failed. Use for stable source citations (`git show <sha>:path`). |
| `SHA256Hash` | The `SHA256Hash` value from the matched CSV row, or `$null` when not found. |
| `Status` | See table below. |
| `WindowExhausted` | `$true` when the `MaxCandidates` window truncated the candidate list. |
| `EarlierGaps` | Number of earlier candidates that could not be inspected cleanly (download or CSV problems). |
| `Tried` | Per-candidate audit trail. |

## Result Status values

| Status | Meaning | Trust |
|---|---|---|
| `match-earliest` | Match found; every earlier candidate was cleanly inspected (valid CSV, either lists a different version or doesn't list the file at all), and the release enumeration was not truncated. | High — this is the earliest release. |
| `match-possibly-not-earliest` | Match found, but at least one earlier candidate could not be inspected (download failed or CSV was malformed) **or** the underlying `gh release list` returned its cap of 1,000 rows, meaning older releases may exist. An even earlier release could contain the same version. | Medium — good tag, but not proven earliest. Inspect `Tried` to decide. |
| `not-found-complete` | Every candidate in the window was inspected cleanly, none matched, and the release enumeration was not truncated. | High — the version was not shipped in this window. |
| `not-found-inconclusive` | No match found, but the search window was exhausted (`WindowExhausted = $true`), some candidates could not be inspected, **or** the release enumeration hit the 1,000-row cap. | Low — do not conclude "never shipped." Re-run with a larger `-MaxCandidates`. |
| `not-found-no-candidates` | No releases have a tag date on or after the version's date. Typically means the version is newer than the newest release, or the target repository has no matching stable date-shaped tags. | Medium — verify the version string is correct and that `-Repository` targets the right repo. |

### Per-candidate Tried statuses

| Status | Meaning | Counts as gap? |
|---|---|---|
| `match` | The candidate's CSV listed the file at the requested version. | n/a — terminates walk |
| `version-mismatch` | Valid CSV lists the file at a different version. | No — definitive |
| `file-not-listed` | Valid CSV does not list the file at all. | No — definitive |
| `download-failed` | `gh release download` returned non-zero (asset missing, network error, auth error, tag not a release). | Yes |
| `csv-oversize-or-missing` | Downloaded CSV was missing after `gh` reported success, or exceeded the 1 MB size cap. | Yes |
| `csv-malformed` | Downloaded CSV failed strict structural validation: empty, could not be parsed, header is not case-exact `File,Version,SHA256Hash` (with or without per-field quotes), any non-blank data line does not have exactly 3 comma-separated fields, any data line contains an odd number of `"` characters (unbalanced quoting), missing/extra/duplicate parsed columns, contains an all-empty delimited record, or lists the requested file more than once. (Fully blank physical lines are ignored.) | Yes |
| `csv-malformed-row` | Matching row present but `Version` was not `YY.MM.DD.HHMM` (including calendar validity) or `SHA256Hash` was not 64 hex characters. | Yes |

`WindowExhausted` reports whether the `MaxCandidates` cap truncated the
candidate list. On a match it is always `$false` (because later candidates
cannot precede the match); a `$true` value only appears on non-match results.

## Report Format

```
## Release Tag Lookup

**Script**:  HealthChecker.ps1
**Version**: 26.03.12.1424

**Confirmed Tag**:    v26.03.12.1616
**Commit SHA**:       a1b2c3d4e5f6...  # 40-hex commit SHA for the tag (may be `$null` if lookup failed)
**Status**:           match-earliest
**SHA256Hash**:       97429DCA7B8092F081149A3CE4B5B9CDB078D2F145ECFC7F51BB449B5EEAAD1D

**Candidates tried**:
- v26.03.12.1616 ✓ match
```

## Known limitations

- Search enumerates GitHub releases up to `--limit 1000` and caps candidates
  at `MaxCandidates` (max 500). CSS-Exchange has ~465 releases today, so
  these caps are not binding; a much larger repo could silently truncate.
- Candidate ordering uses the timestamp encoded in the tag name, not
  `publishedAt`. In this repo the two match; a backfilled or delayed release
  with an earlier-looking tag could theoretically report as "earliest" even
  if it was actually published later.
- Non-date-shaped release tags are silently excluded. A `-Repository`
  override to a project that does not follow the `vYY.MM.DD.HHMM` convention
  will get empty candidate sets.

## Security notes

- `-Repository` accepts only `owner/repo` form. A host prefix (`host/owner/repo`)
  is rejected to prevent `gh` from sending an ambient enterprise token to an
  arbitrary hostname.
- `-WorkFolder` must resolve to a local drive on Windows. Rejected forms:
  UNC/network prefixes (`\\server\share`, `//host/share`), PowerShell
  provider-qualified paths (`FileSystem::…`), NT device namespace (`\??\…`),
  extended-length UNC (`\\?\UNC\…`), drive letters mapped to network (SMB)
  shares, non-FileSystem PSDrives (e.g. `HKCU:`, `Env:`, `Variable:`),
  drives whose `DriveType` is not `Fixed`/`Removable`/`Ram`, `SUBST`-mapped
  drives, drives created via `DefineDosDevice(DDD_RAW_TARGET_PATH, ...)`
  that point at a subdirectory rather than a whole volume (detected via
  `QueryDosDevice`: only bare `\Device\<name>` targets are accepted, so
  `\??\C:\path` and `\Device\<name>\path` are both rejected),
  and paths whose volume root or any existing ancestor is a filesystem
  reparse point (symlink, junction, DFS link). This blocks NetNTLM
  leakage against an SMB server before any I/O reaches the caller-supplied
  path.
- On non-Windows platforms, the script accepts any absolute path but does
  **not** detect network mount points; run this helper only on Windows if
  that guarantee matters to you.
- A `-WorkFolder` you supply must be a directory only you control. The script
  cannot defend against another local process racing the download with
  junctions or symlinks. Prefer the default (a per-run folder under `$env:TEMP`).
- Content from downloaded CSVs is validated (Version format, SHA256 hex form,
  size cap) and control characters are stripped from any string surfaced in
  the result object. Do not treat fields in `Tried[].Detail` as
  authoritative — they are unchecked strings that exist for diagnosis only.

## Important Notes

- `ScriptVersions.csv` is generated by the build and is the single source of
  truth for File → Version. Always verify against it.
- `SHA256Hash` proves byte identity for a *specific release*, not for the
  version string. Different releases of the same version routinely have
  different hashes.
- Same script version in multiple releases → the earliest is the right answer
  for "when did this build first ship."
