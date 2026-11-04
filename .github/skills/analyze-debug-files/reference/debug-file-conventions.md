# CSS-Exchange Debug File Conventions

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


- **Filename**: `{ScriptName}-Debug_{yyyyMMddHHmmss}.txt` (optionally with a
  `-N` rollover suffix), or plain `{ScriptName}-Debug.txt`.
- **Log line**: `[MM/dd/yyyy HH:mm:ss.fffffff] : {message}`. Continuation
  lines (stack traces, dumped `$Error[0]`) are written raw and belong to
  the preceding timestamped line.
- **Version marker(s)** — the helper accepts two repository-backed
  forms, both anchored to a build-timestamp signature
  `YY.MM.DD.HHMM`:
  - `Script Version: YY.MM.DD.HHMM` — the canonical preamble
    emitted by `Write-Grey "Script Version: $BuildVersion"` at
    the start of most CSS-Exchange scripts (including
    HealthChecker's early preamble).
  - `Exchange Health Checker version YY.MM.DD.HHMM` — the
    in-report banner emitted by
    `Diagnostics/HealthChecker/Features/Invoke-HealthCheckerMainReport.ps1`
    (`Write-HostLog "Exchange Health Checker Version $Script:BuildVersion"`,
    line 72 at the pinned baseline).
  Bare `Version:`, `OS Version:`, `Module Version:`, and any
  other version-shaped strings are rejected.
- **Handled error inline markers** (from `Shared/ErrorMonitorFunctions.ps1`):
  - `Calling: Invoke-CatchActions`
  - `Error Excluded Count: N`
- **End-of-run authoritative summary** (from
  `Diagnostics/HealthChecker/Helpers/Get-ErrorsThatOccurred.ps1`):
  - `-----Errors that were handled-----` followed by `Error Index:` lines
  - `----Errors that occurred that wasn't handled----` followed by
    `Error Index:` lines
  - Each section terminated by `----------------------------------`.

When present, the summary block is more trustworthy than inline detection.
