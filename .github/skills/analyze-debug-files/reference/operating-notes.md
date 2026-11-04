# Operating notes

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


- This skill is read-only relative to the caller's repository. On cache
  miss `Get-BaselineDependencyGraph.ps1` creates a temporary local git
  worktree, builds the dependency graph in it, and normally disposes it before
  returning. Cleanup failures warn with the retained path; disclose them in
  the report's `Notes`. Steps 6-8 never depend on a scratch path. It also populates
  a per-user, per-SHA dependency cache under
  `$env:LOCALAPPDATA\CSS-Exchange\dependency-cache\` so subsequent
  runs against the same baseline SHA skip the worktree build. On
  cache hit no worktree is created. Either way the skill writes
  exactly one report artifact — `DebugAnalysis-<timestamp>.md`, or
  `DebugAnalysis-<timestamp>-<8hex>.md` on a same-second collision —
  into the caller's debug directory (`$inventory.DebugDirectory`).
  It never rewrites the input logs.
- **Stay inside the analyzed script's scope.** Read the SYNOPSIS /
  DESCRIPTION at the pinned commit. If a stack frame implicates a
  third-party or out-of-scope module, do not recommend changes there.
  Route the resolution through the analyzed script (defensive code, a
  precondition check, or an environment prerequisite the script needs)
  or clearly label an environment-side investigation for the script's
  supported target.
- **Quote the full exception**, not a trimmed excerpt. For every finding,
  include the entire `----------------Error Information----------------`
  block from the debug file — message, `Inner Exception`, `Position
  Message` (with the caret line), and every `Script Stack:` frame.
  Redact only sensitive values (user profile paths, tenant IDs, machine
  names, email addresses, module GUIDs); everything structurally
  relevant to the failure stays intact. The summary event's `Context`
  field carries these lines verbatim.
- **Source citations must be GitHub permalinks against the pinned
  `ConfirmedCommitSha`**, never against `main` or a tag name. Format:
  `https://github.com/<Owner/Repo>/blob/<ConfirmedCommitSha>/<path/from/repo/root>#L<start>-L<end>`.
  Pin the smallest range that carries the analysis. The commit SHA is
  immutable; tag names are not.
- **Always correlate summary events with the body of the log.** The
  `SummaryEvents` `Context` field contains only the `$Error[N]` dump.
  The narrative around the failure — `Write-Verbose` lines with variable
  values, `Calling: Invoke-CatchActions` markers, `Error Excluded Count:` /
  `Error Count:` markers — lives in the timestamped body of the log
  before the summary block. Use only the markers and context retained by the
  inventory before drawing a conclusion. Missing surrounding lines are
  unavailable evidence, even without a truncation flag; never reopen the log
  or reconstruct them.
- Handled/unhandled classification via `InlineEvents` is a heuristic. Prefer
  `Summary` and `SummaryEvents` when present. Always confirm against source
  code at `$baseline.ConfirmedCommitSha` before declaring an event
  unhandled.
- **Completion detection** relies on markers written by
  `Shared/ErrorMonitorFunctions.ps1` and the HealthChecker
  `Get-ErrorsThatOccurred` helper. Scripts that do not use those helpers may
  produce false "did not complete" results; if the user identifies a script
  outside this pattern, ask before flagging critical.
- Some scripts write large debug files. `Get-DebugFileMetadata.ps1` streams
  files with a 25 MB per-file cap and a 500 MB cumulative cap by default;
  raise `-MaxFileSizeMB` / `-MaxDirectoryTotalMB` only when the user asks.
  Parsing is a single-threaded streaming scan that applies a regex battery
  per line; measured throughput is roughly **5 seconds per MB**, so a
  directory at the default 500 MB cumulative cap can run for tens of
  minutes. The helper emits `Write-Progress` per file — do not mistake a
  long run for a hang, and warn the user before raising the caps.
- `Get-DebugFileMetadata.ps1` sanitizes each surfaced log line (control
  characters stripped, per-line length capped). Do not undo this by
  re-reading raw content into the report.
