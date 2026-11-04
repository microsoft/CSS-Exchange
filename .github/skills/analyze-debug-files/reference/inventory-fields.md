# Step 1a — Early-stop rule and inventory fields

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


Immediately after `Get-DebugFileMetadata.ps1` returns and before doing
any further work, decide whether the directory actually contains
recognizable CSS-Exchange script debug output.

Rule: if the inventory produces zero files whose `ScriptNameConfidence`
is `High`, print the early-stop message and STOP the
skill. Do not proceed to Step 2. Do not prompt for anything. Do not
write a report. Do not explore the directory further.

**The exact message text lives in `SKILL.md` Step 1a and is not restated
here.** Copy it verbatim from there — two copies of a user-facing literal
drift, and the wrong one eventually gets printed.

Otherwise, continue with Steps 2-8. For each entry in `$inventory.Files`,
note:

- `Status` — Parsed / Empty / Oversize / Unreadable / UnsupportedFormat.
  Skip anything not `Parsed`, but report the counts so the user knows what
  was excluded.
- `ScriptName` + `ScriptNameConfidence`. `ScriptNameConfidence` is
  exactly one of `High` (the filename matched a known CSS-Exchange
  debug-log shape) or `None` (it did not, and `ScriptName` is
  `$null`). There is no intermediate confidence level — do not write
  logic that tests for one.
- `LineCount` — total lines read from the file. Use it to decide
  whether a `CompletionSignals[].LineNumber` is "near the end of the
  log"; the helper records the LAST line on which each signal fired.
- `VersionCandidates` — collection.
- `Summary` — authoritative handled/unhandled counts if present.
- `MultipleRunsDetected` — repeated summary headers or a later logger
  invocation indicate concatenated runs. Apply Step 6's mandatory ambiguity
  gate before trusting completion or correlating source.
- `MultipleSummaryBlocksDetected` — the narrower repeated-summary-header
  flag; it can be false when the later invocation crashed before reporting.
- `SummaryEvents` — per-error dumps from the summary block; each entry has
  `IsHandled`, `IsRemoteRecord`, `LineNumber`, `Timestamp`, `HeadLine`,
  `Context`
  (sanitized body lines), `ContextLineNumbers` (parallel `int` list —
  one line-number per retained `Context` entry, with the actual
  source line number at retention time; do NOT compute line numbers
  as `OriginalStartLine + index` because character omissions and
  budget-driven skips make that arithmetic wrong once
  `OmittedLineCount > 0`), `ContextTruncated`, `OriginalStartLine`,
  `OriginalEndLine`, `OmittedLineCount`, `TruncatedLineNumbers` (line
  numbers whose retained text was character-truncated),
  `LinesCharacterTruncated` (count), `TerminationLineNumber` (line
  number of the record's terminating boundary — either the next
  `Error Index:` header, the timestamped
  `----------------------------------` footer, the next section
  header (`-----Errors that were handled-----` /
  `----Errors that occurred that wasn't handled----`), or 0 if the
  record ran to EOF), `TerminationLineText` (sanitized text of that
  boundary line), and `TerminationKind` — which boundary actually
  fired, one of `Footer`, `NextErrorIndex`, `NextRemoteRecord`,
  `SectionHeaderTransition`, or `EOF`.

  **`TerminationKind` decides boundary inclusion, and getting it
  wrong misquotes the record.** `Footer` and `EOF` are INCLUSIVE (the
  boundary line belongs to the section and closes the run of errors),
  whereas
  `NextErrorIndex`, `NextRemoteRecord`, and `SectionHeaderTransition`
  are EXCLUSIVE (the boundary line is the FIRST line of the NEXT
  record and must NOT be quoted as part of the current record).
  `NextRemoteRecord` fires when one remote-error record terminates
  because the NEXT `----Remote Error Information----` header was
  encountered — semantically equivalent to `NextErrorIndex` but for
  the remote section. `SectionHeaderTransition` includes the
  `----Errors that occurred that was not handled remotely----`
  header among its recognized boundaries. `EOF` sets
  `TerminationLineNumber = 0` and the record's own
  `OriginalEndLine` is authoritative. This is the authoritative
  record of unhandled and handled exceptions.
- `CompletionSignals` — end-of-run markers that were detected. See Step 6.
  `NoErrorsMessage` is retained only when the rest of the file contains
  blanks or HealthChecker's valid timestamped total-runtime trailer;
  later work or failures invalidate an earlier no-errors hit.
- `InlineEvents` — best-effort per-event snippets with `IsHandled`. The
  bounded ring buffer retains the most recent events in original order.
- `InlineEventsTruncated` — older inline events were dropped. Disclose
  partial coverage and follow Step 6's rerun guidance.
