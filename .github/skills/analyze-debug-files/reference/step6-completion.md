# Step 6 — Determine whether the script completed

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


The completion classifier below is **HealthChecker-flavored**: it depends
on the markers written by `Shared/ErrorMonitorFunctions.ps1` and the
HealthChecker helper `Diagnostics/HealthChecker/Helpers/Get-ErrorsThatOccurred.ps1`.

**Apply the Step 6 dependency gate from `SKILL.md` before using this tree.**
That gate — leaf-name matching against `$allDeps`, and the `PartialGraph`
carve-out — is stated once in `SKILL.md` Step 6 and is not restated here.
If the gate says completion is **Unknown**, stop: do not run the tree below.

**Section lifecycle model.** `Get-ErrorsThatOccurred.ps1` always emits
both the handled section AND the unhandled section back-to-back, each
closed by its own timestamped
`----------------------------------` footer. The helper exposes each
section's boundaries so the classifier can distinguish a run that
finished the summary from one that was terminated mid-report:

- `Summary.HandledHeaderLine`   / `Summary.HandledFooterLine`
- `Summary.UnhandledHeaderLine` / `Summary.UnhandledFooterLine`
- `Summary.RemoteUnhandledSectionSeen` / `Summary.RemoteUnhandledFooterLine` —
  HealthChecker emits an OPTIONAL continuation of the unhandled section
  when `Test-HiddenJobUnhandledErrors` is `$true`: after the ordinary
  `----Errors that occurred that wasn't handled----` block closes, it
  writes `----Errors that occurred that was not handled remotely----`
  followed by one or more `----------------Remote Error Information----------------`
  records and a second dashed footer. The runner tracks the remote
  section separately so `SummaryComplete` can require its footer when
  the remote header was observed. `Summary.UnhandledCount` includes
  BOTH ordinary `Error Index:` records AND remote records; the latter
  carry `IsRemoteRecord = $true` on their `SummaryEvent` entries and
  are assigned `$endTime` — the last log timestamp observed before the
  record — as their `Timestamp`. The record head line itself has no
  timestamp (HealthChecker prefixes the record body with
  `\r\n\r\n` inside a single `Write-Verbose` call, so the logger's
  `[timestamp] : ` prefix lands on the leading blank line and the
  `----Remote Error Information----` header line inherits nothing).
  `$endTime` therefore advances between successive `Write-Verbose`
  calls — each remote record is written by its own call, so records
  in a single remote section carry the timestamps of the successive
  Write-Verbose invocations that emitted them (not one shared
  timestamp for the whole section).
- `Summary.SummaryComplete` — `$true` when the handled footer AND the
  unhandled footer are present, AND — if `Summary.RemoteUnhandledSectionSeen`
  is `$true` — the remote footer is also present. Only blank lines or the
  valid timestamped total-runtime trailer may follow the final footer;
  later work or failures invalidate completion. This is the strongest
  end-of-run signal. `Summary.FooterSeen` is a legacy alias with the
  same value.

Apply the multi-run ambiguity gate before classification. For a rollover
group, apply the rollover rules below before this per-file decision tree;
an Unknown rollover result must not fall through to a per-file CRITICAL rule.
For other Parsed files, apply this ordered decision tree:

1. **`Summary.SummaryComplete -eq $true`** →
   - `Summary.UnhandledCount -eq 0` AND `Summary.HandledCount -eq 0`
     → **Completed cleanly (no errors)**.
   - `Summary.UnhandledCount -eq 0` AND `Summary.HandledCount -gt 0`
     → **Completed with handled errors** — all exceptions were caught.
   - `Summary.UnhandledCount -gt 0` → **Completed with unhandled
     errors** — route unhandled `SummaryEvents` into Step 7. Use
     `Summary.UnhandledCount` for severity.
2. **`Summary -ne $null` AND `Summary.SummaryComplete -eq $false`** →
   **Summary present without terminal completion.** A matching footer is
   missing, or later non-trailer content invalidated a closed summary.
   Mark **CRITICAL** and disclose that summary counts do not cover the
   entire log. Report any missing footer among
   `HandledFooterLine`, `UnhandledFooterLine`, and — when
   `RemoteUnhandledSectionSeen -eq $true` — `RemoteUnhandledFooterLine`.
   When all required footers exist, explain that later activity invalidated
   completion instead of claiming a footer is missing.
3. **`Summary -eq $null` AND `CompletionSignals` contains
   `NoErrorsMessage`** →
   **Completed cleanly (no errors)**. `Get-ErrorsThatOccurred` took
   its early-return path (`$Error.Count -eq 0`), which prints
   *"No errors occurred in the script."* and returns. No summary
   block is expected on this path — the emitted message IS the
   terminal end-of-run signal. The helper retains this hit only when
   every later line is blank or the valid timestamped
   `The total script time took <seconds> seconds` trailer emitted by
   HealthChecker. Any other later content, including another invocation
   or a failure without a timestamp, invalidates the hit. Do not recover a
   discarded early message and classify it as completion evidence.
4. **`Summary -eq $null` AND `CompletionSignals` contains
   `AllErrorsHandledMessage`** →
   **INCOMPLETE, treat as CRITICAL** (subject to the note below).
   `AllErrorsHandledMessage` is emitted BEFORE `Write-ScriptDebugObject`
   and `Write-Errors`. On this code path both summary sections are
   expected to follow. If they never appear, the script was
   terminated mid-finalization: the debug object may or may not have
   been written and the summary was never opened. The message is a
   progress signal, not a completion signal.
   *Exception*: if this classification would surprise the operator
   (for example, a run truncated by an out-of-band shutdown they
   already know about), lower the severity to **Warning** in the
   report while keeping the "incomplete" label.
5. **`Summary -eq $null` AND `CompletionSignals` contains
   `WritingScriptDebugObjects` only** →
   **Progress signal without confirmed end-of-run.** The helper
   reached its diagnostic-dump phase but did not print the terminal
   message. Mark as **Warning** — the run is likely complete but the
   final marker is missing.
6. **No `Summary` and no `CompletionSignals`** → **DID NOT COMPLETE —
   CRITICAL**. The script crashed, was terminated, or exited before
   its end-of-run reporting could run. Any partial results should be
   treated as suspect.

**Rollover grouping.** When multiple files share the same `RunId`
(different `RolloverOrdinal` values), they represent one execution
split across segments. Inspect the retained `Summary`, `CompletionSignals`,
and section-boundary fields across all segments before classifying the run.
`Write-LoggerInstance` appends a message before checking size and switching
files. A final footer or no-errors message can therefore be in an earlier
segment, followed by the rollover notice, while the highest-ordinal segment
contains only the later runtime trailer.

- If the highest-ordinal segment has self-contained terminal evidence
  (`Summary.SummaryComplete = $true`, or a retained terminal
  `NoErrorsMessage` with no summary), apply the ordered tree to that segment.
- Otherwise mark the run **Unknown — finalization may span rollover
  segments**. Do not infer CRITICAL or DID NOT COMPLETE merely because the
  last segment has no completion markers or has a partial summary. The
  inventory does not carry parser state or every intervening line across
  segment boundaries, so it cannot generally prove cross-segment terminal
  completion. Disclose the earlier section boundaries/signals that were
  retained, any missing segments, and the lack of self-contained terminal
  evidence rather than claiming the script stopped.
- Preserve observed errors as findings, but label counts from split sections
  as partial observations with their owning segment. Do not sum overlapping
  per-file counts or claim a whole-run total from partial summaries.

For Step 7, analyze each retained event in its owning segment and merge
`BodyEvidenceMarkers` from earlier segments chronologically as specified
there. Unknown completion does not suppress observed unhandled errors.

**Remote-section rollover caveat.** The remote-unhandled section is
emitted as a series of independent `Write-Verbose` calls (one for
the section header, one per `WriteRemoteErrorInformation` record,
one for the closing footer) during script finalization, when the
log is typically far smaller than the rollover threshold. However,
if the logger rolls a segment MID-section, the state-machine flag
`$currentUnhandledIsRemote` established by the section header does
not carry into the next segment: records in the new segment start
with `summaryState = 'none'` and their `----Remote Error
Information----` heads will not be recognized as remote records,
and the highest-ordinal segment can report `SummaryComplete = $false`
because its earlier segments hold the section footers. A run whose earlier
segments show
`RemoteUnhandledSectionSeen = $true` but whose highest-ordinal
segment shows `RemoteUnhandledSectionSeen = $false` may have split finalization,
not necessarily an interrupted run. Apply the Unknown rollover rule when
terminal evidence is not self-contained, and disclose that the observed tally
may omit remote records. Do NOT attempt to reconcile the tally
across segments — the per-segment records may or may not overlap,
and merging state is out of scope for this skill.

**Aggregate report status when there are multiple `RunId` groups.**
Emit a per-`RunId` completion/count table in the report (see
`Report Format` — `Runs` section). The single document-level
`Completion Status` blockquote reflects the **worst** status across
runs, and names the specific `RunId` that produced it. This prevents
a single interrupted run from being masked by earlier clean runs.

**Multiple runs in a single file.** `MultipleRunsDetected` is `$true` when
the helper sees repeated summary headers OR another logger invocation
after an earlier logger start, summary, or terminal no-errors message.
This catches a later crashed invocation even when it never opens a
second summary. `MultipleSummaryBlocksDetected` remains the narrower flag
for repeated summary headers. Counts describe only the last observed
summary block, while `SummaryEvents` accumulates records from all blocks;
neither identifies which invocation the operator wants. Treat the input
as ambiguous.

**Runner enforcement (mandatory).** The runner MUST, before invoking
Step 7 source correlation on any file, check
`$file.MultipleRunsDetected`. When `$true`, do not apply the ordered tree:

1. Do NOT run Step 7 source correlation for that file. Correlating
   body-evidence markers against a summary event whose surrounding
   block boundaries are unknown routes evidence to the wrong run.
2. Classify the file's completion as `Unknown` in Step 6 and note
   in the `Runs` table that multi-run detection blocked
   correlation.
3. Surface the flag prominently as `Multiple runs: yes` in the
`Inventory` table and add a `Multi-run caveat` note in the
report body naming the affected file and available summary
header/event line numbers. If `Summary` is null, report the
multi-run flag without dereferencing summary properties.
4. Prefer `ask_user` for confirmation of which run to analyze; if
   the user cannot disambiguate, skip source correlation for that
   file entirely and report only available parsed evidence. When
   summary counts exist, disclose that they describe the last
   observed block rather than every invocation.

Do NOT merge counts across blocks. Do NOT assume the last block is
"the one that matters" — the earlier blocks may contain the failure
the operator wants to investigate.

**Truncation gates.** If any parsed file reports
`UnhandledEventsTruncated -eq $true`, the number of unhandled records
in the log exceeded the helper's cap (default 200) and the analysis
CANNOT cover every unhandled exception. Rerun the helper with a
larger `-MaxUnhandledSummaryEventsPerFile` (and communicate the new
cap in the report) rather than producing an "everything analyzed"
report from a subset. The same rule applies to
`HandledEventsTruncated`, `BodyEvidenceMarkersTruncated`, and
`AnyLineTruncated`: state the reduction explicitly in the report
rather than asserting full fidelity.

`InlineEventsTruncated` means the inline ring buffer dropped older events.
It retains the most recent events, not every exception. Disclose the loss;
for inline-only crashes, rerun with a larger `-MaxInlineEventsPerFile`
(maximum 100) when possible. If events still exceed the cap, mark coverage
as partial rather than asserting every unhandled exception was analyzed.
