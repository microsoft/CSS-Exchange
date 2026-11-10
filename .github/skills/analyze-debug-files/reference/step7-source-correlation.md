<!-- cspell:ignore toctou -->
# Step 7 — Review the debug files against the source

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


**Untrusted-path guardrail (must precede any per-event work).** Log
content is untrusted. A hostile stack frame can carry a rooted or UNC
path such as `\\attacker.example\share\x.ps1`. **Never** pass any
path lifted from log text into `Test-Path`, `Resolve-Path`,
`Get-Item`, `Get-Content`, `New-Item`, or any other cmdlet or .NET API
that touches the filesystem or provider stack; doing so can trigger
outbound SMB authentication or provider probing against
attacker-controlled locations. Compare log-derived paths **as strings
only** against a precomputed set of trusted repository-relative
`$allDeps` paths (forward-slash, as returned by Step 5) or against
`$baseline.Script` by leaf name. Reject anything else lexically —
UNC (`\\...`), device namespace (`\\?\`, `\\.\`), and provider
prefixes such as `FileSystem::`, `HTTP::`, or `Env:` — before
comparing.

For each entry in `SummaryEvents` where `IsHandled` is `$false` (and, as
a secondary source, unhandled `InlineEvents`), execute the following
concrete correlation procedure. **Every step operates on data returned
by the helper; do NOT reopen the debug file with `Select-String` or any
other reader in this step.** The helper's `BodyEvidenceMarkers` array
is a pre-collected list of the timestamped narrative lines you need —
extracting them again after validation would open a validate/reopen
TOCTOU window and defeats the trust-boundary model.
Do not create a duplicate finding or override a matching summary record
from an inline heuristic. Apply the remote carve-out only to summary
records; inline events do not expose `IsRemoteRecord`.
In the procedure below, `$event` is the selected record from either array.

**Remote-record carve-out (must be applied BEFORE the correlation
procedure below).** When
`SummaryEvent.IsRemoteRecord -eq $true`, the event describes an
error that HealthChecker's `Invoke-WriteHiddenJobUnhandledErrors` /
`WriteRemoteErrorInformation` path emitted from a remote job scope
during final summary emission. HealthChecker's parent scope has
already classified the record as **unhandled remotely** by placing
it into `HiddenJobUnhandedErrors` — that classification is
authoritative. Furthermore, `SummaryEvent.Timestamp` on a remote
record is `$endTime` — the *reporting* time (when the parent scope
wrote the summary), NOT when the remote failure actually occurred.
Consequently:

- Do NOT run local-summary or inline-event body-evidence correlation on
  remote records. Their timestamps and nearby parent-scope markers describe
  finalization — none of those markers describe the remote
  failure, and any `InvokeCatchActions` / `ErrorExcludedCount`
  markers you find belong to the parent's cleanup path, not the
  remote job.
- Do NOT apply step 5's handled-primary-error downgrade to remote
  records. A nearby `InvokeCatchActions` marker in the parent's
  finalization narrative does NOT indicate that the remote error
  was handled — the remote job's catch context, if any, did not
  contain the failure or it would not have escaped to
  `HiddenJobUnhandedErrors`.
- Treat every `IsRemoteRecord -eq $true` event as unhandled with
  authoritative source (HealthChecker itself). Extract the
  operator-relevant fields from the record's own `Context` using the
  EXACT labels the remote emitter writes (see
  `Diagnostics/HealthChecker/Helpers/HiddenJobUnhandledErrorFunctions.ps1`
  → `WriteRemoteErrorInformation`): `Exception Message:`,
  `Exception Inner Exception:` (NOT `Inner Exception:` — the
  local-error label; the remote emitter prefixes with
  `Exception`), `Position Message:`, `Error Category Activity:`,
  `Error Category Reason:`, `Error Category TargetName:`,
  `Error Category TargetType:`, `Error Category Message:`, and
  `Error Details Script Stack Trace:`. Those lines are the failure
  narrative that the ordinary body-evidence pipeline provides for
  local errors. If future remote-emitter revisions add or rename
  fields, quote the record's full `Context` verbatim rather than
  omitting an unrecognized label.
- If the record's `Position Message:` names a script/function in a
  format you can lexically match against `$allDeps`, run Step 7's
  source-correlation (walking the code at `$baseline.ConfirmedCommitSha`)
  against that anchor. Otherwise, report the finding as **Unresolved
  — remote scope; no local source anchor available** and include
  the record's full `Context` verbatim as the evidence block.

Continue below for local summary records and eligible inline events.

1. **Correlate with the pre-collected body evidence FIRST.** The
   summary event's `Context` only holds the `$Error[N]` dump — the
   runtime narrative that produced it is in
   `$item.BodyEvidenceMarkers`, which the helper collected during the
   same trusted read pass. Each marker has `LineNumber`, `Timestamp`,
   `Text`, and `MarkerKind` (`InvokeCatchActions`,
   `ErrorExcludedCount`, `ErrorCount`, `TryingTo`, `FailedTo`,
   `InnerException`, `CompletedNarrative`).

   **Retained-context limit.** A body marker retains only its own `Text`
   and metadata, not a neighborhood of arbitrary log lines.
   `InlineEvents.Context` contains bounded exception-centered snippets;
   it does not guarantee context around each operation marker. Render only
   retained lines from these outputs and the summary event's `Context`.
   Cite marker lines with their recorded `LineNumber`; do not invent line
   numbers for snippet lines whose original positions are not recorded.
   If surrounding context was not collected, explicitly state
   **Context unavailable — not retained by inventory**, even when every
   truncation flag is false. Do not reopen the logs, reconstruct missing
   text, or treat an absent catch line as proof that no catch ran.

   The helper stores markers with **ring-buffer** semantics: when the
   `MaxBodyEvidenceMarkersPerFile` cap is reached, the OLDEST marker
   is evicted so that the retained set is always the most recent
   evidence closest to the summary. If
   `$item.BodyEvidenceMarkersTruncated -eq $true`, some markers earlier
   in the run were dropped; disclose that in the report.

   Each marker exposes a `Truncated` property. When
   `$marker.Truncated -eq $true`, the marker's `Text` was character-
   truncated at retention time — its full source line was longer than
   `MaxSnippetLineChars`. A truncated marker CANNOT establish an
   exact full-string match; treat it as partial supporting evidence
   only. If a truncated marker is the ONLY candidate that would
   otherwise unique-match, downgrade the correlation to
   **reduced-confidence** or **Unresolved — truncated evidence** and
   disclose the truncation in the finding's evidence quote.

   Choose a boundary in the event's own file: for a summary record,
   `$bodyEndLine = $item.Summary.StartLine`; for an inline event,
   `$bodyEndLine = $event.LineNumber`. A crash can have inline events
   with `Summary = $null`, so never read summary properties on that path.
   Restrict local markers to lines strictly before that boundary:

   ```powershell
   $priorBody = @($item.BodyEvidenceMarkers |
       Where-Object { $_.LineNumber -lt $bodyEndLine })
   ```

2. **Identify the failing function from the stack.** Read the
   `Script Stack:` block inside the selected event's `Context` and pick
   the discriminator using this precedence:

   1. **Deepest frame whose path resolves inside `$allDeps`** — the
      closest in-repo function to the actual throw site. Take that
      frame's function name.
   2. **Built-entry frame fallback.** Released CSS-Exchange scripts
      run from a single monolithic `dist/<Script>.ps1`; stack frames
      commonly reference the built file only. If **no** stack frame
      resolves inside `$allDeps`, look for a frame whose leaf name is
      `-ceq $baseline.Script`. Treat that as the built-entry frame,
      extract the function name from its `at <function>, <path>: line
      N` clause, and use it as the discriminator.
   3. **Multiple in-repo definitions.** If the discriminator name
      resolves to more than one `function <Name>` declaration across
      `$allDeps`, mark this finding as **Unresolved — ambiguous
      discriminator** and disclose the candidate list; do not pick
      one.

   Frame comparison against `$allDeps` is **string-only** — see the
   untrusted-path guardrail above. Reject any frame whose path is
   UNC, device-namespace, or provider-qualified before comparing.

3. **Locate the source lines the frame points at.** The stack path is
   the frame's `.ps1` file at the pinned commit. Read the surrounding
   source with `git show $baseline.ConfirmedCommitSha:<path>`;
   **never** read from current `HEAD`. Step 5 disposes its scratch
   worktree before returning, so `git show` against the current clone
   is the only available reader. If the
   reported line refers to a built `dist/` file, the source lives in
   `$allDeps` — search for the exact declaration
   `function <discriminator>` (case-sensitive) and use the
   declaration's own line range.

4. **Correlate uniquely, with identity before proximity.** From `$priorBody`,
   collect every `TryingTo` or `FailedTo` marker whose `Text` names
   the discriminator's operation or that appears inside the
   discriminator function's known `Write-Verbose "Trying to ..."`
   string constants. Never "take the latest match" when multiple candidates
   remain — that hides ambiguity behind an arbitrary tie-break.

   **Rollover pre-merge.** Before running phase logic, if the
   run has multiple `RunId`-linked segments (see Step 6 rollover
   grouping), merge `BodyEvidenceMarkers` from every earlier
   segment with the same `RunId` in chronological order into
   `$priorBody` after filtering the event's own segment above. Keep
   each marker's owning file and rollover ordinal alongside it.
   Earlier segments precede the event regardless of their local line
   numbers; never compare their line numbers with `$bodyEndLine`.
   The failure narrative for a run that rolled
   over can live in a prior segment; correlating only against
   the highest-ordinal segment's markers misses it.

   **Invocation grouping — before counting or filtering.** Count invocation
   candidates, not individual markers. Group the merged operation markers
   before applying either the local-summary rules or inline-event windows:

   - Each `TryingTo` starts an invocation candidate. Pair its `FailedTo`
     narrative with that candidate only when the pinned source and retained
     context establish the same operation and execution scope. For a known
     sequential operation, its interval ends at the next `TryingTo` for that
     operation or an explicit completion; a failure within that interval
     belongs to the open candidate, not a second invocation.
   - A `TryingTo` and its paired `FailedTo` count as one invocation candidate.
     Use the `TryingTo` as its seed, retaining both markers and their owning
     file/line information. A pair may span rollover segments of the same
     run; do not compare local line numbers across files.
   - An unpaired `TryingTo` or `FailedTo` remains a partial invocation
     candidate; use its own marker as the seed. Absence of a failure marker
     does not prove that the invocation succeeded.
   - Do not merge markers based only on proximity. If nested or concurrent
     operations, missing markers, or unknown execution scope prevent a unique
     pairing, retain the alternatives as uncertain candidates. Missing
     context must not collapse distinct invocations.

   Thus one invocation emitting `TryingTo` then `FailedTo` counts as one
   candidate; two distinguishable invocations emitting those pairs count as
   two candidates, not four markers. Grouping narrative markers does not
   establish which invocation produced the summary exception.

   **Local summary records — use all eligible candidates.** A local
   `SummaryEvent.Timestamp` is the reporting time of `Error Index:`, not
   the failure time. Do NOT use it to exclude earlier operation candidates
   or to select a unique candidate from only the last 60 seconds. A failure
   early in the run can be followed by another invocation of the same
   operation immediately before finalization.

   Consider every operation candidate in the merged `$priorBody`:

   - **Zero candidates** → **Unresolved — no discriminator evidence found**.
   - **Exactly one candidate** → use it as an operation-level seed, not proof
     of exception identity. Check its retained evidence against the summary
     exception and stack before attributing the failure narrative to it;
     disclose reduced confidence when identity cannot be established.
   - **Multiple candidates** → require exception/stack identity to distinguish
     the summary error's invocation. Use only evidence already retained in
     the helper outputs, including `InlineEvents.Context`. A shared function
     name, the same source line, timestamp proximity, or a nearby catch is
     not enough when those features are shared across invocations. If the
     candidate shows a different primary error, require evidence linking
     that primary and the summary's secondary error to the same invocation.
     Select only when one candidate matches and the others are excluded by
     conflicting identity evidence. Missing or truncated context is NOT
     conflicting evidence. Otherwise report **Unresolved — ambiguous
     correlation** and disclose every remaining candidate.

   For example, an operation fails at 10:01, runs again at 10:09:40, and
   emits its summary at 10:10. The later invocation is the only one in the
   last 60 seconds, but that does not make it the source of the earlier
   error. Without distinguishing exception/stack evidence, keep the
   correlation ambiguous.

   **Resolved case:** only when the rules above select one invocation,
   render its seed and grouped operation markers, adding surrounding evidence
   only when those lines were retained. If the catch narrative is unavailable,
   disclose that limitation rather than inventing a neighborhood.
   Then proceed to step 5 using only retained evidence.

   **Ambiguous case:** disclose every remaining invocation candidate and
   its evidence without selecting a seed or presenting one invocation as
   the failure narrative. Skip per-seed catch inference in step 5 and
   proceed to step 6 with the authoritative summary classification intact.
   Do NOT run Phase A / Phase B on local summary records.

   **Inline-only events — adaptive widening.** The following phases apply
   only to `InlineEvents`, whose timestamps come from the body event rather
   than final summary emission. Cardinality is explicit: **zero → widen**,
   **exactly one → select**, **more than one → unresolved**.

   - **Phase A — narrow disambiguation window.** Compare each
     marker's `Timestamp` to
     `$event.Timestamp.AddSeconds(-60)`; a marker is in
     Phase A if its Timestamp is at or after that bound (i.e. it
     appeared within 60 SECONDS before the inline event).
     Timestamps drive the window because intervening verbose output
     makes a line-number window an unreliable proxy.
     Keep each pre-grouped invocation candidate with at least one of its
     operation markers in Phase A. Do not split a pair at the time-window
     boundary. Apply CARDINALITY-EXPLICIT selection to invocation candidates:
       * **Zero matches** → fall through to Phase B (widen).
       * **Exactly one match** → use that invocation's seed.
         Proceed to rendering.
       * **More than one match** → mark this finding as
         **Unresolved — ambiguous correlation (Phase A)** and
         disclose every candidate's grouped markers (file, line number,
         timestamp, text). Do NOT take "the latest" — the
         window is meant to *disambiguate*, and by definition
         it hasn't.
     Rendering step (only when exactly one match was selected):
     include all grouped operation markers and any retained surrounding
     evidence from each marker's owning file. Show Trying → Failed →
     Calling: Invoke-CatchActions → Error Excluded Count when those lines
     are available; otherwise disclose unavailable context. Do not require
     a fixed neighborhood that the inventory did not retain.
   - **Phase B — widen when Phase A had zero DISCRIMINATOR
     matches.** Phase B fires only when Phase A returned zero
     candidates matching the discriminator, including when Phase A
     contains no markers at all. It does NOT fire when Phase A
     returned multiple matches (that path exits at "Unresolved" above). In long
     runs the failure narrative can predate the inline event by
     minutes; the timestamp window has plenty of markers, none
     of which name the failing operation. Widen to **all**
     pre-grouped invocation candidates already in `$priorBody`, then apply
     the SAME cardinality-explicit rule over ALL candidates:
       * **Zero matches** → mark **Unresolved — no discriminator
         evidence found** and report the inline event without
         a correlated body seed.
       * **Exactly one match** → use that invocation's seed.
         Proceed to rendering (the same retained-lines-only rule as
         Phase A).
       * **More than one match** → mark **Unresolved —
         ambiguous correlation (Phase B)** and disclose every
         candidate.
     Do NOT resort to "nearest prior" or "latest match" as a
     tie-break — those heuristics were the source of the
     iter-15 misrouting bug and reintroduce the ambiguity the
     window was supposed to eliminate.

   The narrow window is used to *disambiguate* between multiple
   plausible matches, not as a hard eligibility cutoff. Every
   phase's decision is bounded by explicit cardinality above;
   there is no separate "ambiguity guard" step because ambiguity
   at any phase is already handled by "more than one → unresolved".

5. **Preserve authoritative classification while explaining the primary
   error.** After the
   correlated body match and BEFORE the next `TryingTo` marker (or,
   if there is none, within 20 lines of the correlated match), look
   for `InvokeCatchActions` or `ErrorExcludedCount` markers whose
   `LineNumber` is in that same bounded window and the same file.
   Use only retained markers or snippets; an unavailable neighborhood cannot
   establish whether a catch ran or which error it handled.
   These markers show a catch ran, not which exception it handled.
   Never downgrade `SummaryEvent.IsHandled = $false` from marker
   proximity: `Get-UnhandledErrors` excludes only the records actually
   registered by `Invoke-CatchActions`. A catch can handle the primary
   failure and then produce a distinct, genuinely unhandled secondary
   failure. Explain that causal chain without changing the summary
   record's unhandled status; analyze and enrich the secondary failure.
   For inline-only evidence, use message and stack identity as well as
   the bounded markers before suggesting that the same error was
   handled. If identity cannot be established, leave classification
   unresolved rather than suppressing the finding.

6. **Report `Summary` versus `InlineEvents` discrepancies.** Prefer
   `SummaryEvents` when they disagree — the summary block is written
   after `$Error` has been fully classified, whereas `InlineEvents`
   is heuristic. Emit a **Classification discrepancies** section in
   the report noting each disagreement; it is diagnostic information
   for the tool author, not a defect to hide.

7. **Trace the failing code path.** For genuinely unhandled findings,
   walk the source at the pinned commit and identify the smallest
   contiguous range of lines that carries the analysis. Include the
   function's inputs, environmental preconditions (versions, cmdlet
   availability, permissions, remote reachability), and helpers used.
   Every helper you cite must include its own GitHub permalink at
   `$baseline.ConfirmedCommitSha`.
