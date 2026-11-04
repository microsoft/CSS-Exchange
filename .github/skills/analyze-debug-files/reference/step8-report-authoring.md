# Step 8 — Write the analysis report

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


The finalized report is written into `$inventory.DebugDirectory` — the
same directory the caller supplied. No staging, no separate persistent
destination, no sidecar file.

**Contract:**

1. Build the report as a single in-memory string using the layout in
   `reference/report-format.md`. Keep the generator interpolation-free
   (see the safe-scalar guidance later in this section); do not stream
   partial writes.
2. Hand that string to `Write-DebugAnalysisReport.ps1`. Do **not**
   hand-roll the filename, the collision handling, or the write — that
   logic lives in the helper so it is covered by PSScriptAnalyzer, the
   repository formatter, and Pester.

   ```powershell
   $writeArgs = @{
       DebugDirectory = $inventory.DebugDirectory
       ReportText     = $reportText
   }
   $written = & .\.github\skills\analyze-debug-files\Write-DebugAnalysisReport.ps1 @writeArgs
   ```

   The helper returns `Path`, `FileName`, `BytesWritten`, and `Collided`.
   It guarantees the following, so the runner does not re-implement any
   of it:

   - The artifact is named `DebugAnalysis-<yyyyMMddHHmmss>.md`. On a
     same-second collision it appends 8 hex characters from a fresh
     GUID and retries; `Collided` reports whether that happened.
   - The write uses `[System.IO.FileMode]::CreateNew`, which fails
     atomically rather than overwriting. `File::WriteAllText` /
     `File::WriteAllBytes` are deliberately NOT used — both truncate an
     existing destination. No `CreateFileW` or P/Invoke scaffolding, and
     no `<report>.sha256` sidecar.
   - `DebugDirectory` is re-validated as a real local directory before
     any write, because the helper is an independent entry point.
   - The report text is rejected outright if it contains any control
     character other than tab, CR, or LF (see **No stray C0/C1
     controls** below). The helper throws instead of persisting it.
   - Existence is verified after the write.
   - Output is UTF-8 **without** a BOM.
3. The helper throws on failure. Catch it, report the failure to the
   user, and print the report to the console instead. Never silently
   continue.
4. Print `$written.Path` to the console as the closing action of the
   skill.

**Report-content requirements** (unchanged from prior iterations —
apply them to the in-memory string before calling the helper):

- **Redaction pre-encoding.** Redact every value that originates in
  untrusted content — filenames, directory names, log excerpts,
  exception messages, and version strings — before either encoding path.
  For inline values, call `ConvertTo-DebugReportScalar` with the redacted
  text; do not wrap or encode its returned element again. For multiline
  excerpts, HTML-encode the redacted text and place it in `<pre><code>`
  blocks; do not pass multiline evidence through the scalar renderer. Redact user
  profile paths (`C:\Users\<name>\`), tenant IDs / raw GUIDs, email
  addresses, machine names, and module GUIDs. Redaction runs FIRST;
  encoding does not remove sensitive substrings.
- **Trust banner at fixed position.** The trust-boundary blockquote
  (see `Report Format`) appears immediately after the H1 and before
  the `**Generated**:` line. Emit it from a trusted constant, not
  from any log-derived text.
- **Related context.** Every genuinely unhandled finding includes both
  enrichment subsections under `Cause`, using the fields and failure
  wording in `reference/report-format.md`. Preserve partial evidence.
- **Permalink integrity.** Every `https://github.com/…/blob/…`
  substring in the report uses `$baseline.ConfirmedCommitSha` (not
  `main`, not a tag name) and ends with `#L<n>` or `#L<n>-L<m>`.
  Every permalink path resolves against the pinned commit in the
  current clone — Step 5 already disposed its scratch worktree, so
  verify with `git show`, never against a worktree path. Every source
  token quoted in a `Cause` narrative appears in
  the linked line slice fetched via
  `git show $baseline.ConfirmedCommitSha:<path>`; convert 1-based
  permalink line numbers to 0-based array indexes explicitly.
- **Exception fidelity.** For each finding, the quoted
  `Full exception record` includes every line of the summary event's
  `Context` from the local `Error Index:` head or remote
  `----------------Remote Error Information----------------` head through the record's
  terminating boundary. Boundary semantics come from the helper:
  `TerminationKind = Footer` is INCLUSIVE; `NextErrorIndex`,
  `NextRemoteRecord`, and `SectionHeaderTransition` are EXCLUSIVE
  (their boundary line belongs to the next record or section); `EOF` sets
  `TerminationLineNumber = 0` and the record's own
  `OriginalEndLine` is authoritative. When the record is intact
  (`ContextTruncated -eq $false` AND `OmittedLineCount -eq 0`),
  emit a single `Log lines: L<start> — L<end>.` anchor line
  ABOVE the `<pre><code>` block and quote the record WITHOUT
  per-line `L<n>` prefixes. When the record was truncated, KEEP
  the per-line `L<n>` prefix inside the block and disclose the
  omitted range explicitly from `OriginalStartLine` /
  `OriginalEndLine` / `OmittedLineCount`. If any file has
  `AnyLineTruncated`, `HandledEventsTruncated`,
  `UnhandledEventsTruncated`, or `BodyEvidenceMarkersTruncated`
  set, disclose those truncations rather than asserting full
  fidelity.
- **Filename fidelity.** Render each debug file's leaf name from
  `[System.IO.Path]::GetFileName($item.File)`. The helper's `File`
  property is a full path, not a leaf name.
- **Source-slice fidelity.** For every `#### Cause` code block, the
  emitted source range MUST be byte-verbatim against
  `git show $baseline.ConfirmedCommitSha:<path>` for the contiguous
  range `<a>` through `<b>` inclusive, with no line dropped,
  replaced, summarized, collapsed, or rewritten. The block MUST
  match the following per-line shape (regex, applied per non-blank
  source line):
  `^(?<src>.*?)\s{2,}# L(?<n>\d+)(?:\s+←\s.+)?$`
  and MUST NOT contain any of the following (case-sensitive):
  a leading `# L\d+:` prefix marker, the substrings ` ... `,
  `{ ... }`, `<-- `, `<- `, `--> `, ` => `, or a jump between
  consecutive emitted `L<n>` values (i.e. every emitted `<n>` in
  the block must equal the previous emitted `<n>` plus 1). All
  emitted `# L<n>` markers in the block MUST start at the same
  column (right-alignment). Every annotation arrow is `←`
  (U+2190). When the debug log's inline `Position Message` /
  `Script Stack` / `Full exception record` cites the offending
  source line by number, the corresponding annotation on that
  source line MUST cite that evidence in parentheses. If any of
  these checks fail, re-render before writing the report. See the
  `Source-slice format` block under `#### Cause` in `Report Format`
  for the authoritative rules.
- **Safe scalar renderer.** After redaction, pass every untrusted inline
  value (filenames, run IDs, narrative tokens, and returned GitHub fields) to
  `ConvertTo-DebugReportScalar`, dot-sourced from
  `ConvertTo-DebugReportScalar.ps1` beside `SKILL.md`, using its named
  `-RedactedText` parameter. It returns the complete `<code>...</code>`
  element: do not wrap or encode that result again.
  Inline HTML code elements are NOT Markdown parsing boundaries in GFM:
  HTML encoding alone still permits image/link syntax, backtick runs, and
  table pipes to change the rendered document. The helper neutralizes every
  ASCII punctuation character plus tabs and line breaks with numeric
  character references before adding the code element. This encodes both
  HTML metacharacters and Markdown delimiters, keeping images, links,
  backticks, and table delimiters literal. Do not substitute single-backtick
  spans or HTML encoding alone.
  Multiline evidence uses `<pre><code>` blocks with HTML-encoded
  content (defense in depth against log-controlled backtick runs,
  ANSI escapes, and Markdown metacharacters).
- **Interpolation-free generation.** Every previous report-generation
  bug in this skill has been caused by piping report text through
  a double-quoted here-string that let PowerShell interpret `` `v ``
  as U+000B or expand `$Error` / `$guid` as empty. Build the report
  as literal text with `[System.Text.StringBuilder]` appended
  line-by-line, or single-quoted here-string templates with
  explicit `.Replace(...)` substitution. Never use double-quoted
  here-strings for report body text.
- **No stray C0/C1 controls.** No character other than `\r`, `\n`, `\t`
  may have code point < 0x20 or lie in [0x7F, 0x9F]. A single VT
  (`0x0B`) is the fingerprint of a double-quoted here-string bug;
  regenerate. `Write-DebugAnalysisReport.ps1` enforces this and throws
  rather than persisting a corrupt artifact, so a violation surfaces as
  a failed write, not a bad report.
- **Baseline verbatim.** `$baseline.ConfirmedTag`,
  `$baseline.ConfirmedCommitSha`, `$baseline.Repository`, and
  `$baseline.Status` appear as exact text after decoding the inline scalar
  character references. Compare decoded text rather than requiring raw
  Markdown substrings: punctuation in these values is encoded by the scalar
  renderer, not changed or omitted.
- **Scope.** Every finding stays within the analyzed script's
  `.SYNOPSIS` / `.DESCRIPTION` scope; environment-side resolutions
  are routed through the script (defensive code, precondition
  check, or documented prerequisite).
- **Redaction assertion (post-render).** After rendering, HTML-decode a
  validation copy of the report once before checking the patterns below.
  Otherwise numeric character references could hide sensitive values from
  the assertions. Do not write the decoded copy. The decoded text must NOT
  contain (case-insensitive) any of these
  patterns:
  - `C:\\Users\\[^\\]+\\` (user profile subpath)
  - `\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`
    (raw GUID / tenant id)
  - `[\w.%+\-]+@[\w.\-]+\.[A-Za-z]{2,}` (raw email)
  - `(?i)(?<![\\/])\b(?!github\.com\b)(?!microsoft\.com\b)(?!raw\.githubusercontent\.com\b)[A-Za-z](?:[A-Za-z0-9]|-(?!\d))*\d[A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9-]{0,62})+\b(?<!\.(?:ps1|psm1|psd1|dll|exe|md|txt|log|json|xml|csv|zip|7z|pdb|rtf|doc|docx|pdf|png|jpg|jpeg|gif|htm|html|js|css))`
    (multi-label hostname / FQDN with a digit-bearing leftmost
    label; the allowlist keeps repo-controlled URLs visible.)

Also print a brief summary to the console/agent output so the user
knows the report was written and where to find it.
