# Step 7.5 — Related issues and code introduction

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


Two sibling skills provide provenance that turns a finding from
"here's what broke" into "here's what broke, whether we already know
about it, and when we introduced it":

- **`find-related-github-issues`** — searches this repository's GitHub
  Issues and Pull Requests for records that match the exception
  signature. Classifies matches as **Duplicate** (top-level AND inner
  exception match) or **Similar** (top-level OR inner exception
  match). A Duplicate result is only a candidate: confirm the same failure
  context or root cause before recommending that an issue be closed.
  Exception phrase matches alone never justify closure.
  Discriminator-function-name matches alone do NOT qualify as
  Similar — they are silently discarded (the same enclosing function
  can fail for unrelated reasons at different call sites) and counted
  in `DiscardedFunctionOnly` for transparency. See
  `.github/skills/find-related-github-issues/SKILL.md`.
- **`trace-code-introduction`** — walks `git log -L` for the source
  range at the pinned baseline SHA to find the introducing commit
  and the merging PR, then applies a conservative heuristic to
  classify the change as `Intentional`, `LikelyOversight`,
  `PossibleRegression`, or `Indeterminate`. See
  `.github/skills/trace-code-introduction/SKILL.md`.

**Range selection for `trace-code-introduction` (critical).**
`git log -L <start>,<end>:<file>` returns the most-recent commit that
touched **any** line in the range. Passing a range wider than the
actual failing code path will surface a later unrelated edit in the
same block, not the commit that introduced the failure.

Pass the **smallest contiguous range that covers the failing code
path** — the guard(s) that admit the bad value, the assignment that
produces it, and the failing call itself. Do NOT pass the enclosing
`try`/`if`/function block; sibling statements added by later commits
will be misattributed as the "introducing" change. If the range in
the `Resolution` narrative is broader than the failing-path range,
they will differ intentionally — the trace range describes the
failure origin, the Resolution range describes the scope of the
proposed change.

Invoke both for each genuinely-unhandled finding produced by Step 7.
Both skills return result objects. Render their two required subsections
under `#### Cause` using `reference/report-format.md`, the single authority
for their headings, field layout, and status-dependent wording.

**Input redaction (find-related-github-issues).** The
`TopLevelException` and `InnerException` arguments carry the same
untrusted content that log excerpts do — tenant IDs, email addresses,
machine names, user profile path components, module GUIDs, and other
sensitive tokens can appear verbatim in an exception message. Unlike
report content, which stays on the operator's own machine, these
arguments are submitted to `github.com/search` and become part of
`gh`'s network traffic and GitHub's own search-query telemetry.
BEFORE invoking `find-related-github-issues`:

1. Route the top-level exception message and (if present) the inner
   exception message through the same redaction pipeline used for
   report content (see `Safe scalar renderer` in Step 8). Redact
   `C:\Users\<name>\` prefixes, raw GUIDs, email addresses, machine
   names, and any other tokens the pipeline strips for the report.
2. Pass the REDACTED strings as `-TopLevelException` and
   `-InnerException`. Do NOT pass the raw exception message.
3. If neither string retains distinctive exception content after redaction
   (only `<user>`, `<guid>`, `<email>`, etc. remain), skip the
   invocation for that finding — the query would either produce
   zero-signal noise or fail phrase validation inside the sibling
   skill. Render the corresponding subsection with a "lookup
   unavailable: no distinctive phrase after redaction" note.
   One surviving exception signature is sufficient for Similar matches;
   both are needed for possible duplicates.

`Find-RelatedGitHubIssues.ps1` documents in its `.PARAMETER
TopLevelException` help that its caller MUST supply already-redacted
messages; the skill does no exception-content redaction of its own
beyond generic path/UNC stripping. Enforcing redaction here is the
only line of defense.

**Trust boundary.** Issue titles, issue bodies, commit messages, PR
titles, PR bodies, PR author logins, and commit author names are ALL
untrusted content. The report renderer MUST route every scalar from
these skills through the same redaction + HTML-encode pipeline used
for log content (see `Safe scalar renderer` in Step 8). Wrap untrusted
values in `<code>...</code>` blocks, NEVER in single-backtick spans.
Never pass a returned value back into `gh` or `git` as an argument.

**Failure modes.** Both skills return a `Status` field.

- `Status = 'Ok'` — render the returned results normally.
- `Status = 'PartialLookup'` — retain the available results and disclose
  `StatusDetail`. For `find-related-github-issues`, render the retained
  matches AND append "results may be incomplete: `<StatusDetail>`".
  For `trace-code-introduction`, render the genuine local commit, diff,
  and regression assessment, but label the associated PR lookup
  "lookup unavailable: `<StatusDetail>`". A failed PR lookup is not
  evidence that no associated PR exists.
- Any other non-`Ok` status (`GhUnavailable`, `AuthFailure`,
  `RateLimited`, `NoSearchablePhrase`, `Error`, or any status returned by
  `trace-code-introduction` other than `Ok` or `PartialLookup`) — render a single-line
  "lookup unavailable: `<StatusDetail>`" note in the corresponding
  subsection and continue with the report.

A failing provenance lookup MUST NOT abort the report.

`RangeUnavailable` can indicate a shallow-history boundary even when Step 4's
release baseline passed validation. Baseline trust proves which source is
being analyzed, not that its ancestry is complete. Render the returned
`StatusDetail` as unavailable history; do not infer an introducing commit,
associated PR, or regression verdict from the truncated range. Deeper local
history is needed before retrying against the same pinned baseline, never
HEAD or another unpinned revision.
