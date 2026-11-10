# skill-lib

Shared filesystem-safety helpers dot-sourced by skills under `.github/skills/`.

This directory sits **beside** `.github/skills/`, not inside it, so the skill
loader does not attempt to discover a `SKILL.md` here. Each helper is a
single-purpose `.ps1` file with a documented contract at the top; skills
dot-source only the helpers they need.

## When to add a helper here

Extract a helper into this directory only when it is:

- **Byte-for-byte reusable** across two or more skills. If two callers need
  different behavior, keep the helpers inline in each skill — divergent
  copies with the same name are worse than duplication because they silently
  break the "same call, same behavior" contract downstream.
- **Purely defensive filesystem plumbing** (path validation, reparse-point
  detection, DOS-device probes, handle equality checks). Domain logic,
  reporting helpers, and one-of-a-kind orchestration stay in the calling
  skill.

## Consuming a helper

Skills dot-source with a `$PSScriptRoot`-relative path that walks up out of
`.github/skills/<skill-name>/` and back down into `.github/skill-lib/`:

```powershell
. $PSScriptRoot\..\..\skill-lib\Resolve-SkillLocalPath.ps1
```

The `analyze-debug-files` helpers — `Get-DebugFileMetadata.ps1`,
`Assert-BaselineTrusted.ps1`, `Get-BaselineDependencyGraph.ps1`, and
`Write-DebugAnalysisReport.ps1` — all use this same `$PSScriptRoot`-relative
form, because each is a real `.ps1` file where the variable is well-defined.

`Resolve-SkillLocalPath` owns the shared path policy and loads the two defensive
primitives itself. It returns a validated absolute path, or `$null` on refusal.
Callers must use that returned path rather than normalize the input again.
Relative paths resolve against PowerShell's current location. `-PathType Leaf`
requires an existing file; the default requires a directory. `-AllowMissing`
performs the same locality checks without requiring existence or an item type,
for paths that the caller will create.

Each helper's `.DESCRIPTION` carries a `Consumed by:` list. That list is not
decorative — `Tests/SkillLibContract.Tests.ps1` derives the real consumer set
from both the skills and this library, and fails when either the list or the "Skills that depend
on this directory" section below falls out of sync.

## Repository-only: these skills are not independently distributable

Because the helpers live **outside** each skill's own directory, the
`.github/skills/<skill-name>/` folders are **not** self-contained. The Agent
Skills loader discovers and bundles only the files inside a skill's directory,
so copying one of these skill folders on its own — or installing it with
`gh skill install` — produces a skill that fails at dot-source time.

Skills that depend on this directory:

- `.github/skills/analyze-debug-files/`
- `.github/skills/trace-code-introduction/`

These are **repository-scoped skills**, intended to run from a
`microsoft/CSS-Exchange` clone. That is a deliberate trade: a single canonical
copy of each safety helper is worth more than independent distributability,
because divergent copies of a path-validation routine fail silently and
dangerously. If a skill here ever needs to be distributed standalone, vendor the
helpers into its own directory at that point rather than loosening this rule.

`find-release-tag-for-script-version` intentionally carries equivalent inline
filesystem checks to remain self-contained. It is not a consumer of this
directory. When changing the canonical policy or its primitives, review that
standalone copy for the same edge case; do not silently make it depend on this
library.

## Add-Type namespace convention

Helpers that use `Add-Type` for P/Invoke declare types under the
`SkillLib.*` namespace and guard the declaration with an `-as [type]`
check so re-sourcing is a no-op:

```powershell
if (-not ('SkillLib.DosDeviceHelper' -as [type])) {
    Add-Type -Namespace 'SkillLib' -Name 'DosDeviceHelper' -MemberDefinition ...
}
```

A single shared namespace means the P/Invoke types load once per PowerShell
session even when multiple skills consume the same helper.
