<!-- cspell:ignore toplevel -->
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
. $PSScriptRoot\..\..\skill-lib\Test-IsLocalDosDeviceTarget.ps1
. $PSScriptRoot\..\..\skill-lib\Test-PathHasReparsePointRootToLeaf.ps1
```

The `SKILL.md` fenced code block used by the analyze-debug-files skill
does NOT use `$PSScriptRoot` — that variable is unreliable when a
markdown-embedded PowerShell block is executed via `pwsh -Command`, an
extracted temp `.ps1`, or a dot-source from `Invoke-Expression`. That
block anchors to the repo root via `git rev-parse --show-toplevel`,
verifies the resolved repository is `microsoft/CSS-Exchange`, and then
dot-sources the same helper files with `Join-Path $repoRoot ...`. The
skill scripts under `.github/skills/<skill-name>/` use `$PSScriptRoot`
because they are always dot-sourced from a real file where the variable
is well-defined.

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
