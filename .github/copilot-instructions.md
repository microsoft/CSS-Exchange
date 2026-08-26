# Copilot Instructions for CSS-Exchange

## Behavioral Rules

NEVER commit, push, or create PRs without explicit user instruction.
NEVER auto-fix issues found during code review. Report findings only.
NEVER present code as complete without running `Invoke-CodeFormatterOnFiles` and `SpellCheck.ps1` first.
ALWAYS report findings and wait for user decision before modifying the repository.
ALWAYS commit only the specific files the user requests. No extra files.
ALWAYS use named parameters instead of positional parameters.
ALWAYS ensure .ps1 files have UTF-8 BOM encoding.
When counting code patterns (function calls, occurrences), ALWAYS exclude comment lines from the count.

## Code Quality Standards

All code must pass these checks before being presented as complete:

```powershell
. .build/Invoke-CodeFormatterOnFiles.ps1
Invoke-CodeFormatterOnFiles -FilePaths @("<your changed files>") -Save   # Formatting, BOM, PSScriptAnalyzer
.build/SpellCheck.ps1                                                    # Spelling (use PascalCase/camelCase)
```

## Available Agents and Skills

Specialized agents are available in `.github/agents/` for specific tasks:

- **code-review** — Runs the quality pipeline and analyzes code for issues. Reports findings only, cannot modify files. Use: `"Use the code-review agent to review this PR"`
- **code-creator** — Creates and modifies PowerShell scripts following repo standards. Validates with `Invoke-CodeFormatterOnFiles` and `SpellCheck.ps1`. Use: `"Use the code-creator agent to create a new function"`
- **pester-test** — Creates Pester tests following repo patterns and performance rules. Use: `"Use the pester-test agent to write tests for FunctionName"`

Skills are available in `.github/skills/` and are automatically loaded when relevant:

- **dependency-analysis** — Maps cascading impact of changes using build system XML. Auto-loads when working with shared functions or assessing change impact. Can also be invoked explicitly: `"Use the /dependency-analysis skill to analyze impact of changing FunctionName"`

## Personal Overrides

Developers can create personal agents, skills, and instructions that override or extend the repo-level defaults without affecting other contributors. These directories are gitignored:

| Directory | Purpose | Behavior |
|-----------|---------|----------|
| `.copilot/copilot-instructions.md` | Personal instructions | **Merges** with repo instructions (additive — safe) |
| `.copilot/agents/` | Personal agent overrides | **Replaces** repo agent entirely (use with caution) |
| `.copilot/skills/` | Personal skills | Available only to you |
| `.claude/` | Claude Code personal configuration | — |
| `.agents/` | Alternative personal agents/skills location | — |

### Important: Agent Overrides Replace, They Don't Merge

If you create `.copilot/agents/code-review.md`, it **completely replaces** `.github/agents/code-review.agent.md` — it does not merge. This means:
- You must maintain the full agent file, not just your changes
- You won't receive repo-level updates to that agent until you delete your override
- Stale overrides silently mask improvements made by other contributors

### Recommended Workflow for Iterating on Rules

1. **Discover** a needed change while working → store it as a Copilot memory
2. **Test** additive changes via `.copilot/copilot-instructions.md` (safe — merges with repo)
3. **Only** use `.copilot/agents/` override when testing a full agent rewrite, and delete the override once the change is promoted
4. **Batch** validated changes into a single PR to `.github/` periodically
5. **Clean up** any memories that were promoted to files

## Repository Overview

CSS-Exchange is a multi-script repository where:
- **Main scripts** live in domain folders (Admin, Calendar, Databases, Diagnostics, Hybrid, M365, Outlook, etc.)
- **Shared utilities** are in the `Shared/` folder and are dot-sourced into scripts
- **Scripts are built** into single `.ps1` files in the `dist/` folder via the build system
- **All scripts follow PowerShell best practices** enforced by PSScriptAnalyzer and custom formatting tools

## Before Any Work: Understanding Script Context

Before writing tests, reviewing code, or making any changes to a script:

1. Read the full script to understand its purpose, logic, functions, parameters, and dependencies.
2. Use `.build/Build.ps1` to generate dependency XML files (`dist/dependencyHashtable.xml` and `dist/dependentHashtable.xml`). These are the authoritative source for all script relationships.
3. Map the cascading impact: changes to Shared functions affect direct callers AND their callers. The dependency-analysis skill auto-loads when relevant, or use `.github/skills/dependency-analysis/Get-DependencyCascade.ps1` directly.

## Build, Test, and Code Quality Commands

All commands require **PowerShell 7+** and should be run from the repository root.

### Building

```powershell
.build/Build.ps1
```

- Combines multi-file scripts into single-file releases in the `dist/` folder
- Embeds dot-sourced scripts and file resources (e.g., `.txt`, `.html`) directly into the output
- Generates version numbers based on the most recent commit date for each script

### Code Formatting and Linting

For targeted formatting of specific files (preferred for agents):
```powershell
. .build/Invoke-CodeFormatterOnFiles.ps1
Invoke-CodeFormatterOnFiles -FilePaths @("<files to check>") -Save
```

For formatting all changed files on a branch:
```powershell
.build/CodeFormatter.ps1 -Save -Branch main
```

- Runs PSScriptAnalyzer rules from `PSScriptAnalyzerSettings.psd1`
- Automatically applies formatting fixes (indentation, braces, whitespace)
- Adds UTF-8 BOM to `.ps1` files, removes it from `.md` files
- `CodeFormatter.ps1` wraps `Invoke-CodeFormatterOnFiles` with automatic file discovery

### Spell Checking

```powershell
.build/SpellCheck.ps1
```

- Uses `cspell` (Node.js-based tool)
- Dictionary is in `.build/cspell-words.txt`
- Most spelling issues are caught by using proper camelCase or PascalCase variable names
- Note: `.github/` is excluded from spell checking via `.build/cspell.json`

### Testing (Pester)

```powershell
.build/Pester.ps1
```

- Runs all Pester tests (`*.Tests.ps1`) found recursively across the repository (excludes `.github/`)
- Runs tests in parallel (auto-scales to CPU cores)
- To test only changed files: `.build/Pester.ps1 -Branch main`
- Tests use `BeforeAll` to dot-source scripts and set up the environment

### Running the Full Pipeline

```powershell
.build/CodeFormatter.ps1 -Save -Branch main
.build/SpellCheck.ps1
.build/Pester.ps1 -Branch main
.build/Build.ps1
```

Then verify the output scripts in the `dist/` folder.

## High-Level Architecture

### Multi-File to Single-File Pattern

The build system allows scripts to be developed as multi-file projects but released as single files:

1. **Development**: Scripts can dot-source other `.ps1` files and reference resources like `.txt` files
2. **Build**: The build system detects dot-sourcing and file inclusions, embeds them, and outputs to `dist/`
3. **Release**: Only the final single `.ps1` files in `dist/` are released

### Dot-Sourcing Convention

Scripts dot-source shared functions with `$PSScriptRoot`-relative paths:

```powershell
. $PSScriptRoot\HelperScript.ps1
. $PSScriptRoot\..\..\Shared\GenericScriptStartLogging.ps1
```

**Why**: Allows scripts to run and be debugged at development time without building, and ensures the build system can find and embed them.

### Shared Functions in `Shared/`

Common utilities organized by domain:

- **ActiveDirectoryFunctions**: AD queries and user lookups
- **AzureFunctions**: Azure AD/Graph API calls
- **CertificateFunctions**: Certificate handling
- **EMailFunctions**: Email parsing and validation
- **ExchangeSessionFunctions**: PowerShell remoting to Exchange
- **GraphApiFunctions**: Microsoft Graph API wrappers
- **ErrorMonitorFunctions**: Error tracking and reporting
- **LoggerFunctions**: Logging and output formatting
- **Out-Columns.ps1**: Colorized table output with word-wrapping
- **ScriptUpdateFunctions**: Auto-update capability (see below)

Other shared utilities:
- **Confirm-ExchangeShell.ps1**: Validates Exchange PowerShell is available
- **Get-ProcessedServerList.ps1**: Parses and deduplicates server lists
- **Invoke-CatchActionError.ps1**: Standardized error handling

### Auto-Update Pattern

Scripts can enable auto-update by dot-sourcing `Test-ScriptVersion.ps1`:

```powershell
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if (Test-ScriptVersion -AutoUpdate) {
    Write-Host "Script was updated. Please rerun the command."
    return
}
```

This checks GitHub releases and downloads the latest version if available.

## Key Conventions

### Parameter and Variable Naming

- **PascalCase** for parameters and public functions: `$Identity`, `$TargetMailbox`
- **camelCase** for internal/local variables: `$results`, `$processedItems`
- **UPPER_CASE** for constants: `$MAX_RETRY_COUNT`, `$DEFAULT_TIMEOUT`

**Why**: Variables in PascalCase pass spell-checking; inconsistency fails the spell check.

### Comments and Documentation

- Use `#` for single-line comments
- Use `<# #>` for block comments (especially for complex logic)
- Use `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE` for function help
- Avoid over-commenting obvious code; focus on *why* not *what*

### Testing Patterns

Tests follow a **colocated pattern**: `*.Tests.ps1` files are placed in a `Tests/` subfolder adjacent to the script being tested. Examples:

- `Shared/Tests/*.Tests.ps1` - Tests for shared utilities
- `Setup/Tests/*.Tests.ps1` - Tests for Setup scripts
- `Diagnostics/HealthChecker/Tests/*.Tests.ps1` - Tests for HealthChecker
- `Admin/MonitorExchangeAuthCertificate/DataCollection/Tests/*.Tests.ps1` - Tests colocated near the script

Basic test structure:

```powershell
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\ScriptToTest.ps1

    # Load helper functions if needed
    . $PSScriptRoot\..\..\Shared\PesterLoadFunctions.NotPublished.ps1
}

Describe "ScriptName" {
    It "should do something" {
        $result = Function-Name -Param "value"
        $result | Should -Be "expected"
    }
}
```

Key conventions:

- Use `BeforeAll` to set up the environment and dot-source the script
- Prefix script-scope variables with `$Script:` to avoid conflicts
- Use `Mock` for external cmdlets (e.g., Exchange cmdlets, Get-ExchangeCertificate)
- Store mock data in XML files in a `Tests/Data/` subfolder: `Import-Clixml $Script:parentPath\Tests\Data\MockData.xml`
- For complex multi-script testing (e.g., HealthChecker), create helper functions in `NotPublished.ps1` files (e.g., `HealthCheckerTests.ImportCode.NotPublished.ps1`)
- Load functions dynamically with `Get-PesterScriptContent` and `Invoke-Expression` when testing individual functions from large scripts

