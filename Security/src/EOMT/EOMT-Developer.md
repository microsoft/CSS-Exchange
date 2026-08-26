# EOMT Developer Guide

Developer documentation for the **Exchange On-premises Mitigation Tool (EOMT)** framework.
This guide explains how the tool works, how to add new CVE definitions, and common pitfalls
to avoid. If you are new to the codebase, start with [Architecture Overview](#1-architecture-overview)
and then read [How to Add a New CVE Definition](#2-how-to-add-a-new-cve-definition).

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [How to Add a New CVE Definition](#2-how-to-add-a-new-cve-definition)
3. [Execution Flow](#3-execution-flow)
4. [IIS Management Pipeline](#4-iis-management-pipeline)
5. [Rollback Design](#5-rollback-design)
6. [Key Design Decisions](#6-key-design-decisions)
7. [Common Pitfalls](#7-common-pitfalls)
8. [Testing](#8-testing)

---

## 1. Architecture Overview

EOMT is a PowerShell-based tool that applies IIS URL Rewrite mitigations for known
Exchange Server CVEs. It replaces the legacy single-CVE scripts (`EOMT.ps1`, `EOMTv2.ps1`)
with a single, extensible framework.

### Directory Structure

```
Security/src/EOMT/
├── EOMT.ps1                           # Main orchestrator (begin/process/end pipeline)
├── ConfigurationAction/
│   ├── Invoke-ApplyMitigations.ps1    # Wraps CVE actions and sends to IIS pipeline
│   └── Invoke-RollbackMitigations.ps1 # Restores original config from JSON backup
├── DataCollection/
│   └── Get-VulnerabilityStatus.ps1    # Runs TestVulnerable for a CVE; returns MitigationApplied, CodeFixApplied, DisabledRules, and RuleNameMatch
├── Mitigations/
│   ├── MitigationDefinitions.ps1      # CVE registry — dot-sources all CVE files
│   ├── CVE-2021-26855.ps1             # ProxyLogon
│   ├── CVE-2022-41040.ps1             # ProxyNotShell
│   └── CVE-2026-42897.ps1             # OWA XSS (outbound rule with preConditions)
├── MSERT/
│   └── Invoke-MSERTScan.ps1           # Microsoft Safety Scanner download + run
└── SharedFunctions/
    └── Install-IISUrlRewriteModule.ps1 # URL Rewrite Module installer
```

### Shared Module: IISManagement

The IIS configuration pipeline lives in a separate shared module at
`Security/src/IISManagement/`. It is used by both EOMT and
ExchangeExtendedProtectionManagement.

```
Security/src/IISManagement/
├── Get-ParameterString.ps1
├── Invoke-IISConfigurationManagerAction.ps1
├── Invoke-IISConfigurationRemoteAction.ps1
├── New-IISConfigurationAction.ps1
└── Tests/
```

### Core Design Principles

- **EOMT.ps1 is the orchestrator.** It uses a `begin`/`process`/`end` pipeline to
  support piped input from `Get-ExchangeServer`. It knows nothing about individual CVEs.
- **CVE definitions are pluggable.** Each CVE is a self-contained `.ps1` file that returns
  a definition object. Adding a new CVE requires no changes to the core pipeline logic.
- **IIS changes flow through the IISManagement pipeline.** Raw actions from CVE definitions
  are wrapped into Set/Get/Restore tuples by `New-IISConfigurationAction`, then executed
  remotely by `Invoke-IISConfigurationRemoteAction`.
- **JSON-backed rollback.** Before every IIS change, the current value is captured and written
  to a JSON backup file. Rollback reads this file to restore the original configuration.

---

## 2. How to Add a New CVE Definition

This is the most common maintenance task. Follow these four steps.

### Step 1: Create the Definition File

Create a new file at:

```
Security/src/EOMT/Mitigations/CVE-YYYY-NNNNN.ps1
```

The file contains a single function that returns a `[PSCustomObject]` with the mitigation
definition. Follow this naming convention:

| Item | Convention | Example |
|------|-----------|---------|
| **File name** | `CVE-YYYY-NNNNN.ps1` | `CVE-2022-41040.ps1` |
| **Function name** | `Get-CVE20XX99999-MitigationDefinition` (digits only, no hyphens in the CVE portion) | `Get-CVE202241040-MitigationDefinition` |

Here is the minimal skeleton:

```powershell
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    Mitigation definition for CVE-YYYY-NNNNN.
    <Brief description of what the mitigation does.>
#>
function Get-CVE20XX99999-MitigationDefinition {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    return [PSCustomObject]@{
        Id                     = "CVE-YYYY-NNNNN"
        Priority               = 1
        Description            = "Short human-readable description"
        RequiresUrlRewrite     = $true
        SiteName               = "Default Web Site"
        TestVulnerable = {
            # Returns a hashtable with MitigationApplied (bool), CodeFixApplied (bool),
                # DisabledRules (array), and RuleNameMatch (bool).
                # Must work over PS remoting — no module dependencies!
        }
        GetActions             = {
            # Returns an array of action objects for the IIS pipeline.
        }
    }
}
```

#### Required Properties

| Property | Type | Description |
|----------|------|-------------|
| `Id` | `string` | The CVE identifier, e.g., `"CVE-2022-41040"`. Must match the key used in the registry. |
| `Priority` | `int` | Lower number = higher priority. `0` is the default selection in the interactive prompt. |
| `Description` | `string` | Human-readable description shown in prompts and logs. |
| `RequiresUrlRewrite` | `bool` | Set to `$true` if the mitigation needs the IIS URL Rewrite Module. The framework will auto-install it if missing. |
| `SiteName` | `string` | The IIS site name, e.g., `"Default Web Site"`. Used in prerequisite checks. |
| `TestVulnerable` | `ScriptBlock` | Returns a `@{ MitigationApplied = [bool]; CodeFixApplied = [bool]; DisabledRules = [array]; RuleNameMatch = [bool] }` hashtable. `MitigationApplied` is `$true` only when a rule exists **and** is enabled. `CodeFixApplied` indicates whether the Exchange security update is installed. `DisabledRules` is an array of `@{ Filter; PSPath }` objects for rules that match the expected behavior but are disabled; empty array (`@()`) when none. `RuleNameMatch` is `$true` when our expected rule name exists but its behavior doesn't match (name conflict). Should `throw` on unrecoverable errors. See [Important Constraints](#testvulnerable-constraints) below. |
| `GetActions` | `ScriptBlock` | Returns an `array` of `[PSCustomObject]` action definitions for the IIS management pipeline. |

#### TestVulnerable Constraints

This ScriptBlock runs on the target server via PowerShell remoting. It is passed as a string
and recreated with `[ScriptBlock]::Create()`. This means:

- ❌ **No Exchange Management Shell cmdlets** (e.g., no `Get-ExchangeServer` — EMS may not be loaded on the remote side)
- ✅ **IIS cmdlets are allowed** (`Get-WebConfiguration`, `Get-WebConfigurationProperty` — the WebAdministration module is always available on Exchange servers)
- ✅ **Use built-in commands** (`Get-Command`, `Get-ItemProperty`, registry reads, etc.)
- ✅ **Throw on failure** — the framework catches exceptions and reports them
- ✅ **Return a hashtable** with `MitigationApplied` (bool), `CodeFixApplied` (bool), `DisabledRules` (array of `@{ Filter; PSPath }`), and `RuleNameMatch` (bool)

**Example** — version check via `ExSetup.exe` with mitigation detection:

```powershell
TestVulnerable = {
    $codeFixApplied = $false
    $mitigationApplied = $false

    # Check if the security update is installed
    try {
        $exchangeBuildInfo = Get-Command ExSetup.exe -ErrorAction Stop |
            ForEach-Object { $_.FileVersionInfo }
        [System.Version]$fullBuildNumber = $exchangeBuildInfo.FileVersion
    } catch {
        throw ("Failed to get Exchange Server build number. The error was: {0}." -f $_)
    }

    if ($exchangeBuildInfo.FileMinorPart -eq 1) {
        # Exchange 2016
        if ($exchangeBuildInfo.ProductBuildPart -gt 2375) {
            $codeFixApplied = ($fullBuildNumber -ge "15.01.2507.016")
        } else {
            $codeFixApplied = ($fullBuildNumber -ge "15.01.2375.037")
        }
    } elseif ($exchangeBuildInfo.FileMinorPart -eq 2) {
        # Exchange 2019
        if ($exchangeBuildInfo.ProductBuildPart -gt 986) {
            $codeFixApplied = ($fullBuildNumber -ge "15.02.1118.020")
        } else {
            $codeFixApplied = ($fullBuildNumber -ge "15.02.0986.036")
        }
    } else {
        throw ("Exchange Server version not supported. Build: {0}" -f $fullBuildNumber)
    }

    # Check if IIS mitigation rule is present
    # (detection logic varies per CVE — see CVE-2026-42897 for advanced example)
    $mitigationApplied = $false  # Placeholder — check for IIS URL Rewrite rule

    return @{
        MitigationApplied = $mitigationApplied
        CodeFixApplied    = $codeFixApplied
        DisabledRules     = @()
        RuleNameMatch     = $false
    }
}
```

### Step 2: Define GetActions

`GetActions` returns an array of action objects. Each object represents one IIS configuration
change. The framework supports three IIS cmdlet types:

#### Add-WebConfigurationProperty — Adding New IIS Configuration Entries

Use this to add new rules, preConditions, or other named elements to IIS collections.

| Property | Required | Description |
|----------|----------|-------------|
| `Cmdlet` | Yes | `"Add-WebConfigurationProperty"` |
| `Parameters` | Yes | Hashtable with `Filter`, `PSPath`, `Name`, `Value` |
| `RuleName` | Yes (for top-level adds) | The element name. Used to build a targeted `Clear-WebConfiguration` filter for rollback. **Without this, the element cannot be individually rolled back.** |
| `ElementName` | No | The IIS collection element type. Defaults to `"rule"`. Override for other types like `"preCondition"`. |

**Rollback behavior:**
- **With `RuleName`**: The framework auto-generates a `Clear-WebConfiguration` rollback
  command targeting `filter/elementName[@name='RuleName']`.
- **Without `RuleName`**: No individual rollback is generated. Use this for child elements
  (e.g., conditions inside a preCondition) where the parent's rollback handles cleanup.

#### Set-WebConfigurationProperty — Modifying Existing IIS Configuration

Use this to set properties on elements that already exist (or were just created by an `Add`).

| Property | Required | Description |
|----------|----------|-------------|
| `Cmdlet` | Yes | `"Set-WebConfigurationProperty"` |
| `Parameters` | Yes | Hashtable with `Filter`, `Name`, `Value`, `PSPath` |

**Rollback behavior:** The current value is automatically captured via
`Get-WebConfigurationProperty` before the change is applied. If the current value is `null`
(the property did not exist), the restore step is skipped.

#### Clear-WebConfiguration — Removing IIS Configuration Entries

Use this to remove existing configuration entries.

| Property | Required | Description |
|----------|----------|-------------|
| `Cmdlet` | Yes | `"Clear-WebConfiguration"` |
| `Parameters` | Yes | Hashtable with `Filter` |

**Rollback behavior:** The current value is captured via `Get-WebConfiguration`. On restore,
`Add-WebConfigurationProperty` is used to re-create the removed entry.

### Complete Example: Simple Inbound Rule (CVE-2022-41040)

This example adds an inbound URL Rewrite rule that blocks requests matching both
`autodiscover` and `powershell` in the URL.

```powershell
GetActions = {
    $site = "IIS:\Sites\Default Web Site"
    $root = 'system.webServer/rewrite/rules'
    $httpRequestInput = '{UrlDecode:{REQUEST_URI}}'
    $inbound = '.*'

    $name = 'PowerShell - inbound'
    $pattern = '(?=.*autodiscover)(?=.*powershell)'
    $filter = "{0}/rule[@name='{1}']" -f $root, $name

    @(
        # Step 1: Add the inbound rule (top-level — requires RuleName)
        [PSCustomObject]@{
            Cmdlet     = "Add-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = $root
                Name   = '.'
                Value  = @{
                    name           = $name
                    patternSyntax  = 'Regular Expressions'
                    stopProcessing = 'True'
                }
            }
            RuleName   = $name
        },
        # Step 2: Set the match URL pattern
        [PSCustomObject]@{
            Cmdlet     = "Set-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = "$filter/match"
                Name   = 'url'
                Value  = $inbound
            }
        },
        # Step 3: Set the request condition
        [PSCustomObject]@{
            Cmdlet     = "Set-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = "$filter/conditions"
                Name   = '.'
                Value  = @{
                    input      = $httpRequestInput
                    matchType  = '0'
                    pattern    = $pattern
                    ignoreCase = 'True'
                    negate     = 'False'
                }
            }
        },
        # Step 4: Set the action to abort the request
        [PSCustomObject]@{
            Cmdlet     = "Set-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = "$filter/action"
                Name   = 'type'
                Value  = 'AbortRequest'
            }
        }
    )
}
```

**Key points:**

- The first action (`Add`) has `RuleName = $name`, which enables targeted rollback.
- The subsequent `Set` actions configure the rule created by the `Add`. These don't need
  `RuleName` — their rollback captures the current value before overwriting.
- The `$filter` variable builds a path like
  `system.webServer/rewrite/rules/rule[@name='PowerShell - inbound']` to target the
  specific rule.

### Complete Example: Outbound Rule with PreConditions (CVE-2026-42897)

This more complex example adds an outbound URL Rewrite rule on the OWA virtual directory
with preConditions that scope the rule to specific HTML pages.

```powershell
GetActions = {
    $site = "IIS:\Sites\Default Web Site\owa"
    $outboundRoot = 'system.webServer/rewrite/outboundRules'

    $preConditionName = 'EOMT OWA SPA HTML shell - precondition'
    $ruleName = 'EOMT OWA CSP - outbound'
    $ruleFilter = "{0}/rule[@name='{1}']" -f $outboundRoot, $ruleName

    @(
        # Step 1: Add preCondition (note ElementName override)
        [PSCustomObject]@{
            Cmdlet      = "Add-WebConfigurationProperty"
            Parameters  = @{
                PSPath = $site
                Filter = "$outboundRoot/preConditions"
                Name   = '.'
                Value  = @{
                    name            = $preConditionName
                    logicalGrouping = 'MatchAll'
                    patternSyntax   = 'ECMAScript'
                }
            }
            RuleName    = $preConditionName
            ElementName = 'preCondition'    # Override default "rule"
        },
        # Step 2: Add condition to preCondition — match HTML responses
        # (No RuleName — parent preCondition rollback cleans this up)
        [PSCustomObject]@{
            Cmdlet     = "Add-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = "$outboundRoot/preConditions/preCondition[@name='$preConditionName']"
                Name   = '.'
                Value  = @{
                    input   = '{RESPONSE_CONTENT_TYPE}'
                    pattern = '^text/html'
                }
            }
        },
        # Step 3: Add condition — match specific OWA SPA pages
        [PSCustomObject]@{
            Cmdlet     = "Add-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = "$outboundRoot/preConditions/preCondition[@name='$preConditionName']"
                Name   = '.'
                Value  = @{
                    input   = '{REQUEST_URI}'
                    pattern = '^/owa/?($|\?|default\.aspx|projection\.aspx)'
                }
            }
        },
        # Step 4: Add the outbound rule referencing the preCondition
        [PSCustomObject]@{
            Cmdlet     = "Add-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = $outboundRoot
                Name   = '.'
                Value  = @{
                    name           = $ruleName
                    preCondition   = $preConditionName
                    patternSyntax  = 'ECMAScript'
                    stopProcessing = 'False'
                }
            }
            RuleName   = $ruleName
        },
        # Steps 5-8: Set match/action properties on the rule
        [PSCustomObject]@{
            Cmdlet     = "Set-WebConfigurationProperty"
            Parameters = @{
                PSPath = $site
                Filter = "$ruleFilter/match"
                Name   = 'serverVariable'
                Value  = 'RESPONSE_Content_Security_Policy'
            }
        },
        # ... additional Set actions for pattern and action type
    )
}
```

**Key differences from the simple example:**

- Uses `ElementName = 'preCondition'` on the first `Add` so the rollback filter targets
  `preCondition[@name='...']` instead of `rule[@name='...']`.
- Child conditions (Steps 2-3) have no `RuleName` — when the parent preCondition is
  cleared during rollback, its children are removed automatically.
- Targets `Default Web Site\owa` (a virtual directory) rather than the site root.

> **Advanced Detection Example: CVE-2026-42897** — The `TestVulnerable` ScriptBlock for
> CVE-2026-42897 goes beyond simple rule-name checks. It performs behavior-based detection
> by inspecting outbound rule properties (such as `serverVariable`, action type, and action
> value) and verifying preCondition conditions using `GetCollection()` with indexer access.
> This ensures the mitigation is detected even if rule names have been customized.
>
> **Enabled check:** A rule is only considered "applied" if its `enabled` property is `$true`.
> Disabled rules that match the expected behavior are collected in the `DisabledRules` array
> (each entry contains `Filter` and `PSPath` for identification).
>
> **Name conflict detection:** The ScriptBlock maintains `$expectedRuleNames` and
> `$expectedPreConditionNames` lists. If a rule with the expected name exists but its behavior
> does not match (e.g., the name was reused for a different purpose), `RuleNameMatch` is set
> to `$true`. This prevents EOMT from blindly overwriting a user-customized rule.
>
> **Verbose logging:** Every rule evaluated is logged via `Write-Verbose`, showing its name,
> enabled state, and whether its behavior matched. This aids troubleshooting when rules are
> not detected as expected.

### Step 3: Register the Definition

Three changes are needed:

#### 1. Dot-source in MitigationDefinitions.ps1

Add a line to load your new file at the top of
`Security/src/EOMT/Mitigations/MitigationDefinitions.ps1`:

```powershell
. $PSScriptRoot\CVE-2021-26855.ps1
. $PSScriptRoot\CVE-2022-41040.ps1
. $PSScriptRoot\CVE-2026-42897.ps1
. $PSScriptRoot\CVE-YYYY-NNNNN.ps1      # <-- Add this line
```

#### 2. Add to the definition map

Add an entry to `$script:MitigationDefinitionMap` in the same file:

```powershell
$script:MitigationDefinitionMap = @{
    "CVE-2021-26855" = { Get-CVE202126855-MitigationDefinition }
    "CVE-2022-41040" = { Get-CVE202241040-MitigationDefinition }
    "CVE-2026-42897" = { Get-CVE202642897-MitigationDefinition }
    "CVE-YYYY-NNNNN" = { Get-CVE20XX99999-MitigationDefinition }  # <-- Add this line
}
```

#### 3. Add to ValidateSet in EOMT.ps1

Update the `[ValidateSet()]` attribute on the `-CVE` parameter in `EOMT.ps1`:

```powershell
[ValidateSet("CVE-2021-26855", "CVE-2022-41040", "CVE-2026-42897", "CVE-YYYY-NNNNN")]
[string]$CVE,
```

### Step 4: Test

Run these checks before submitting a pull request:

#### Code Quality

```powershell
# Format code to match project style
.\.build\CodeFormatter.ps1 -Save -Branch next-release

# Run spell check
.\.build\SpellCheck.ps1 -Branch next-release
```

#### Lab Testing Checklist

Test each scenario in a lab environment with IIS URL Rewrite Module installed:

| Test | Command | What to Verify |
|------|---------|----------------|
| **Apply** | `.\EOMT.ps1 -CVE "CVE-YYYY-NNNNN"` | Rule appears in IIS Manager; blocked requests return expected response |
| **Verify** | `curl` or browser request | Confirm the mitigation blocks the attack pattern |
| **WhatIf** | `.\EOMT.ps1 -WhatIf -CVE "CVE-YYYY-NNNNN"` | Shows planned changes without modifying IIS |
| **Status** | `.\EOMT.ps1 -ShowMitigationStatus -CVE "CVE-YYYY-NNNNN"` | Reports vulnerability status correctly |
| **Rollback** | `.\EOMT.ps1 -RollbackMitigation -CVE "CVE-YYYY-NNNNN"` | Rule is removed; original config is restored |
| **Verify Clean** | Confirm in IIS Manager | No leftover rules or preConditions |
| **Apply Twice** | Apply, then apply again | Second apply should not corrupt the backup (see [Rollback Design](#5-rollback-design)) |
| **Remote** | `Get-ExchangeServer \| .\EOMT.ps1 -CVE "CVE-YYYY-NNNNN"` | Works across multiple servers via pipeline |

---

## 3. Execution Flow

This section walks through what happens when a user runs `.\EOMT.ps1`.

### Phase 1: `begin` Block — Initialization

1. **TLS 1.2** is forced for HTTPS downloads.
2. **Dependencies** are dot-sourced (mitigation definitions, shared functions, etc.).
3. **Interactive CVE prompt** — if `-CVE` was not specified, the user sees a numbered list
   of available CVEs sorted by `Priority`. The lowest-priority-number CVE is the default.
4. **Server list** is initialized as an empty collection.

### Phase 2: `process` Block — Server Collection

This block runs once per pipeline input object. If the user pipes `Get-ExchangeServer`,
each server's `Name` or `Fqdn` is collected into `$serversToProcess` via the
`ValueFromPipelineByPropertyName` binding.

```powershell
# Pipeline usage example:
Get-ExchangeServer | .\EOMT.ps1 -CVE "CVE-2022-41040"
```

### Phase 3: `end` Block — Execution

All real work happens here, after all pipeline input is collected.

```
┌─────────────────────────────────────────────────────┐
│ 1. Prerequisites: Admin check + PowerShell 3+ check │
│ 2. Auto-update check (unless -SkipAutoUpdate)       │
│ 3. Server resolution:                               │
│    - No servers provided → target local machine     │
│    - Servers provided → confirm EMS, apply skip list│
│ 4. Load CVE definition via Get-MitigationDefinition │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
     ┌────────────────────┐
     │ -ShowMitigationStatus? ──Yes──► Run TestVulnerable on each server
     │                    │           via Invoke-ScriptBlockHandler.
     │                    │           Display Code Fix and Mitigation status (6 states):
     │                    │             CodeFix ✓ + Mitigation ✓ → "True (can be safely rolled back)" Yellow
     │                    │             CodeFix ✓ + Mitigation ✗ → "N/A (protected by security update)" Green
     │                    │             CodeFix ✗ + Mitigation ✓ → "True" Green
     │                    │             CodeFix ✗ + RuleNameMatch → "CONFLICT — rollback then re-apply" Red
     │                    │             CodeFix ✗ + DisabledRules → "DISABLED — rollback then re-apply" Red
     │                    │                                          or "False — matching rule disabled
     │                    │                                          under different name. Run EOMT to apply." Red
     │                    │             CodeFix ✗ + Nothing       → "False — ACTION REQUIRED" Red
     │                    │           Report and exit.
     └────────┬───────────┘
              │ No
              ▼
     ┌────────────────────┐
     │ Disclaimer prompt  │  (unless -SkipDisclaimer)
     └────────┬───────────┘
              │
              ▼
     ┌────────────────────────────────────────────────────────────┐
     │ Per-server prerequisite check (remote Call 1):             │
     │   • Run TestVulnerable → {MitigationApplied, CodeFixApplied,│
     │     DisabledRules, RuleNameMatch}                           │
     │   • Skip server if CodeFixApplied or MitigationApplied     │
     │   • If RuleNameMatch = $true → block apply, warn to        │
     │     rollback first then re-apply (name conflict)            │
     │   • If DisabledRules > 0 with no RuleNameMatch → proceed   │
     │     to apply (different name, no conflict)                  │
     │   • Is URL Rewrite installed? (if RequiresUrlRewrite)      │
     │   Skip server if protected or missing URL Rewrite          │
     └────────┬───────────────────────────────────────────────────┘
              │
              ├── -RollbackMitigation? ──Yes──► Invoke-RollbackMitigations
              │
              ├── (default) ──► Invoke-ApplyMitigations (remote Call 2)
              │
              ▼
     ┌────────────────────────────────────────────────┐
     │ MSERT (if -RunMSERT, local server only)       │
     │   Download → verify signature → run → report  │
     └────────────────────────────────────────────────┘
```

### Remote Execution Detail

When targeting remote servers, the framework makes **two remote calls** per server:

| Call | Purpose | Mechanism |
|------|---------|-----------|
| **Call 1** | Prerequisite check — run `TestVulnerable` and check URL Rewrite | `Invoke-ScriptBlockHandler` with the ScriptBlock passed as a string |
| **Call 2** | Apply or rollback — execute IIS changes | `Invoke-IISConfigurationManagerAction` → `Invoke-IISConfigurationRemoteAction` |

The ScriptBlock serialization pattern for Call 1:

```powershell
# ScriptBlocks can't be serialized over PS remoting, so we pass them as strings:
$testString = $MitigationDefinition.TestVulnerable.ToString()

# On the remote side, recreate the ScriptBlock:
$testScript = [ScriptBlock]::Create($testString)
$status = & $testScript
# $status is a hashtable: @{ MitigationApplied = $bool; CodeFixApplied = $bool; DisabledRules = @(); RuleNameMatch = $bool }
```

---

## 4. IIS Management Pipeline

The IIS Management module at `Security/src/IISManagement/` is a shared pipeline used by
both EOMT and ExchangeExtendedProtectionManagement. For a deep dive, see
[IISManagement-Developer.md](../IISManagement/IISManagement-Developer.md).

### Pipeline Summary

```
CVE Definition                    IIS Management Pipeline
─────────────────                 ───────────────────────────────
                                  ┌────────────────────────────┐
GetActions returns:          ──►  │ New-IISConfigurationAction │
  • Cmdlet                        │   Wraps each raw action    │
  • Parameters                    │   into a 3-part tuple:     │
  • RuleName (optional)           │   { Set, Get, Restore }    │
  • ElementName (optional)        └──────────┬─────────────────┘
                                             │
                                             ▼
                                  ┌───────────────────────────────────┐
                                  │ Invoke-IISConfigurationManager   │
                                  │ Action                           │
                                  │   Iterates servers               │
                                  │   Calls remote action per server │
                                  └──────────┬────────────────────────┘
                                             │
                                             ▼
                                  ┌───────────────────────────────────┐
                                  │ Invoke-IISConfigurationRemote    │
                                  │ Action                           │
                                  │   Per action:                    │
                                  │     1. Run Get (capture current) │
                                  │     2. Write restore to JSON     │
                                  │     3. Run Set (apply change)    │
                                  └──────────────────────────────────┘
```

### How New-IISConfigurationAction Wraps Actions

Each raw action from `GetActions` is converted into a tuple with three parts:

| Part | Purpose | Generated From |
|------|---------|----------------|
| **Set** | The change to apply | The original `Cmdlet` + `Parameters` |
| **Get** | Captures current value before change | Auto-generated `Get-WebConfigurationProperty` or `Get-WebConfiguration` |
| **Restore** | Reverts the change on rollback | Auto-generated inverse operation |

The restore cmdlet depends on the original cmdlet:

| Original Cmdlet | Restore Cmdlet | Notes |
|----------------|----------------|-------|
| `Set-WebConfigurationProperty` | `Set-WebConfigurationProperty` | Restores captured current value |
| `Add-WebConfigurationProperty` (with `RuleName`) | `Clear-WebConfiguration` | Removes the named element |
| `Add-WebConfigurationProperty` (without `RuleName`) | *(none)* | Parent element rollback handles cleanup |
| `Clear-WebConfiguration` | `Add-WebConfigurationProperty` | Re-creates removed entry |

---

## 5. Rollback Design

### Backup Files

When mitigations are applied, a per-CVE JSON backup file is created at:

```
%WINDIR%\System32\inetsrv\config\IISManagementRestoreCmdlets-{CVE-ID}.json
```

For example:

```
C:\Windows\System32\inetsrv\config\IISManagementRestoreCmdlets-CVE-2022-41040.json
```

The JSON file contains an array of restore cmdlets, each with:

```json
[
    {
        "Cmdlet": "Set-WebConfigurationProperty",
        "Parameters": {
            "Filter": "system.webServer/rewrite/rules/rule[@name='PowerShell - inbound']/match",
            "Name": "url",
            "Value": "<original value captured before apply>",
            "PSPath": "IIS:\\Sites\\Default Web Site"
        }
    },
    {
        "Cmdlet": "Clear-WebConfiguration",
        "Parameters": {
            "Filter": "system.webServer/rewrite/rules/rule[@name='PowerShell - inbound']"
        }
    }
]
```

### Rollback Flow

1. Read `IISManagementRestoreCmdlets-{CVE-ID}.json`.
2. Deserialize each entry. Convert `Parameters` from `PSObject` back to `hashtable`.
3. Execute each restore cmdlet: `& $entry.Cmdlet @parameters`.
4. On success, rename `.json` to `.bak` (preserves audit trail).
5. On failure, stop and report — the `.json` file is preserved for retry.

### Idempotent Apply

Applying the same CVE twice is safe. On the second apply:

- The framework detects an existing `.json` backup file.
- **The existing backup is preserved** — it is not overwritten. This ensures the backup
  always contains the *original* pre-mitigation state, not the already-mitigated state.
- The apply proceeds (re-applying the same rules), which is a no-op from IIS's perspective.

---

## 6. Key Design Decisions

### Why ScriptBlocks for TestVulnerable?

`TestVulnerable` is a `[ScriptBlock]` rather than a regular function because it
needs to execute on remote servers via `Invoke-ScriptBlockHandler`. PowerShell remoting
serializes ScriptBlocks as **dead objects** (they lose their code). The framework works
around this by:

1. Calling `.ToString()` on the ScriptBlock to get the code as a string.
2. Passing the string to the remote server.
3. Recreating the ScriptBlock with `[ScriptBlock]::Create($string)`.

This is why `TestVulnerable` cannot reference variables or functions from the
calling scope — it must be completely self-contained.

### Why RuleName Is Mandatory for Top-Level Add Actions

Without `RuleName`, `New-IISConfigurationAction` cannot generate a targeted
`Clear-WebConfiguration` rollback filter. The rollback would need to clear a broader
filter path, potentially removing other legitimate rules. Requiring `RuleName` ensures
rollback only removes exactly what was added.

Child elements (conditions inside a preCondition, for example) don't need `RuleName`
because they are automatically removed when the parent element is cleared.

### Why MSERT Is Local-Only

The Microsoft Safety Scanner (MSERT) must be downloaded from the internet. In a remote
execution scenario, each target server would need internet access to download the binary,
which is not guaranteed in enterprise environments. Instead, MSERT runs only on the local
machine where the script is executed.

### Why begin/process/end Pipeline

The `begin`/`process`/`end` pipeline pattern enables idiomatic PowerShell usage with
`Get-ExchangeServer`:

```powershell
Get-ExchangeServer | .\EOMT.ps1 -CVE "CVE-2022-41040"
```

- `begin`: One-time initialization (load definitions, set up TLS).
- `process`: Runs once per piped server — collects names into a list.
- `end`: All servers are known — run prerequisites, apply, rollback, or status in bulk.

This pattern is preferred over `$input` or `@()` accumulation because it integrates
naturally with Exchange Management Shell workflows.

---

## 7. Common Pitfalls

### Don't Use Exchange Management Shell Cmdlets in TestVulnerable

IIS cmdlets (`Get-WebConfiguration`, `Get-WebConfigurationProperty`) are allowed because the
WebAdministration module is always available on Exchange servers. However, Exchange Management
Shell cmdlets require the EMS snapin which may not be loaded in the remote session.

```powershell
# ❌ WRONG — Get-ExchangeServer requires the Exchange Management Shell snapin
TestVulnerable = {
    $server = Get-ExchangeServer -Identity $env:COMPUTERNAME
    return @{ MitigationApplied = $false; CodeFixApplied = ($server.AdminDisplayVersion -ge "15.2.1118.20") }
}

# ✅ CORRECT — Use built-in commands and IIS cmdlets
TestVulnerable = {
    $info = Get-Command ExSetup.exe -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo }
    $codeFixApplied = ([System.Version]$info.FileVersion -ge "15.02.1118.020")
    $rule = Get-WebConfiguration -Filter "system.webServer/rewrite/rules/rule[@name='MyRule']" -PSPath "IIS:\" -ErrorAction SilentlyContinue
    $mitigationApplied = ($null -ne $rule -and $rule.enabled -ne $false)
    return @{
        MitigationApplied = $mitigationApplied
        CodeFixApplied    = $codeFixApplied
        DisabledRules     = @()
        RuleNameMatch     = $false
    }
}
```

### Set-WebConfigurationProperty with Name='.' on Some IIS Collections

Some IIS collections (like preCondition conditions) don't support
`Set-WebConfigurationProperty -Name '.'` to add new entries. Use
`Add-WebConfigurationProperty` instead:

```powershell
# ❌ May fail on preCondition sub-elements
[PSCustomObject]@{
    Cmdlet     = "Set-WebConfigurationProperty"
    Parameters = @{
        Filter = "$outboundRoot/preConditions/preCondition[@name='MyPreCondition']"
        Name   = '.'
        Value  = @{ input = '{RESPONSE_CONTENT_TYPE}'; pattern = '^text/html' }
        PSPath = $site
    }
}

# ✅ Use Add-WebConfigurationProperty for collection entries
[PSCustomObject]@{
    Cmdlet     = "Add-WebConfigurationProperty"
    Parameters = @{
        Filter = "$outboundRoot/preConditions/preCondition[@name='MyPreCondition']"
        Name   = '.'
        Value  = @{ input = '{RESPONSE_CONTENT_TYPE}'; pattern = '^text/html' }
        PSPath = $site
    }
}
```

### PS Remoting Serializes ScriptBlocks as Dead Objects

If you pass a `[ScriptBlock]` over PowerShell remoting, it arrives as a deserialized
object that **cannot be invoked**. Always convert to string first:

```powershell
# ❌ WRONG — $scriptBlock is a dead deserialized object on the remote side
Invoke-Command -ComputerName $server -ScriptBlock {
    param($scriptBlock)
    & $scriptBlock
} -ArgumentList $myScriptBlock

# ✅ CORRECT — Pass as string, recreate on the remote side
$scriptString = $myScriptBlock.ToString()
Invoke-Command -ComputerName $server -ScriptBlock {
    param($codeString)
    $sb = [ScriptBlock]::Create($codeString)
    & $sb
} -ArgumentList $scriptString
```

### ConvertTo-Json on IIS Configuration Objects Can Hang

The `Invoke-IISConfigurationRemoteAction` function writes restore actions to JSON using
`ConvertTo-Json -Depth 5`. Some IIS configuration objects have deeply nested or circular
references that cause `ConvertTo-Json` to hang. The framework includes a fallback:

```powershell
# Primary attempt
$json = $restoreActions | ConvertTo-Json -Depth 5

# Fallback if the above hangs or fails
$json = $restoreActions | ConvertTo-Json -Depth 5 -Compress
```

If you encounter this issue during testing, verify that your action `Value` parameters
contain only simple types (strings, booleans, numbers) — not IIS configuration objects.

---

## 8. Testing

### Pester Unit Tests

The IIS Management pipeline has **78 Pester tests** located at:

```
Security/src/IISManagement/Tests/
├── Get-ParameterString.Tests.ps1                    (7 tests)
├── Invoke-IISConfigurationManagerAction.Tests.ps1   (7 tests)
├── Invoke-IISConfigurationRemoteAction.Tests.ps1    (21 tests)
└── New-IISConfigurationAction.Tests.ps1             (43 tests)
```

These tests cover:
- Set/Get/Restore tuple generation and validation
- `RuleName` and `ElementName` handling
- Backup JSON creation and restore execution
- Error handling and failure paths
- Server iteration and mixed success/failure scenarios
- Parameter string formatting

### CVE-Specific TestVulnerable Tests

Each new CVE definition should have a corresponding Pester test file at
`Security/src/EOMT/Mitigations/Tests/CVE-YYYY-NNNNN.Tests.ps1`. Use
`CVE-2026-42897.Tests.ps1` as a template. At minimum, include tests for:

| Category | Test cases |
|----------|-----------|
| Mitigation detection | Full match (enabled), different name still matches, wrong behavior does not match, missing preCondition does not match |
| Disabled rule detection | Disabled + our name → `RuleNameMatch = $true`, disabled + different name → `RuleNameMatch = $false` |
| RuleNameMatch detection | Our name with wrong behavior → `RuleNameMatch = $true`, different name with wrong behavior → `RuleNameMatch = $false` |
| Code fix detection | At threshold, above threshold, below threshold |

Mock IIS cmdlets with stub functions (`Get-WebConfiguration`) and use helper functions
to build mock rule/preCondition objects with `enabled`, `match`, `action`, and
`GetCollection()` support.
- Server iteration and mixed success/failure scenarios
- Parameter string formatting

### Code Quality Gates

Before submitting a PR, ensure both pass:

```powershell
# Auto-format code to match project style conventions
.\.build\CodeFormatter.ps1 -Save -Branch next-release

# Check for spelling errors in code and comments
.\.build\SpellCheck.ps1 -Branch next-release
```

### Lab Testing Checklist

Use a lab environment with Exchange Server and IIS URL Rewrite Module installed.

| # | Test | Command | Expected Result |
|---|------|---------|-----------------|
| 1 | Apply mitigation | `.\EOMT.ps1 -CVE "CVE-YYYY-NNNNN"` | Rule visible in IIS Manager, backup JSON created |
| 2 | Verify block | `curl https://server/path` | Attack pattern returns expected error/abort |
| 3 | WhatIf | `.\EOMT.ps1 -WhatIf -CVE "CVE-YYYY-NNNNN"` | Shows actions without changing IIS |
| 4 | Status check | `.\EOMT.ps1 -ShowMitigationStatus -CVE "CVE-YYYY-NNNNN"` | Reports correct vulnerability state |
| 5 | Rollback | `.\EOMT.ps1 -RollbackMitigation -CVE "CVE-YYYY-NNNNN"` | Rule removed, `.json` renamed to `.bak` |
| 6 | Verify clean | Check IIS Manager | No leftover rules or preConditions |
| 7 | Apply twice | Apply → Apply again | Second apply uses existing backup, no corruption |
| 8 | Remote apply | `Get-ExchangeServer \| .\EOMT.ps1 -CVE "CVE-YYYY-NNNNN"` | All servers mitigated successfully |
| 9 | Remote rollback | `Get-ExchangeServer \| .\EOMT.ps1 -RollbackMitigation -CVE "CVE-YYYY-NNNNN"` | All servers restored |

---

## Further Reading

- [IIS URL Rewrite Module](https://www.iis.net/downloads/microsoft/url-rewrite)
- [Exchange Server Security Updates](https://aka.ms/exchangevulns)
- [EOMT Public Documentation](https://microsoft.github.io/CSS-Exchange/Security/EOMT/)
