# IIS Configuration Management — Developer Guide

> **Audience**: Junior developers contributing to EOMT or ExchangeExtendedProtectionManagement.
> **Last updated**: July 2025

---

## 1. Overview

The IIS Configuration Management module provides a safe, reversible way to apply IIS configuration changes across one or more Exchange servers. Every change the module makes can be rolled back because the framework automatically captures the current state before modifying it.

### What it does

- Applies IIS configuration changes (properties, URL Rewrite rules, request filtering, etc.)
- Automatically backs up the current value of every setting before changing it
- Saves backup data to a JSON file on each target server
- Supports rollback by replaying the saved restore actions

### Who uses it

| Consumer | Purpose |
|----------|---------|
| **EOMT** (Exchange On-premises Mitigation Tool) | Applies and rolls back CVE mitigations (URL Rewrite rules, request filtering) |
| **ExchangeExtendedProtectionManagement** | Configures Extended Protection settings across Exchange servers |

### Key principle

> Every change is captured in a **Set / Get / Restore** action tuple so it can be reversed.

The `Set` describes what to change, the `Get` reads the current value (for backup), and the `Restore` describes how to undo the change. This three-part structure is the foundation of the entire module.

---

## 2. Architecture

The module is organized as a three-layer pipeline. Each layer has a single responsibility:

```
New-IISConfigurationAction        →  Action Factory (build tuples)
Invoke-IISConfigurationManagerAction  →  Server Iterator (fan out to servers)
Invoke-IISConfigurationRemoteAction   →  Execution Engine (backup, save, apply)
```

### New-IISConfigurationAction (Action Factory)

This function takes a raw action object — a simple `[PSCustomObject]` with a `Cmdlet` string and a `Parameters` hashtable — and wraps it into a three-part tuple:

| Part | Purpose |
|------|---------|
| **Set** | The cmdlet to execute (the change you want to make) |
| **Get** | The cmdlet to read the current value before the change (for backup) |
| **Restore** | The cmdlet to reverse the change (for rollback) |

#### Supported cmdlet types

| Cmdlet | Get Uses | Restore Uses | Notes |
|--------|----------|--------------|-------|
| `Set-WebConfigurationProperty` | `Get-WebConfigurationProperty` | `Set-WebConfigurationProperty` | Captures current value, restores it on rollback |
| `Add-WebConfigurationProperty` (with `RuleName`) | `Get-WebConfiguration` | `Clear-WebConfiguration` | Checks if element exists, clears it on rollback |
| `Add-WebConfigurationProperty` (without `RuleName`) | `null` | `null` | Sub-collection items — parent rollback handles cleanup |
| `Clear-WebConfiguration` | `Get-WebConfiguration` | `Add-WebConfigurationProperty` | Captures element before removal, re-adds on rollback |
| Any other cmdlet | `null` | `null` | Executed without backup/restore |

#### Special parameters

- **`RuleName`**: Required for top-level `Add` actions. Used to build a targeted `Clear` filter like:
  ```
  system.webServer/rewrite/rules/rule[@name='RuleName']
  ```
- **`ElementName`**: Optional, defaults to `"rule"`. Override with `"preCondition"` etc. for non-rule collection types.
- **`ErrorAction` and `WhatIf`**: Automatically injected into the Set parameters by the factory. You do not need to include them in your raw action.

#### Example usage

```powershell
$action = [PSCustomObject]@{
    Cmdlet     = "Set-WebConfigurationProperty"
    Parameters = @{
        Filter = "system.webServer/security/requestFiltering"
        Name   = "allowHighBitCharacters"
        Value  = "false"
        PSPath = "IIS:\"
    }
}

$wrapped = New-IISConfigurationAction -Action $action
# $wrapped.Set     → executes Set-WebConfigurationProperty
# $wrapped.Get     → executes Get-WebConfigurationProperty (reads current value)
# $wrapped.Restore → executes Set-WebConfigurationProperty (restores original value)
```

---

### Invoke-IISConfigurationManagerAction (Server Iterator)

This function receives `InputObject`(s) via the pipeline. Each `InputObject` contains:

- `ServerName` — the target server
- `Actions` — an array of action tuples (from `New-IISConfigurationAction`)
- `BackupFileName` — identifier for the backup JSON file

**Or**, for restore operations:

- `ServerName` — the target server
- `Restore` — an object with `FileName` and `PassedWhatIf`

#### What it does

1. Collects all `InputObject`s from the pipeline
2. Iterates each server sequentially (with progress bar)
3. Calls `Invoke-ScriptBlockHandler` to execute `Invoke-IISConfigurationRemoteAction` on each server
4. Tracks which servers succeeded and which failed
5. Returns a result object:

```powershell
[PSCustomObject]@{
    FailedServers     = [List[object]]   # servers where execution failed
    SuccessfulServers = [List[object]]   # servers where execution succeeded
    AllSucceeded      = [bool]           # true when no failures and at least one success
}
```

> **Note**: The return value is non-breaking — callers that don't capture it are unaffected. The function also writes `Write-Host` and `Write-Warning` output for console visibility.

---

### Invoke-IISConfigurationRemoteAction (Execution Engine)

This function runs on each target server (locally or via PowerShell remoting). It operates in one of two modes based on which properties are present on `InputObject`.

#### Apply mode (`InputObject` has `.Actions`)

Runs through three phases:

**Phase 1 — Backup**

For each action that has a `Get`:

1. Executes the Get cmdlet to read the current value
2. If a backup JSON already exists, checks whether this restore action is already recorded (preserves the first-apply state — never overwrites the original backup)
3. Builds a restore action with the captured current value

Special null-value handling:

| Scenario | Behavior |
|----------|----------|
| `Add` action, current value is `null` | Rule doesn't exist yet. Records a `Clear` restore action (no `Value` parameter needed) |
| `Set` action, current value is `null` | Skips restore action (nothing to restore to) |
| Other action, current value is `null` | Skips restore action |
| Action has no `Get` (null) | Skips entirely — sub-collection item whose parent handles rollback |

**Phase 2 — Save**

Writes the restore actions list to a JSON file:

```
%WINDIR%\System32\inetsrv\config\IISManagementRestoreCmdlets-{BackupFileName}.json
```

If `ConvertTo-Json` fails (legacy OS compatibility), retries with the `-Compress` parameter.

**Phase 3 — Set**

Executes each action's Set cmdlet. Failures are caught per-action with `try/catch` — execution continues through remaining actions even if one fails.

#### Restore mode (`InputObject` has `.Restore`)

1. Loads the JSON backup file from disk
2. Converts JSON properties back to parameter collections
3. Executes each restore cmdlet from the JSON
4. On success, renames the backup file from `.json` to `.bak`

#### Return value

```powershell
[PSCustomObject]@{
    ComputerName              = [string]   # server where this ran
    SuccessfulExecution       = [bool]     # true ONLY when ALL four conditions below are met
    AllActionsPerformed        = [bool]     # all Set (or Restore) cmdlets succeeded
    GatheredAllRestoreActions  = [bool]     # all Get cmdlets succeeded
    RestoreActionsSaved        = [bool]     # JSON file was written successfully
    ErrorContext               = [List]     # caught exceptions (empty on success)
    RestoreActions             = [List]     # restore action objects (for logging)
}
```

The `SuccessfulExecution` formula:

```powershell
$allActionsPerformed -and $gatheredAllRestoreActions -and $restoreActionsSaved -and $errorContext.Count -eq 0
```

---

### Get-ParameterString (Utility)

Converts a hashtable to a human-readable string for logging:

```powershell
Get-ParameterString @{ Filter = "system.webServer"; Name = "enabled" }
# Output: -Filter "system.webServer" -Name "enabled"
```

Used throughout the module and tests for verbose/debug output.

---

## 3. Data Flow Diagram

```
Caller (EOMT / EP Management)
  │
  ▼
New-IISConfigurationAction   ← wraps each raw action into Set/Get/Restore tuple
  │
  ▼
InputObject { ServerName, Actions[], BackupFileName }
  │
  ▼ (pipeline)
Invoke-IISConfigurationManagerAction   ← iterates servers
  │
  ▼ (per server, via Invoke-ScriptBlockHandler)
Invoke-IISConfigurationRemoteAction    ← backup → save JSON → execute Set actions
  │
  ▼
IIS Configuration Changed + JSON Backup Saved
```

### Restore flow

```
Caller
  │
  ▼
InputObject { ServerName, Restore: { FileName, PassedWhatIf } }
  │
  ▼ (pipeline)
Invoke-IISConfigurationManagerAction   ← iterates servers
  │
  ▼ (per server)
Invoke-IISConfigurationRemoteAction    ← load JSON → execute restore cmdlets → rename .json → .bak
  │
  ▼
IIS Configuration Restored
```

---

## 4. JSON Backup Format

The backup file is a JSON array of cmdlet/parameter pairs. Each entry has enough information to replay the restore action independently.

### Example

```json
[
  {
    "Cmdlet": "Set-WebConfigurationProperty",
    "Parameters": {
      "Filter": "system.webServer/security/requestFiltering",
      "Name": "allowHighBitCharacters",
      "PSPath": "IIS:\\",
      "ErrorAction": "Stop",
      "Value": "true"
    }
  },
  {
    "Cmdlet": "Clear-WebConfiguration",
    "Parameters": {
      "Filter": "system.webServer/rewrite/rules/rule[@name='MyRule']",
      "PSPath": "IIS:\\",
      "ErrorAction": "Stop"
    }
  }
]
```

### File details

| Property | Value |
|----------|-------|
| **Location** | `%WINDIR%\System32\inetsrv\config\` |
| **Naming** | `IISManagementRestoreCmdlets-{identifier}.json` |
| **After rollback** | Renamed to `.bak` (prevents accidental double-restore) |
| **Encoding** | Written via `Out-File` (system default encoding) |

---

## 5. Remote Execution

### How functions travel to remote servers

`Invoke-IISConfigurationManagerAction` uses a PowerShell technique to capture the function body as a script block:

```powershell
$result = Invoke-ScriptBlockHandler `
    -ComputerName $server.ServerName `
    -ArgumentList $server `
    -ScriptBlock ${Function:Invoke-IISConfigurationRemoteAction}
```

The `${Function:FunctionName}` syntax retrieves the function's body as a `[ScriptBlock]`. `Invoke-ScriptBlockHandler` then executes it via `Invoke-Command -ComputerName`.

### Nested helper functions

`Invoke-IISConfigurationRemoteAction` defines its helper functions (`Write-VerboseAndLog`, `GetLocationValue`) **inside** the function body. This is intentional — when the function body is serialized for remoting, the helpers travel with it. Any dot-sourced dependencies at the top level would **not** be available in the remote session.

### Serialization pitfalls

**ScriptBlock parameters become dead objects remotely:**

`[ScriptBlock]` objects passed in `-ArgumentList` are deserialized as `Deserialized.ScriptBlock` on the remote side — they cannot be invoked. If you need to pass a script block to a remote function, convert it to a string first and recreate it on the other side:

```powershell
# Caller side
$sb = { Get-Process }
Invoke-Command -ComputerName $server -ArgumentList $sb.ToString() -ScriptBlock {
    param($sbText)
    $remoteBlock = [ScriptBlock]::Create($sbText)
    & $remoteBlock
}
```

**PowerShell 7 member enumeration bug:**

In PowerShell 5, `$array.Property` enumerates the property across all items in the array. In PowerShell 7, if `Property` is also a method name on the array type, PS7 resolves to the method instead of enumerating.

```powershell
# Dangerous — behaves differently in PS5 vs PS7:
$actions.Parameters

# Safe — explicit iteration works consistently:
foreach ($action in $actions) {
    $action.Parameters
}
```

---

## 6. Historical Bugs (Regression Tests)

The test suite includes regression tests for three bugs that were found in production. Understanding these helps avoid repeating similar mistakes.

| Bug | Commit | Description | Test Coverage |
|-----|--------|-------------|---------------|
| **SuccessfulExecution formula** | `ce0908097` | Used `$restoreActions` (a `List` object, always truthy even when empty) instead of `$restoreActionsSaved` (a boolean). This meant `SuccessfulExecution` could be `$true` even when the JSON file failed to save. | Bug 1 tests validate the formula uses the boolean flag |
| **Backup action handling** | `9429952036` | Used `[System.IO.Path]::Join` (which concatenates without separators) instead of `::Combine`. Also lacked `try/catch` around individual Set actions, so one failure would abort all remaining actions. | Bug 2 tests verify path construction and per-action error isolation |
| **Legacy OS ConvertTo-Json** | `ce2260e94` | `ConvertTo-Json` without `-Compress` fails on older Windows versions. Added a fallback that retries with `-Compress`. | Bug 3 tests verify the fallback path |

---

## 7. Pester Tests

### Overview

- **78 tests** across 4 test files
- All tests run without a real IIS installation

### File breakdown

| File | Tests | Purpose |
|------|-------|---------|
| `Get-ParameterString.Tests.ps1` | 7 | Validates hashtable-to-string conversion |
| `New-IISConfigurationAction.Tests.ps1` | 43 | Action factory: validates Set/Get/Restore tuple creation for all cmdlet types |
| `Invoke-IISConfigurationRemoteAction.Tests.ps1` | 21 | Execution engine: backup/restore flow, error propagation, null value handling, historical regressions |
| `Invoke-IISConfigurationManagerAction.Tests.ps1` | 7 | Server iteration: success/failure tracking, result object |

### Stub design

All tests use stub IIS cmdlets (`Set-WebConfigurationProperty`, `Get-WebConfigurationProperty`, `Add-WebConfigurationProperty`, `Clear-WebConfiguration`, `Get-WebConfiguration`). These stubs replace the real IIS cmdlets so tests can run anywhere.

**Important**: Stubs use an explicit `-WhatIf` switch parameter — **not** `[CmdletBinding(SupportsShouldProcess)]`. This avoids PSScriptAnalyzer conflicts where the analyzer would flag missing `ShouldProcess` calls in stub functions that declare `SupportsShouldProcess`.

### Collection types in tests

Tests use `[System.Collections.Generic.List[object]]` for the Actions array to match production behavior. This is important because of the PowerShell 7 member enumeration issue described in section 5 — using a plain `@()` array can mask bugs that only appear with `List[object]`.

### Key test categories

- **Action factory validation** — correct tuple generation for each cmdlet type
- **Backup/restore flow** — JSON round-trip, existing backup preservation
- **Error propagation** — individual action failures don't abort the pipeline
- **Null value handling** — Add vs Set vs other cmdlets when current value is null
- **Historical regression** — the three bugs documented in section 6

---

## 8. Common Pitfalls

### ConvertTo-Json on IIS objects

IIS configuration objects can contain circular references that cause `ConvertTo-Json` to hang indefinitely. The framework handles this with a fallback to `-Compress`, but if you're debugging and manually serializing IIS objects, be aware of this behavior.

### WhatIf in stubs

When writing test stubs for IIS cmdlets, **do not** use `[CmdletBinding(SupportsShouldProcess)]`. Instead, add an explicit `-WhatIf` switch parameter:

```powershell
# ✅ Correct — explicit switch
function Set-WebConfigurationProperty {
    param(
        [switch]$WhatIf,
        # ... other params
    )
}

# ❌ Wrong — triggers PSScriptAnalyzer warnings
function Set-WebConfigurationProperty {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # ... params
    )
}
```

### Member enumeration

Never use the `$collection.Property` shorthand for iterating properties across a collection. Always use explicit iteration:

```powershell
# ❌ Dangerous — different behavior in PS5 vs PS7
$actions.Cmdlet

# ✅ Safe — works consistently everywhere
foreach ($action in $actions) {
    $action.Cmdlet
}
```

### Out-File encoding

`Write-VerboseAndLog` uses `Out-File` internally. In PowerShell 7, `Out-File` defaults to UTF-8 without BOM and may emit a warning about the `'utf8'` encoding. This is cosmetic and does not affect functionality.

### ErrorAction on Get vs Restore

The framework intentionally uses different `ErrorAction` values:

| Phase | ErrorAction | Reason |
|-------|-------------|--------|
| **Get** (backup) | `SilentlyContinue` | Checking if a value exists — absence is a valid state |
| **Restore** (rollback) | `Stop` | Restoring must succeed — failures need to surface |
| **Set** (apply) | `Stop` | Changes should throw on failure for per-action error handling |

---

## File Structure Reference

```
Security/src/IISManagement/
├── Get-ParameterString.ps1                          # Utility: hashtable → string
├── Invoke-IISConfigurationManagerAction.ps1          # Layer 2: Server iterator
├── Invoke-IISConfigurationRemoteAction.ps1           # Layer 3: Execution engine
├── New-IISConfigurationAction.ps1                    # Layer 1: Action factory
├── IISManagement-Developer.md                        # This file
└── Tests/
    ├── Get-ParameterString.Tests.ps1
    ├── Invoke-IISConfigurationManagerAction.Tests.ps1
    ├── Invoke-IISConfigurationRemoteAction.Tests.ps1
    └── New-IISConfigurationAction.Tests.ps1
```
