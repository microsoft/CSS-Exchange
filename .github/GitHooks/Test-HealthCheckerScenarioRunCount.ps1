# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Blocks commits when test files exceed the max pipeline run count.
.DESCRIPTION
    Scans staged .Tests.ps1 files for SetDefaultRunOfHealthChecker calls.
    Blocks the commit if any file exceeds 5 runs (the benchmarked optimal maximum).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Files
)

$maxRunsPerFile = 5
$failed = $false

foreach ($file in $Files) {
    if (-not (Test-Path $file)) { continue }

    # Count actual calls only, excluding comments and strings
    try {
        $content = Get-Content -Path $file -Raw -ErrorAction Stop
    } catch {
        Write-Host "  BLOCKED: $file - Unable to read file: $($_.Exception.Message)" -ForegroundColor Red
        $failed = $true
        continue
    }
    $parseErrors = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$parseErrors)

    if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
        Write-Host "  WARN: $file has $($parseErrors.Count) parse error(s) - run count may be inaccurate" -ForegroundColor Yellow
    }

    $runCount = @($tokens | Where-Object {
            $_.Type -eq 'Command' -and $_.Content -eq 'SetDefaultRunOfHealthChecker'
        }).Count

    if ($runCount -gt $maxRunsPerFile) {
        Write-Host "  BLOCKED: $file has $runCount pipeline runs (max: $maxRunsPerFile)" -ForegroundColor Red
        Write-Host "        Consider splitting this file. Balance runs evenly (e.g., 4+2 not 5+1)." -ForegroundColor Yellow
        $failed = $true
    } elseif ($runCount -gt 0) {
        Write-Host "  OK: $file - $runCount pipeline run(s)" -ForegroundColor Green
    }
}

# Use 'git commit --no-verify' to bypass if needed
if ($failed) {
    Write-Host "`nTest run count check found issues. See above." -ForegroundColor Red
    return 1
}

return 0
