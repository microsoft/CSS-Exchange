# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 7

. $PSScriptRoot\Load-Module.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckContainsCurlyQuotes.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckFileHasNewlineAtEndOfFile.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckMarkdownFileHasNoBOM.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckMultipleEmptyLines.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFileHasBOM.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFileHasComplianceHeader.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFormat.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckTokenTypeCasing.ps1

function Invoke-CodeFormatterOnFiles {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]
        $FilePaths,

        [switch]
        $Save
    )

    if (-not (Load-Module -Name PSScriptAnalyzer -MinimumVersion "1.24")) {
        throw "PSScriptAnalyzer module could not be loaded"
    }

    if (-not (Load-Module -Name EncodingAnalyzer)) {
        throw "EncodingAnalyzer module could not be loaded"
    }

    $repoRoot = Get-Item "$PSScriptRoot\.."
    $errorCount = 0
    $filesToCheck = New-Object System.Collections.Generic.List[object]

    foreach ($path in $FilePaths) {
        if (Test-Path -Path $path) {
            $filesToCheck.Add((Get-Item -Path $path))
        } else {
            Write-Warning "File not found, skipping: $path"
        }
    }

    if ($filesToCheck.Count -eq 0) {
        Write-Host "No valid files to check."
        return 0
    }

    foreach ($fileInfo in $filesToCheck) {
        $errorCount += (CheckFileHasNewlineAtEndOfFile $fileInfo $Save) ? 1 : 0
        $errorCount += (CheckMarkdownFileHasNoBOM $fileInfo $Save) ? 1 : 0
        $errorCount += (CheckScriptFileHasBOM $fileInfo $Save) ? 1 : 0
        $errorCount += (CheckScriptFileHasComplianceHeader $fileInfo $Save) ? 1 : 0
        $errorCount += (CheckTokenTypeCasing $fileInfo $Save "Keyword") ? 1 : 0
        $errorCount += (CheckTokenTypeCasing $fileInfo $Save "Operator") ? 1 : 0
        $errorCount += (CheckMultipleEmptyLines $fileInfo $Save) ?  1 : 0
        $errorCount += (CheckContainsCurlyQuotes $fileInfo $Save) ? 1 : 0

        $results = @(CheckScriptFormat $fileInfo $Save)
        if ($results.Length -gt 0 -and $results[0] -eq $true) {
            $errorCount++
            if ($results.Length -gt 2) {
                git -c color.status=always diff ($($results[1]) | git hash-object -w --stdin) ($($results[2]) | git hash-object -w --stdin) | Out-Host
            }
        }
    }

    $maxRetries = 5

    foreach ($fileInfo in $filesToCheck) {
        for ($i = 0; $i -lt $maxRetries; $i++) {
            try {
                $params = @{
                    Path                = ($fileInfo.FullName)
                    Settings            = "$repoRoot\PSScriptAnalyzerSettings.psd1"
                    CustomRulePath      = "$repoRoot\.build\CodeFormatterChecks\CustomRules.psm1"
                    IncludeDefaultRules = $true
                }
                $analyzerResults = Invoke-ScriptAnalyzer @params
                if ($null -ne $analyzerResults) {
                    $errorCount++
                    $analyzerResults | Format-Table -AutoSize | Out-Host
                }
                break
            } catch {
                Write-Warning "Invoke-ScriptAnalyzer failed on $($fileInfo.FullName). Error:"
                $_.Exception | Format-List | Out-Host
                Write-Warning "Retrying in 5 seconds."
                Start-Sleep -Seconds 5
            }
        }

        if ($i -eq $maxRetries) {
            throw "Invoke-ScriptAnalyzer failed $maxRetries times. Giving up."
        }
    }

    return $errorCount
}
