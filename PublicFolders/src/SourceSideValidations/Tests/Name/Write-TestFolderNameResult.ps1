# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-ResultSummary.ps1

function Write-TestFolderNameResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $badNames = New-Object System.Collections.ArrayList
    }

    process {
        if ($TestResult.TestName -eq "FolderName" -and $TestResult.ResultType -eq "SpecialCharacters") {
            [void]$badNames.Add($TestResult)
        }
    }

    end {
        if ($badNames.Count -gt 0) {
            Get-ResultSummary -ResultType $badNames[0].ResultType -Severity $badNames[0].Severity -Count $badNames.Count -Action (
                "Folders have characters @, /, or \ in the folder name. " +
                "These folders should be renamed prior to migrating. The following command " +
                "can be used:`n`n" +
                "Import-Csv .\ValidationResults.csv |`n" +
                " ? ResultType -eq SpecialCharacters |`n" +
                " % {`n" +
                "  `$newName = (`$_.ResultData -replace `"@|/|\\`", `" `").Trim()`n" +
                "  Set-PublicFolder `$_.FolderEntryId -Name `$newName`n" +
                " }")
        }
    }
}
