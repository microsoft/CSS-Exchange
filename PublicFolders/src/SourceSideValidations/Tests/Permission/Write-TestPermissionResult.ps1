# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-ResultSummary.ps1

function Write-TestPermissionResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $badPermissionResults = New-Object System.Collections.ArrayList
    }

    process {
        if ($TestResult.TestName -eq "Permission" -and $TestResult.ResultType -eq "BadPermission") {
            [void]$badPermissionResults.Add($TestResult)
        }
    }

    end {
        if ($badPermissionResults.Count -gt 0) {
            Get-ResultSummary -ResultType $badPermissionResults[0].ResultType -Severity $badPermissionResults[0].Severity -Count $badPermissionResults.Count -Action (
                "Invalid permissions were found. These can be removed using the RemoveInvalidPermissions switch as follows:`n`n" +
                ".\SourceSideValidations.ps1 -RemoveInvalidPermissions")
        }
    }
}
