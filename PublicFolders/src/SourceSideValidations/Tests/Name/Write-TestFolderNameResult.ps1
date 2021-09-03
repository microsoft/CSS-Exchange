# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        if ($TestResult.Name -eq "FolderName" -and $TestResult.ResultType -eq "SpecialCharacters") {
            $badNames += $TestResult
        }
    }

    end {
        if ($badNames.Count -gt 0) {
            Write-Host
            Write-Host $badNames.Count "folders have characters @, /, or \ in the folder name."
            Write-Host "These are shown in the results CSV with a result type of SpecialCharacters."
            Write-Host "These folders should be renamed prior to migrating. The following command"
            Write-Host "can be used:"
            Write-Host "Import-Csv .\ValidationResults.csv | ? ResultType -eq SpecialCharacters | % { Set-PublicFolder `$_.FolderEntryId -Name (`$_.ResultData -replace `"@|/|\\`") }" -ForegroundColor Green
        }
    }
}
