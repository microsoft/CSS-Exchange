# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1

function Test-FolderName {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Checking names"
            Id       = 2
            ParentId = 1
        }
        $testResultParams = @{
            TestName   = "FolderName"
            Severity   = "Error"
            ResultType = "SpecialCharacters"
        }
    }

    process {
        $FolderData.IpmSubtree | ForEach-Object {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.IpmSubtree.Count)
            }

            if ($_.Name -match "@|/|\\") {
                $testResultParams.FolderIdentity = $_.Identity.ToString()
                $testResultParams.FolderEntryId = $_.EntryId.ToString()
                $testResultParams.ResultData = $_.Name
                New-TestResult @testResultParams
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed

        $params = @{
            TestName       = $testResultParams.TestName
            ResultType     = "Duration"
            Severity       = "Information"
            FolderIdentity = ""
            FolderEntryId  = ""
            ResultData     = ((Get-Date) - $startTime)
        }

        New-TestResult @params
    }
}
