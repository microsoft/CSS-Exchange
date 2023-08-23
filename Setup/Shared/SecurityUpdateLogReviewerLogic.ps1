# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\SecurityUpdateLogReviewerFunctions.ps1
. $PSScriptRoot\..\SecurityUpdateLogReviewer\Checks\Write-Result.ps1

function Invoke-SecurityUpdateLogReviewer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.IO.FileInfo]$SecurityUpdateLog
    )

    begin {
        function InvokeTests {
            [CmdletBinding()]
            param(
                [object]$SecurityUpdateLogReviewer,
                [string[]]$Tests
            )

            foreach ($test in $Tests) {
                $result = $SecurityUpdateLogReviewer | & $test

                if ($null -ne $result) {
                    $result | Write-Result
                    break
                }
            }
        }
    }
    process {
        if (-not ([IO.File]::Exists($SecurityUpdateLog))) {
            Write-Error "Could not find file: $SecurityUpdateLog"
            return
        }

        $securityUpdateLogReviewer = Get-SecurityUpdateLogReviewer -SecurityUpdateLog $SecurityUpdateLog



    }
}