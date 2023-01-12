# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1

function Test-InstallWatermark {
    [CmdletBinding()]
    param()
    begin {
        $resultParams = @{
            TestName      = "Install Watermark"
            Result        = "Passed"
            Details       = [string]::Empty
            ReferenceInfo = "More Information: https://aka.ms/SA-InstallWatermark"
        }
    }
    process {
        $waterMarks = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15' -Recurse |
            Where-Object { $null -ne $_.Property -and $_.Property.Contains("Watermark") }

        if ($null -ne $waterMarks) {
            Write-Verbose "Watermark detected"

            foreach ($waterMark in $waterMarks) {

                if ($waterMark.GetValue("Action") -eq "Install") {
                    $resultParams.Result = "Failed"
                    $resultParams.Details += $waterMark.GetValue("Watermark") + [System.Environment]::NewLine
                } else {
                    Write-Verbose "Watermark didn't contain action of install"
                }
            }
        }
    }
    end {
        New-TestResult @resultParams
    }
}
