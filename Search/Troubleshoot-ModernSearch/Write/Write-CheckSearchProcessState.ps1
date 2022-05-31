# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Exchange\Get-SearchProcessState.ps1
. $PSScriptRoot\Write-DisplayObjectInformation.ps1
function Write-CheckSearchProcessState {
    [CmdletBinding()]
    param(
        [string]$ActiveServer
    )
    begin {
        $searchProcessState = Get-SearchProcessState -ComputerName $ActiveServer
        $thirdPartyModuleFound = $false
        $checksPassed = $true
        $status = "Passed"
    }
    process {

        if (-not ($searchProcessState.ServicesCheckPass) -or
            -not ($searchProcessState.ProcessesCheckPass)) {
            $checksPassed = $false
            $status = "Failed"
        }

        Write-Host "----------------------------------------"
        Write-Host "Search Processes Status: $status"

        if (-not($checksPassed)) {
            Write-Host "Latest Process Start: $($searchProcessState.LatestProcessStartTime)"
        }

        foreach ($key in $searchProcessState.ProcessResults.Keys) {

            $process = $searchProcessState.ProcessResults[$key]

            Write-Verbose "------------------------"
            Write-Verbose "Process: $key"
            Write-Verbose "PID: $($process.PID)"
            Write-Verbose "StartTime: $($process.StartTime)"

            if ($process.StartTime -eq [DateTime]::MinValue) {
                Write-Host "Process '$key' Isn't Started!!! This will cause search issues!!!"
            } elseif ($process.StartTime -gt ([DateTime]::Now.AddHours(-1))) {
                Write-Host "Process '$key' hasn't been running for at least an hour. This could mean it is crashing causing search issues."
            }

            if ($process.ThirdPartyModules.Count -ge 1) {

                Write-Host "Third Party Modules Loaded into Process '$key'"

                foreach ($module in $process.ThirdPartyModules) {
                    Write-Verbose "----------"
                    $module |
                        Select-Object ModuleName, FileName, Company |
                        Out-String |
                        Write-Verbose
                }
                $thirdPartyModuleFound = $true
            }
        }

        if ($thirdPartyModuleFound) {
            Write-Host "Please exclude AV from all Exchange processes: https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019"
        }

        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host ""
    }
}
