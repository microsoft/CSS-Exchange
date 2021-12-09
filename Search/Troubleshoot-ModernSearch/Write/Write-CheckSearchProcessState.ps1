# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Exchange\Get-SearchProcessState.ps1
. $PSScriptRoot\Write-DisplayObjectInformation.ps1
. $PSScriptRoot\Write-ScriptOutput.ps1
Function Write-CheckSearchProcessState {
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

        Write-ScriptOutput "----------------------------------------"
        Write-ScriptOutput "Search Processes Status: $status"

        if (-not($checksPassed)) {
            Write-ScriptOutput "Latest Process Start: $($searchProcessState.LatestProcessStartTime)"
        }

        foreach ($key in $searchProcessState.ProcessResults.Keys) {

            $process = $searchProcessState.ProcessResults[$key]

            Write-ScriptOutput "------------------------" -Diagnostic
            Write-ScriptOutput "Process: $key" -Diagnostic
            Write-ScriptOutput "PID: $($process.PID)" -Diagnostic
            Write-ScriptOutput "StartTime: $($process.StartTime)" -Diagnostic

            if ($process.StartTime -eq [DateTime]::MinValue) {
                Write-ScriptOutput "Process '$key' Isn't Started!!! This will cause search issues!!!"
            } elseif ($process.StartTime -gt ([DateTime]::Now.AddHours(-1))) {
                Write-ScriptOutput "Process '$key' hasn't been running for at least an hour. This could mean it is crashing causing search issues."
            }

            if ($process.ThirdPartyModules.Count -ge 1) {

                Write-ScriptOutput "Third Party Modules Loaded into Process '$key'"

                foreach ($module in $process.ThirdPartyModules) {
                    Write-ScriptOutput "----------" -Diagnostic
                    $module |
                        Select-Object ModuleName, FileName, Company |
                        Write-ScriptOutput -Diagnostic
                }
                $thirdPartyModuleFound = $true
            }
        }

        if ($thirdPartyModuleFound) {
            Write-ScriptOutput "Please exclude AV from all Exchange processes: https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019"
        }

        Write-ScriptOutput ""
        Write-ScriptOutput "----------------------------------------"
        Write-ScriptOutput ""
    }
}
