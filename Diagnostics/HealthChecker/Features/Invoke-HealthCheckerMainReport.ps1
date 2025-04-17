# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-HealthCheckerDataCollection.ps1
. $PSScriptRoot\Get-HealthCheckerData.ps1
. $PSScriptRoot\..\Analyzer\Invoke-AnalyzerEngineHandler.ps1
# The main functionality of Exchange Health Checker.
# Collect information and report it to the screen and export out the results.
function Invoke-HealthCheckerMainReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames,

        [Parameter(Mandatory = $true)]
        [bool]$EdgeServer
    )

    $currentErrors = $Error.Count

    if ((-not $SkipVersionCheck) -and
        (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/HC-VersionsUrl")) {
        Write-Yellow "Script was updated. Please rerun the command."
        return
    } else {
        $Script:DisplayedScriptVersionAlready = $true
        Write-Green "Exchange Health Checker version $BuildVersion"
    }

    Invoke-ErrorCatchActionLoopFromIndex $currentErrors
    $hcDataCollection = Get-HealthCheckerDataCollection $ServerNames
    $analyzedEngineResults = Invoke-AnalyzerEngineHandler -ServerDataCollection $hcDataCollection -RunType "StartNow"

    # TODO: Handle this better.
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($key in $analyzedEngineResults.Keys) {
        $serverName = $analyzedEngineResults[$key].HealthCheckerExchangeServer.ServerName
        Invoke-SetOutputInstanceLocation -Server $serverName -FileName "HealthChecker" -IncludeServerName $true
        Write-ResultsToScreen -ResultsToWrite $analyzedEngineResults[$key].DisplayResults
    }
    Write-Verbose "Writing the results to the screen took $($stopWatch.Elapsed.TotalSeconds) seconds." -Verbose

    # Get-HealthCheckerData $ServerNames $EdgeServer
}
