# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-HealthCheckerDataCollection.ps1
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
    [array]$hcDataCollection = Get-HealthCheckerDataCollection $ServerNames
    # TODO: Properly handle Force Legacy.
    if ($hcDataCollection.Count -eq 1) {
        $runType = "CurrentSession"
    } else {
        $runType = "StartNow"
    }
    $analyzedEngineResults = Invoke-AnalyzerEngineHandler -ServerDataCollection $hcDataCollection -RunType $runType

    # TODO: Handle this better.
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $stopWatchWrite = New-Object System.Diagnostics.Stopwatch
    $stopWatchToScreen = New-Object System.Diagnostics.Stopwatch
    foreach ($key in $analyzedEngineResults.Keys) {
        $serverName = $analyzedEngineResults[$key].HealthCheckerExchangeServer.ServerName
        Invoke-SetOutputInstanceLocation -Server $serverName -FileName "HealthChecker" -IncludeServerName $true

        try {
            $stopWatchWrite.Start()
            $analyzedEngineResults[$key] | Export-Clixml -Path $Script:OutXmlFullPath -Encoding utf8 -Depth 2 -ErrorAction Stop -Force
        } catch {
            Write-Verbose "Failed to Export-Clixml. Inner Exception: $_"
            Write-Verbose "Converting HealthCheckerExchangeServer to json."
            $outputXml = [PSCustomObject]@{
                HealthCheckerExchangeServer = $null
                HtmlServerValues            = $analyzedEngineResults[$key].HtmlServerValues
                DisplayResults              = $analyzedEngineResults[$key].DisplayResults
            }
            try {
                $jsonHealthChecker = $analyzedEngineResults[$key].HealthCheckerExchangeServer | ConvertTo-Json -Depth 6 -ErrorAction Stop
                $outputXml.HealthCheckerExchangeServer = $jsonHealthChecker | ConvertFrom-Json -ErrorAction Stop
                $outputXml | Export-Clixml -Path $Script:OutXmlFullPath -Encoding UTF8 -Depth 2 -ErrorAction Stop -Force
                Write-Verbose "Successfully export out the data after the convert"
            } catch {
                Write-Red "Failed to Export-Clixml. Unable to export the data."
            }
        } finally {
            $stopWatchWrite.Stop()
        }

        Write-HostLog "Exchange Health Checker Version $Script:BuildVersion"
        $stopWatchToScreen.Start()
        Write-ResultsToScreen -ResultsToWrite $analyzedEngineResults[$key].DisplayResults
        $stopWatchToScreen.Stop()
        Write-Grey "Output file written to $($Script:OutputFullPath)"
        Write-Grey "Exported Data Object Written to $($Script:OutXmlFullPath)"
    }
    Write-Verbose "Writing the analyzed results to disk took $($stopWatchWrite.Elapsed.TotalSeconds) seconds."
    Write-Verbose "Writing the results to the screen took $($stopWatchToScreen.Elapsed.TotalSeconds) seconds."
    Write-Verbose "Total process to write to screen and disk took $($stopWatch.Elapsed.TotalSeconds) seconds."
}
