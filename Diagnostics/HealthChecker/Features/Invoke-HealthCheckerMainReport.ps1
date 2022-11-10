# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# The main functionality of Exchange Health Checker.
# Collect information and report it to the screen and export out the results.
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Get-HealthCheckerExchangeServer.ps1
. $PSScriptRoot\..\DataCollection\OrganizationInformation\Get-OrganizationInformation.ps1
. $PSScriptRoot\..\Helpers\Test-RequiresServerFqdn.ps1

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

    $organizationInformation = Get-OrganizationInformation -EdgeServer $EdgeServer

    foreach ($serverName in $ServerNames) {
        Invoke-SetOutputInstanceLocation -Server $serverName -FileName "HealthChecker" -IncludeServerName $true
        Write-HostLog "Exchange Health Checker version $BuildVersion"
        #TODO Fix this as Test-RequiresServerFqdn I am sure doesn't work correctly right now.
        Test-RequiresServerFqdn -Server $serverName
        [HealthChecker.HealthCheckerExchangeServer]$HealthObject = Get-HealthCheckerExchangeServer -ServerName $serverName
        $HealthObject.OrganizationInformation = $organizationInformation
        $analyzedResults = Invoke-AnalyzerEngine -HealthServerObject $HealthObject
        Write-ResultsToScreen -ResultsToWrite $analyzedResults.DisplayResults

        $currentErrors = $Error.Count

        try {
            $analyzedResults | Export-Clixml -Path $Script:OutXmlFullPath -Encoding UTF8 -Depth 6 -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Failed to Export-Clixml. Converting HealthCheckerExchangeServer to json"
            $jsonHealthChecker = $analyzedResults.HealthCheckerExchangeServer | ConvertTo-Json

            $testOuputxml = [PSCustomObject]@{
                HealthCheckerExchangeServer = $jsonHealthChecker | ConvertFrom-Json
                HtmlServerValues            = $analyzedResults.HtmlServerValues
                DisplayResults              = $analyzedResults.DisplayResults
            }

            $testOuputxml | Export-Clixml -Path $Script:OutXmlFullPath -Encoding UTF8 -Depth 6 -ErrorAction Stop
        } finally {
            Invoke-ErrorCatchActionLoopFromIndex $currentErrors

            Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
            Write-Grey("Exported Data Object Written to {0} " -f $Script:OutXmlFullPath)
        }
    }
}
