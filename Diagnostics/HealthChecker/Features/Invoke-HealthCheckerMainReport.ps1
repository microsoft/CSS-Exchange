# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# The main functionality of Exchange Health Checker.
# Collect information and report it to the screen and export out the results.
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Get-HealthCheckerExchangeServer.ps1
. $PSScriptRoot\..\DataCollection\OrganizationInformation\Get-OrganizationInformation.ps1

function Invoke-HealthCheckerMainReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames,

        [Parameter(Mandatory = $true)]
        [bool]$EdgeServer
    )

    function TestComputerName {
        [CmdletBinding()]
        [OutputType([bool])]
        param(
            [string]$ComputerName
        )
        try {
            Write-Verbose "Testing $ComputerName"
            Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-Date } -ErrorAction Stop | Out-Null
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(“LocalMachine”, $ComputerName)
            $reg.OpenSubKey(“SOFTWARE\Microsoft\Windows NT\CurrentVersion”) | Out-Null
            Write-Verbose "Returning true back"
            return $true
        } catch {
            Write-Verbose "Failed to run against $ComputerName"
            Invoke-CatchActions
        }
        return $false
    }

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

    $passedOrganizationInformation = @{
        OrganizationConfig = $organizationInformation.GetOrganizationConfig
        SettingOverride    = $organizationInformation.GetSettingOverride
    }

    $failedServerList = New-Object "System.Collections.Generic.List[string]"

    foreach ($serverName in $ServerNames) {

        # Set serverName to be not be FQDN if that is what is passed.
        $serverName = $serverName.Split(".")[0]

        try {
            $fqdn = (Get-ExchangeServer $serverName -ErrorAction Stop).FQDN
            Write-Verbose "Set FQDN to $fqdn"
        } catch {
            Write-Host "Unable to find server: $serverName" -ForegroundColor Yellow
            Invoke-CatchActions
            continue
        }

        # Test out serverName and FQDN to determine if we can properly reach the server.
        # It appears in some environments, you can't do both.
        $serverNameParam = $fqdn

        if (-not (TestComputerName $fqdn)) {
            if (-not (TestComputerName $serverName)) {
                $line = "Unable to connect to server $serverName. Please run locally"
                Write-Verbose $line
                Write-Host $line -ForegroundColor Yellow
                continue
            }
            Write-Verbose "Set serverNameParam to $serverName"
            $serverNameParam = $serverName
        }

        try {
            Invoke-SetOutputInstanceLocation -Server $serverName -FileName "HealthChecker" -IncludeServerName $true
            Write-HostLog "Exchange Health Checker version $BuildVersion"
            [HealthChecker.HealthCheckerExchangeServer]$HealthObject = Get-HealthCheckerExchangeServer -ServerName $serverNameParam -PassedOrganizationInformation $passedOrganizationInformation
            $HealthObject.OrganizationInformation = $organizationInformation
            $analyzedResults = Invoke-AnalyzerEngine -HealthServerObject $HealthObject
            Write-ResultsToScreen -ResultsToWrite $analyzedResults.DisplayResults
        } catch {
            Write-Red "Failed to Health Checker against $serverName"
            $failedServerList.Add($serverName)
            continue
        }

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
    Write-Verbose "Failed Server List: $([string]::Join(",", $failedServerList))"
}
