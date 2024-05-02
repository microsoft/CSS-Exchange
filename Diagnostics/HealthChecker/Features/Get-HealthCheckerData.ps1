# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\DataCollection\ExchangeInformation\Get-HealthCheckerExchangeServer.ps1
. $PSScriptRoot\..\DataCollection\OrganizationInformation\Get-OrganizationInformation.ps1

# Collects the data required for Health Checker
function Get-HealthCheckerData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames,

        [Parameter(Mandatory = $true)]
        [bool]$EdgeServer,

        [Parameter(Mandatory = $false)]
        [bool]$ReturnDataCollectionOnly = $false #TODO Remove this an display somewhere else. This function should only do data collection. Once it is optimized to do so.
    )

    function TestComputerName {
        [CmdletBinding()]
        [OutputType([bool])]
        param(
            [string]$ComputerName
        )
        try {
            Write-Verbose "Testing $ComputerName"

            # If local computer, we should just assume that it should work.
            if ($ComputerName -eq $env:COMPUTERNAME) {
                Write-Verbose "Local computer, returning true"
                return $true
            }

            Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-Date } -ErrorAction Stop | Out-Null
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName)
            $reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion") | Out-Null
            Write-Verbose "Returning true back"
            return $true
        } catch {
            Write-Verbose "Failed to run against $ComputerName"
            Invoke-CatchActions
        }
        return $false
    }

    function ExportHealthCheckerXml {
        [CmdletBinding()]
        [OutputType([bool])]
        param(
            [Parameter(Mandatory = $true)]
            [object]$SaveDataObject,

            [Parameter(Mandatory = $true)]
            [hashtable]$ProgressParams
        )
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $dataExported = $false

        try {
            $currentErrors = $Error.Count
            $ProgressParams.Status = "Exporting Data"
            Write-Progress @ProgressParams
            $SaveDataObject | Export-Clixml -Path $Script:OutXmlFullPath -Encoding UTF8 -Depth 2 -ErrorAction Stop -Force
            Write-Verbose "Successfully export out the data"
            $dataExported = $true
        } catch {
            try {
                Write-Verbose "Failed to Export-Clixml. Inner Exception: $_"
                Write-Verbose "Converting HealthCheckerExchangeServer to json."
                $outputXml = [PSCustomObject]@{
                    HealthCheckerExchangeServer = $null
                    HtmlServerValues            = $null
                    DisplayResults              = $null
                }

                if ($null -ne $SaveDataObject.HealthCheckerExchangeServer) {
                    $jsonHealthChecker = $SaveDataObject.HealthCheckerExchangeServer | ConvertTo-Json -Depth 6 -ErrorAction Stop
                    $outputXml.HtmlServerValues = $SaveDataObject.HtmlServerValues
                    $outputXml.DisplayResults = $SaveDataObject.DisplayResults
                } else {
                    $jsonHealthChecker = $SaveDataObject | ConvertTo-Json -Depth 6 -ErrorAction Stop
                }

                $outputXml.HealthCheckerExchangeServer = $jsonHealthChecker | ConvertFrom-Json -ErrorAction Stop
                $outputXml | Export-Clixml -Path $Script:OutXmlFullPath -Encoding UTF8 -Depth 2 -ErrorAction Stop -Force
                Write-Verbose "Successfully export out the data after the convert"
                $dataExported = $true
            } catch {
                Write-Red "Failed to Export-Clixml. Unable to export the data."
            }
        } finally {
            # This prevents the need to call Invoke-CatchActions
            Invoke-ErrorCatchActionLoopFromIndex $currentErrors
        }
        return $dataExported
    }

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $paramWriteProgress = @{
        Id       = 1
        Activity = "Organization Information"
        Status   = "Data Collection"
    }

    Write-Progress @paramWriteProgress
    $organizationInformation = Get-OrganizationInformation -EdgeServer $EdgeServer

    $failedServerList = New-Object "System.Collections.Generic.List[string]"
    $returnDataList = New-Object "System.Collections.Generic.List[object]"
    $serverCount = 0

    foreach ($serverName in $ServerNames) {

        # Set serverName to be not be FQDN if that is what is passed.
        $serverName = $serverName.Split(".")[0]

        $paramWriteProgress.Activity = "Server: $serverName"
        $paramWriteProgress.Status = "Data Collection"
        $paramWriteProgress.PercentComplete = (($serverCount / $ServerNames.Count) * 100)
        Write-Progress @paramWriteProgress
        $serverCount++

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

            if (-not $Script:VulnerabilityReport) {
                # avoid having vulnerability report having a txt file with nothing in it besides the Exchange Health Checker Version
                Write-HostLog "Exchange Health Checker version $BuildVersion"
            }

            $HealthObject = $null
            $HealthObject = Get-HealthCheckerExchangeServer -ServerName $serverNameParam
            $HealthObject.OrganizationInformation = $organizationInformation

            # If we successfully got the data, we want to export it out right away.
            # This then allows if an exception does occur in the analysis stage,
            # we then have the data output that is reproducing a problem in that section of code that we can debug.
            $dataExported = ExportHealthCheckerXml -SaveDataObject $HealthObject -ProgressParams $paramWriteProgress
            $paramWriteProgress.Status = "Analyzing Data"
            Write-Progress @paramWriteProgress
            $analyzedResults = Invoke-AnalyzerEngine -HealthServerObject $HealthObject

            if (-not $ReturnDataCollectionOnly) {
                Write-Progress @paramWriteProgress -Completed
                Write-ResultsToScreen -ResultsToWrite $analyzedResults.DisplayResults
            } else {
                $returnDataList.Add($analyzedResults)
            }
        } catch {
            Write-Red "Failed to Health Checker against $serverName"
            $failedServerList.Add($serverName)

            if ($null -eq $HealthObject) {
                # Try to handle the issue so we don't get a false positive report.
                Invoke-CatchActions
            }
            continue
        } finally {

            if ($null -ne $analyzedResults) {
                # Export out the analyzed data, as this is needed for Build HTML Report.
                $dataExported = ExportHealthCheckerXml -SaveDataObject $analyzedResults -ProgressParams $paramWriteProgress
            }

            # for now don't want to display that we output the information if ReturnDataCollectionOnly is false
            if ($dataExported -and -not $ReturnDataCollectionOnly) {
                Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
                Write-Grey("Exported Data Object Written to {0} " -f $Script:OutXmlFullPath)
            }
        }
    }
    Write-Verbose "Failed Server List: $([string]::Join(",", $failedServerList))"

    if ($ReturnDataCollectionOnly) {
        return $returnDataList
    }
}
