# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\DataCollection\OrganizationInformation\Add-JobOrganizationInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Add-JobHardwareInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Add-JobOperatingSystemInformation.ps1
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Add-JobExchangeInformationCmdlet.ps1

<#
    TODO:
        Write-Progress bar to be included
        Include Write-Warning in the debug logging
        Improve logic for determining what name to use FQDN or name.
#>
function Get-HealthCheckerDataCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames
    )
    begin {

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

        $getExchangeServerList = @{}
    }
    process {
        # Loop through all the server names provided to make sure they are an Exchange server, and to get the FQDN for them.
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($serverName in $ServerNames) {
            try {
                $getExchangeServer = Get-ExchangeServer $serverName -ErrorAction Stop
                # test the name to know what we are going to use for the Invoke-Command logic.
                $serverKeyName = $getExchangeServer.FQDN
                if (-not (TestComputerName $getExchangeServer.FQDN)) {
                    if (-not (TestComputerName $getExchangeServer.Name)) {
                        Write-Warning "Unable to connect to server $serverName. Please run locally"
                        continue
                    }
                    $serverKeyName = $getExchangeServer.Name
                }

                $getExchangeServerList.Add($serverKeyName, $getExchangeServer)
            } catch {
                Write-Warning "Unable to find server: $serverName"
                Invoke-CatchActions
            }
        }
        Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to get the Exchange Server and determine what names we can use."

        # Set the script variable for the name of the computer that we want to connect to for EMS
        $Script:PrimaryRemoteShellConnectionPoint = (Get-PSSession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Select-Object -First 1).ComputerName

        # Add all the jobs to the queue that we need.
        Add-JobOrganizationInformation

        foreach ($serverName in $getExchangeServerList.Keys) {
            Add-JobHardwareInformation -ComputerName $serverName
            Add-JobOperatingSystemInformation -ComputerName $serverName
            Add-JobExchangeInformationCmdlet -ComputerName $serverName
        }
        Write-Debug "Testing" -Debug
    }
}
