# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 3.0

<#
.SYNOPSIS
    Removes duplicate entries from the IanaTimeZoneMappings.xml file which is used by Exchange Server
.DESCRIPTION
    Removes duplicate entries from the IanaTimeZoneMappings.xml file which is used by Exchange Server.
    Duplicate entries can lead to exceptions and break functionalities on Microsoft Exchange Server such as processing .ics files.

    For more information see: https://aka.ms/ExchangeIanaTimeZoneIssue
.PARAMETER Server
    The Exchange server that should be validated by the script. It also accepts values directly from the pipeline for seamless integration.
.PARAMETER RestartServices
    Specifies whether the following services should be restarted on the target system: W3SVC, WAS, MSExchangeTransport
    Default value: $false
.PARAMETER ScriptUpdateOnly
    This optional parameter allows you to only update the script without performing any other actions.
.PARAMETER SkipVersionCheck
    This optional parameter allows you to skip the automatic version check and script update.
.EXAMPLE
    PS C:\> .\Remove-DuplicateEntriesFromIanaMappings.ps1 -Server exch1.contoso.com
.EXAMPLE
    PS C:\> Get-ExchangeServer | .\Remove-DuplicateEntriesFromIanaMappings.ps1
.EXAMPLE
    PS C:\> .\Remove-DuplicateEntriesFromIanaMappings.ps1 -Server exch1.contoso.com -RestartServices $true
#>

[CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "Default")]
    [string[]]$Server = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [bool]$RestartServices = $false,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [switch]$SkipVersionCheck
)

begin {
    . $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\Shared\Get-ExSetupFileVersionInfo.ps1
    . $PSScriptRoot\..\Shared\Invoke-ScriptBlockHandler.ps1
    . $PSScriptRoot\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1

    Write-Verbose "PowerShell version: $($PSVersionTable.PSVersion)"

    $scriptBlock = {
        param(
            $PerformServiceRestart,
            $LocalComputerName
        )

        . $PSScriptRoot\..\Shared\ValidatorFunctions\Test-IanaTimeZoneMapping.ps1
        . $PSScriptRoot\..\Shared\Get-RemoteRegistryValue.ps1

        # This needs to be set if the server, which is processed is not the local computer
        # If we don't set it, we won't see verbose output if -Verbose parameter is used
        if ($LocalComputerName -ne $env:COMPUTERNAME) {
            $VerbosePreference = $Using:VerbosePreference
        }

        try {
            Write-Host "[+] Validating IanaTimeZoneMappings.xml on server $env:COMPUTERNAME"

            $activityBase = "[$env:COMPUTERNAME]"
            $writeProgressParams = @{
                Activity = "$activityBase Getting IanaTimeZoneMappings.xml Path"
                Id       = [Math]::Abs(($env:COMPUTERNAME).GetHashCode())
            }
            Write-Progress @writeProgressParams

            # Locate the path where the IanaTimeZoneMappings.xml resides - to do this, read the MsiInstallPath from the registry
            $exchangeServerSetupPathParams = @{
                MachineName = $env:COMPUTERNAME
                SubKey      = "SOFTWARE\Microsoft\ExchangeServer\v15\Setup"
                GetValue    = "MsiInstallPath"
            }
            $exchangeSetupPath = Get-RemoteRegistryValue @exchangeServerSetupPathParams

            if (([System.String]::IsNullOrEmpty($exchangeSetupPath))) {
                Write-Host "[+] Unable to locate the Exchange Server setup path"
                return
            }

            # Define the final full path to the mapping file and for the backup file (in case we need to create it)
            $mappingFilePath = "$exchangeSetupPath\Bin\IanaTimeZoneMappings.xml"
            $mappingBackupFilePath = "$mappingFilePath.{0}.bak" -f $(Get-Date -Format MMddyyyyHHmmss)

            if ((Test-Path -Path $mappingFilePath) -eq $false) {
                Write-Host "[+] Iana mappings file was not found" -ForegroundColor Red

                return
            }

            $writeProgressParams.Activity = $activityBase + " Searching for duplicate entries in IanaTimeZoneMappings.xml"
            Write-Progress @writeProgressParams

            # Check if IanaTimeZoneMappings.xml contains duplicate entries - this is done by the custom Test-IanaTimeZoneMapping function
            $testIanaTimeZoneMappingResults = Test-IanaTimeZoneMapping -FilePath $mappingFilePath

            if ($null -ne $testIanaTimeZoneMappingResults -and
                $testIanaTimeZoneMappingResults.DuplicateEntries.Count -ge 1) {

                $duplicateEntries = $testIanaTimeZoneMappingResults.DuplicateEntries
                $ianaMappingXml = $testIanaTimeZoneMappingResults.IanaMappingXml

                Write-Host "[+] Duplicate entries detected!" -ForegroundColor Yellow

                try {
                    $writeProgressParams.Activity = $activityBase + " Creating backup $mappingBackupFilePath"
                    Write-Progress @writeProgressParams

                    # If duplicate entries were detected, create a backup of the file before modifying it
                    Copy-Item -Path $mappingFilePath -Destination $mappingBackupFilePath
                    Write-Host "[+] Backup created: $mappingBackupFilePath"
                } catch {
                    Write-Host "[+] Failed to create backup file. Inner Exception: $_" -ForegroundColor Red

                    return
                }

                $dupeIndex = 0

                # Iterate through all of the duplicate entries and remove them one by one
                foreach ($dupe in $duplicateEntries) {
                    Write-Host "[+] Processing duplicate entry: $dupe"

                    $writeProgressParams.Activity = $activityBase + " Processing duplicate entry: $dupe"
                    Write-Progress @writeProgressParams

                    try {
                        # Select the duplicate node and remove it - we use SelectSingleNode here as it could be that there are multiple duplicates
                        $singleNode = $ianaMappingXml.SelectSingleNode("//Map[@IANA='$($dupe.IANA)' and @Win='$($dupe.Win)']")
                        $singleNode.ParentNode.RemoveChild($singleNode) | Out-Null

                        $dupeIndex++
                    } catch {
                        Write-Host "[+] Failed to fix duplicate entry $dupe. Inner Exception: $_" -ForegroundColor Red

                        return
                    }
                }

                # Validate that all duplicate entries were removed before saving the mapping file
                if ($duplicateEntries.Count -eq $dupeIndex) {
                    Write-Host "[+] All duplicate entries were removed" -ForegroundColor Green

                    $writeProgressParams.Activity = $activityBase + " Saving changes to file IanaTimeZoneMappings.xml"
                    Write-Progress @writeProgressParams

                    try {
                        # Save the modified IanaTimeZoneMappings.xml file and override the existing one
                        $ianaMappingXml.Save($mappingFilePath)

                        # Restart services if the -RestartServices $true was used when running the script - otherwise do nothing
                        if ($PerformServiceRestart) {
                            Write-Host "[+] Restart services: W3SVC, WAS & MSExchangeTransport"

                            $writeProgressParams.Activity = $activityBase + " Restarting services W3SVC, WAS & MSExchangeTransport"
                            Write-Progress @writeProgressParams

                            try {
                                Restart-Service -Name W3SVC, WAS, MSExchangeTransport -Force
                            } catch {
                                Write-Host "[+] Failed to restart services. Inner Exception: $_" -ForegroundColor Red
                            }
                        }
                    } catch {
                        Write-Host "[+] Failed to save the modified mapping file. Inner Exception: $_" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "[+] No duplicate entries were found" -ForegroundColor Green
            }
        } finally {
            Write-Progress @writeProgressParams -Completed
        }
    }
} process {
    if (-not(Confirm-Administrator)) {
        Write-Host "The script needs to be executed in elevated mode. Start the PowerShell as an administrator." -ForegroundColor Yellow
        exit
    }

    foreach ($srv in $Server) {
        # Check if the target server is online / reachable to us, we use the Get-ExSetupFileVersionInfo custom function to do this
        $exchangeFileVersionInfo = Get-ExSetupFileVersionInfo -Server $srv

        if (-not([System.String]::IsNullOrEmpty($exchangeFileVersionInfo))) {
            Invoke-ScriptBlockHandler -ComputerName $srv -ScriptBlock $scriptBlock -ArgumentList $RestartServices, $env:COMPUTERNAME
        } else {
            Write-Host "[+] Server: $srv is offline or not reachable" -ForegroundColor Yellow
        }
        Write-Host ""
    }
} end {
    Write-Host ("Do you have feedback regarding the script? Please email ExToolsFeedback@microsoft.com.") -ForegroundColor Green
    Write-Host ""
}
