# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Set the Unified Content Cleanup path when exchange isn't installed in the default location
.DESCRIPTION
    The AntiMalware.xml is hard coded to look at the default locations without regards to where Exchange is installed at or the transport database is located.
    Because of this, the probe that goes through and cleans up the Unified Content in the Transport's temp storage location isn't aware of any other locations.
    This script will go through and correct the value to where Exchange is truly installed at or where the Transport's temp storage is located at.
.EXAMPLE
    PS C:\> .\SetUnifiedContentPath.ps1
    Will detect and determine if the AntiMalware.xml file contains the correct expected CleanupFolderResponderFolderPaths within it.
    Otherwise, it will set it for you and create a AntiMalware.xml.bak file.
.EXAMPLE
    PS C:\> Get-ExchangeServer | .\SetUnifiedContentPath.ps1
    Will run the SetUnifiedContentPath.ps1 against all the Exchange Servers
.EXAMPLE
    PS C:\> Get-ExchangeServer | .\SetUnifiedContentPath.ps1 -RestartService
    Will run the SetUnifiedContentPath.ps1 against all the Exchange Servers and restart the service MSExchangeHM
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ValueFromPipeline = $true)]
    [string[]]
    $ComputerName = $env:COMPUTERNAME,

    [switch]
    $RestartService
)

begin {
    . $PSScriptRoot\Get-UnifiedContentInformation.ps1
    . $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
    . $PSScriptRoot\..\..\Shared\Invoke-ScriptBlockHandler.ps1
    . $PSScriptRoot\..\..\Shared\Write-ErrorInformation.ps1

    $computerNames = New-Object System.Collections.ArrayList
}

process {
    foreach ($computer in $ComputerName) {
        [void]$computerNames.Add($computer)
    }
}

end {
    try {
        if (-not (Confirm-Administrator)) {
            Write-Warning "Not running script as an Administrator. Please open a PowerShell session as Administrator"
            exit
        }

        $exchangeSession = Confirm-ExchangeShell

        if (-not ($exchangeSession.ShellLoaded)) {
            Write-Warning "Failed to load Exchange Management Shell."
            exit
        }

        foreach ($computer in $computerNames) {
            $unifiedContentInformation = Invoke-ScriptBlockHandler -ComputerName $computer -ScriptBlock ${Function:Get-UnifiedContentInformation}

            if ($unifiedContentInformation.Success) {

                if ($unifiedContentInformation.ValidSetting) {
                    Write-Host "$computer : Unified Content Path is set correctly."
                    continue
                } else {
                    Write-Host "$computer : CleanupFolderResponderFolderPaths isn't set to what we expect."

                    if ($RestartService) { $restartWording = "and restart service MSExchangeHM" } else { $restartWording = "and not restart service MSExchangeHM" }

                    if ($PSCmdlet.ShouldProcess("Update the CleanupFolderResponderFolderPaths to '$($unifiedContentInformation.ExpectedCleanupFolderValue)' on server $computer $restartWording",
                            "AntiMalware.xml on $computer", "Update CleanupFolderResponderFolderPaths to '$($unifiedContentInformation.ExpectedCleanupFolderValue)'")) {
                        Write-Host "$computer : Updating to expected values: $($unifiedContentInformation.ExpectedCleanupFolderValue)"
                        Write-Host "$computer : Attempting to backup and save the Expected Value... " -NoNewline

                        Invoke-ScriptBlockHandler -ComputerName $computer -ArgumentList @($unifiedContentInformation, $computer, $RestartService) -ScriptBlock {
                            param(
                                [object]$UnifiedContentInformation,
                                [string]$Computer,
                                [bool]$RestartService
                            )
                            try {
                                Copy-Item $unifiedContentInformation.AntiMalwareFilePath -Destination $unifiedContentInformation.AntiMalwareFilePath.Replace(".xml", ".xml.bak") -Force
                                $unifiedContentInformation.LoadAntiMalwareFile.Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths = $unifiedContentInformation.ExpectedCleanupFolderValue
                                $unifiedContentInformation.LoadAntiMalwareFile.Save($unifiedContentInformation.AntiMalwareFilePath)
                                Write-Host "$computer : Successfully backup and save"

                                if ($RestartService) {
                                    Write-Host "$computer : Restarting MSExchangeHM"
                                    try {
                                        Restart-Service MSExchangeHM -ErrorAction Stop
                                    } catch {
                                        Write-Host "$computer : Failed to restart the MSExchangeHM service"
                                        Write-HostErrorInformation
                                    }
                                } else {
                                    Write-Host "$computer : Restart the MSExchangeHM to have new setting take effect."
                                }
                            } catch {
                                Write-Host "$computer : Failed to backup and save new value"
                                Write-HostErrorInformation
                            }
                        }
                    }
                }
            } else {
                Write-Warning "$computer : Failed to determine the Unified Content Information"
                continue
            }
        }
    } catch {
        Write-HostErrorInformation
    }
}
