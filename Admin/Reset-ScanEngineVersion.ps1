# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 3

[CmdletBinding()]
param (
    [switch]$Force
)

begin {
    #region Remoting Scriptblock
    $scriptBlock = {
        #region Functions
        function Get-ExchangeInstallPath {
            return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
        }

        function StopServicesAndProcesses {
            Write-Host "$($env:COMPUTERNAME) Stopping MSExchangeTransport, FMS, and updateservice..."
            Stop-Service FMS -Force
            $updateservice = Get-Process updateservice -ErrorAction SilentlyContinue
            if ($null -ne $updateservice) {
                $updateservice | Stop-Process -Force
            }

            Start-Sleep -Seconds 2
        }

        function RemoveMicrosoftFolder {
            Write-Host "$($env:COMPUTERNAME) Removing Microsoft engine folder..."
            $installPath = Get-ExchangeInstallPath
            if ($null -ne $installPath) {
                $microsoftFolder = Join-Path $installPath "FIP-FS\Data\Engines\amd64\Microsoft"
                Remove-Item -Recurse -Force $microsoftFolder
            }
        }

        function EmptyMetadataFolder {
            Write-Host "$($env:COMPUTERNAME) Emptying metadata folder..."
            $installPath = Get-ExchangeInstallPath
            if ($null -ne $installPath) {
                $metadataFolder = Join-Path $installPath "FIP-FS\Data\Engines\metadata"
                Get-ChildItem $metadataFolder | Remove-Item -Recurse -Force
            }
        }

        function StartServices {
            Write-Host "$($env:COMPUTERNAME) Starting services..."
            Start-Service FMS
            Start-Service MSExchangeTransport
        }

        function StartEngineUpdate {
            Write-Host "$($env:COMPUTERNAME) Starting engine update..."
            $installPath = Get-ExchangeInstallPath
            $updateScriptPath = Join-Path $installPath "Scripts\Update-MalwareFilteringServer.ps1"
            $fqdn = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName
            & $updateScriptPath $fqdn
        }

        function WaitForDownload {
            do {
                Start-Sleep -Seconds 1
                $transfer = Get-BitsTransfer -AllUsers | Where-Object { $_.DisplayName -like "Forefront_FPS*" }
                if ($null -ne $transfer) {
                    $percentComplete = 0
                    if ($transfer.BytesTotal.GetType() -eq [Int64] -and
                        $transfer.BytesTransferred.GetType() -eq [Int64] -and
                        $transfer.BytesTotal -gt 0) {
                        $percentComplete = ($transfer.BytesTransferred * 100 / $transfer.BytesTotal)
                    }

                    Write-Progress -Activity "$($env:COMPUTERNAME) Downloading scan engines" -Status "$($transfer.BytesTransferred) / $($transfer.BytesTotal)" -PercentComplete $percentComplete
                }
            } while ($null -ne $transfer)
        }
        #endregion Functions

        Add-PSSnapin -Name Microsoft.Exchange.Management.Powershell.E2010
        $hasMailboxRole = (Get-ExchangeServer ($env:COMPUTERNAME)).ServerRole -like "*Mailbox*"
        if ((-not $Force) -and (-not $hasMailboxRole)) {
            Write-Host "$($env:COMPUTERNAME) This server does not have the Mailbox role. Add -Force to proceed anyway."
            return
        }

        Add-PSSnapin -Name Microsoft.Forefront.Filtering.Management.PowerShell
        $engineInfo = Get-EngineUpdateInformation
        Write-Host "$($env:COMPUTERNAME) UpdateVersion: $($engineInfo.UpdateVersion)"
        $isImpacted = $engineInfo.UpdateVersion -like "22*"
        if ((-not $Force) -and (-not $isImpacted)) {
            Write-Host "$($env:COMPUTERNAME) This server is not impacted. Add -Force to proceed anyway."
            return
        }

        StopServicesAndProcesses
        RemoveMicrosoftFolder
        EmptyMetadataFolder
        StartServices
        StartEngineUpdate
        WaitForDownload
    }
    #endregion Remoting Scriptblock
}
process {
    Invoke-Command -ScriptBlock $scriptBlock
}
