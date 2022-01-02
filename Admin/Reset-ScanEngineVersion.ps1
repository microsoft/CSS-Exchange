# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 3

[CmdLetBinding()]
param(
    [switch]$DontEnableAntiMalwareScanning
)

begin {
    #region Remoting Scriptblock
    $scriptBlock = {
        #region Functions
        function Get-ExchangeInstallPath {
            return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
        }

        function StopServicesAndProcesses {
            Write-Host "$($env:COMPUTERNAME) Stopping services..."
            Stop-Service FMS -Force
            $updateservice = Get-Process updateservice -ErrorAction SilentlyContinue
            if ($null -ne $updateservice) {
                $updateservice | Stop-Process -Force
            }
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

        function EnableAntiMalwareScanning {
            $installPath = Get-ExchangeInstallPath
            if (-not $DontEnableAntiMalwareScanning -and $null -ne $installPath) {
                $response = Read-Host "Would you like to enable malware scanning now? (Y/n)"
                if ($response -eq "" -or $response -eq "y") {
                    Write-Host "$($env:COMPUTERNAME) Enabling Anti Malware Agent..."
                    $enableScanningScriptPath = Join-Path $installPath "Scripts\Enable-AntiMalwareScanning.ps1"
                    & $enableScanningScriptPath
                    Write-Host "$($env:COMPUTERNAME) Starting MSExchangeTransport service..."
                    Restart-Service MSExchangeTransport
                }
            }
        }
        #endregion Functions

        StopServicesAndProcesses
        RemoveMicrosoftFolder
        EmptyMetadataFolder
        StartServices
        StartEngineUpdate
        WaitForDownload
        EnableAntiMalwareScanning
    }
    #endregion Remoting Scriptblock
}
process {
    Invoke-Command -ScriptBlock $scriptBlock
}
