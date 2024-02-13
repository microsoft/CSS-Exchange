# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-RollbackExtendedProtection {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$ExchangeServers
    )
    begin {
        $failedServers = New-Object 'System.Collections.Generic.List[string]'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($server in $ExchangeServers) {
            Write-Host "Attempting to rollback on $server"
            $results = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock {
                param(
                    [bool]$PassedWhatIf
                )
                try {
                    $saveToPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
                    $backupLocation = $saveToPath.Replace(".config", ".revert.cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                    $restoreFile = (Get-ChildItem "$($env:WINDIR)\System32\inetSrv\config\" -Filter "*applicationHost.cep.*.bak" | Sort-Object CreationTime | Select-Object -First 1).FullName
                    $successRestore = $false
                    $successBackupCurrent = $false

                    if ($null -eq $restoreFile) {
                        throw "Failed to find applicationHost.cep.*.bak file. Either file was moved or script was never run. Please use -DisableExtendedProtection to Disable Extended Protection."
                    }

                    $tooOld = (Get-ChildItem $restoreFile).CreationTime -lt [DateTime]::Now.AddDays(-30)

                    if ($tooOld) {
                        throw "Configuration file is too old to restore from. Please use -DisableExtendedProtection to Disable Extended Protection."
                    }

                    Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop -WhatIf:$PassedWhatIf
                    $successBackupCurrent = $true
                    Copy-Item -Path $restoreFile -Destination $saveToPath -Force -ErrorAction Stop -WhatIf:$PassedWhatIf
                    $successRestore = $true
                } catch {
                    Write-Host "Failed to restore application host file on server $env:COMPUTERNAME. Inner Exception $_"
                }
                return [PSCustomObject]@{
                    RestoreFile          = $restoreFile
                    SuccessRestore       = $successRestore
                    SuccessBackupCurrent = $successBackupCurrent
                    ErrorContext         = $Error[0]
                }
            } -ArgumentList $WhatIfPreference

            if ($results.SuccessRestore -and $results.SuccessBackupCurrent) {
                Write-Host "Successful restored $($results.RestoreFile) on server $server"
                continue
            } elseif ($results.SuccessBackupCurrent -eq $false) {
                $line = "Failed to backup the current configuration on server $server"
                Write-Verbose $line
                Write-Warning $line
            } elseif ($null -eq $results) {
                $line = "Failed to restore application host config file on server $server, because we weren't able to reach it."
                Write-Verbose $line
                Write-Warning $line
                # need to add to list and continue because there is no error context
                $failedServers.Add($server)
                continue
            } else {
                $line = "Failed to restore $($results.RestoreFile) to be the active application host config file on server $server"
                Write-Verbose $line
                Write-Warning $line
            }
            $failedServers.Add($server)
            Start-Sleep 1
            Write-HostErrorInformation $results.ErrorContext
            Write-Host ""
        }
    } end {
        if ($failedServers.Count -gt 0) {
            $line = "These are the servers that failed to rollback: $([string]::Join(", " ,$failedServers))"
            Write-Verbose $line
            Write-Warning $line
        }
    }
}
