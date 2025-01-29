﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-ScriptBlockHandler.ps1

function Get-ServerRebootPending {
    [CmdletBinding()]
    param(
        [string]$ServerName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        function Get-PendingFileReboot {
            try {
                if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\" -Name PendingFileRenameOperations -ErrorAction Stop)) {
                    return $true
                }
                return $false
            } catch {
                return $false
            }
        }

        function Get-UpdateExeVolatile {
            try {
                $updateExeVolatileProps = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Updates\UpdateExeVolatile\" -ErrorAction Stop
                if ($null -ne $updateExeVolatileProps -and $null -ne $updateExeVolatileProps.Flags) {
                    return $true
                }
                return $false
            } catch {
                return $false
            }
        }

        function Get-PendingCCMReboot {
            try {
                return (Invoke-CimMethod -Namespace 'Root\ccm\clientSDK' -ClassName 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction Stop)
            } catch {
                return $false
            }
        }

        function Get-PathTestingReboot {
            param(
                [string]$TestingPath
            )

            return (Test-Path $TestingPath)
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $pendingRebootLocations = New-Object 'System.Collections.Generic.List[string]'
    }
    process {
        if ($PSSenderInfo) {
            $pendingFileRenameOperationValue = Get-PendingFileReboot
            $componentBasedServicingPendingRebootValue = Get-PathTestingReboot "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            $ccmReboot = Get-PendingCCMReboot
            $autoUpdatePendingRebootValue = Get-PathTestingReboot "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
            $updateExeVolatileValue = Get-UpdateExeVolatile
        } else {
            $pendingFileRenameOperationValue = Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PendingFileReboot} `
                -ScriptBlockDescription "Get-PendingFileReboot" `
                -CatchActionFunction $CatchActionFunction

            $componentBasedServicingPendingRebootValue = Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PathTestingReboot} `
                -ScriptBlockDescription "Component Based Servicing Reboot Pending" `
                -ArgumentList "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" `
                -CatchActionFunction $CatchActionFunction

            $ccmReboot = Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PendingCCMReboot} `
                -ScriptBlockDescription "Get-PendingSCCMReboot" `
                -CatchActionFunction $CatchActionFunction

            $autoUpdatePendingRebootValue = Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PathTestingReboot} `
                -ScriptBlockDescription "Auto Update Pending Reboot" `
                -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" `
                -CatchActionFunction $CatchActionFunction

            $updateExeVolatileValue = Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-UpdateExeVolatile} `
                -ScriptBlockDescription "UpdateExeVolatile Reboot Pending" `
                -CatchActionFunction $CatchActionFunction
        }

        $ccmRebootPending = $ccmReboot -and ($ccmReboot.RebootPending -or $ccmReboot.IsHardRebootPending)
        $pendingReboot = $ccmRebootPending -or $pendingFileRenameOperationValue -or $componentBasedServicingPendingRebootValue -or $autoUpdatePendingRebootValue -or $updateExeVolatileValue

        if ($null -eq $pendingFileRenameOperationValue) {
            $pendingFileRenameOperationValue = $false
        }

        if ($ccmRebootPending) {
            Write-Verbose "RebootPending in CCM_ClientUtilities"
            $pendingRebootLocations.Add("CCM_ClientUtilities Showing Reboot Pending")
        }

        if ($pendingFileRenameOperationValue) {
            Write-Verbose "RebootPending at HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
            $pendingRebootLocations.Add("HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations")
        }

        if ($componentBasedServicingPendingRebootValue) {
            Write-Verbose "RebootPending at HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            $pendingRebootLocations.Add("HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
        }

        if ($autoUpdatePendingRebootValue) {
            Write-Verbose "RebootPending at HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
            $pendingRebootLocations.Add("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
        }

        if ($updateExeVolatileValue) {
            Write-Verbose "RebootPending at HKLM:\Software\Microsoft\Updates\UpdateExeVolatile\Flags"
            $pendingRebootLocations.Add("HKLM:\Software\Microsoft\Updates\UpdateExeVolatile\Flags")
        }
    }
    end {
        return [PSCustomObject]@{
            PendingFileRenameOperations          = $pendingFileRenameOperationValue
            ComponentBasedServicingPendingReboot = $componentBasedServicingPendingRebootValue
            AutoUpdatePendingReboot              = $autoUpdatePendingRebootValue
            UpdateExeVolatileValue               = $updateExeVolatileValue
            CcmRebootPending                     = $ccmRebootPending
            PendingReboot                        = $pendingReboot
            PendingRebootLocations               = $pendingRebootLocations
        }
    }
}
