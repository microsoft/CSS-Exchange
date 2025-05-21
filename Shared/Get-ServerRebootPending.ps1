# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1
. $PSScriptRoot\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

# Updated this function to only be executed on the intended server.
function Get-ServerRebootPending {
    [CmdletBinding()]
    param(
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
                Invoke-CatchActionError $CatchActionFunction
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
                Invoke-CatchActionError $CatchActionFunction
                return $false
            }
        }

        function Get-PendingCCMReboot {
            try {
                return (Invoke-CimMethod -Namespace 'Root\ccm\clientSDK' -ClassName 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction Stop)
            } catch {
                Invoke-CatchActionError $CatchActionFunction
                return $false
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $pendingRebootLocations = New-Object 'System.Collections.Generic.List[string]'
        $pendingFileRenameOperationValue = $null
        $ccmReboot = $null
        $updateExeVolatileValue = $null
    }
    process {
        Get-PendingFileReboot | Invoke-RemotePipelineHandler -Result ([ref]$pendingFileRenameOperationValue)
        Get-UpdateExeVolatile | Invoke-RemotePipelineHandler -Result ([ref]$updateExeVolatileValue)
        Get-PendingCCMReboot | Invoke-RemotePipelineHandler -Result ([ref]$ccmReboot)
        $componentBasedServicingPendingRebootValue = (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
        $autoUpdatePendingRebootValue = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
        $ccmRebootPending = $ccmReboot -and ($ccmReboot.RebootPending -or $ccmReboot.IsHardRebootPending)
        $pendingReboot = ($ccmRebootPending -or $pendingFileRenameOperationValue -or $componentBasedServicingPendingRebootValue -or
            $autoUpdatePendingRebootValue -or $updateExeVolatileValue)

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
