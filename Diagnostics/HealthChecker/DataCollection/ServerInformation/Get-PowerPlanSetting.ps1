# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1

function Get-PowerPlanSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $highPerformanceSet = $false
        $powerPlanSetting = [string]::Empty
        $win32_PowerPlan = Get-WmiObjectHandler -ComputerName $Server -Class Win32_PowerPlan -Namespace 'root\ciMv2\power' -Filter "isActive='true'" -CatchActionFunction ${Function:Invoke-CatchActions}

        if ($null -ne $win32_PowerPlan) {

            # Guid 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c is 'High Performance' power plan that comes with the OS
            # Guid db310065-829b-4671-9647-2261c00e86ef is 'High Performance (ConfigMgr)' power plan when configured via Configuration Manager / SCCM
            if (($win32_PowerPlan.InstanceID -eq "Microsoft:PowerPlan\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}") -or
                ($win32_PowerPlan.InstanceID -eq "Microsoft:PowerPlan\{db310065-829b-4671-9647-2261c00e86ef}")) {
                Write-Verbose "High Performance Power Plan is set to true"
                $highPerformanceSet = $true
            } else { Write-Verbose "High Performance Power Plan is NOT set to true" }
            $powerPlanSetting = $win32_PowerPlan.ElementName
        } else {
            Write-Verbose "Power Plan Information could not be read"
            $powerPlanSetting = "N/A"
        }
    } end {
        return [PSCustomObject]@{
            HighPerformanceSet = $highPerformanceSet
            PowerPlanSetting   = $powerPlanSetting
            PowerPlan          = $win32_PowerPlan
        }
    }
}
