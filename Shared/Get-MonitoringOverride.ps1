# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-MonitoringOverride {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        # If Server is provided, then we are doing Get-ServerMonitoringOverride. Otherwise, we are doing Get-GlobalMonitoringOverride.
        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    process {
        try {
            $monitoringOverrides = New-Object System.Collections.Generic.List[object]
            $monitoringOverridesSimple = New-Object System.Collections.Generic.List[object]
            $globalMonitoringOverride = [string]::IsNullOrEmpty($Server)
            if ($globalMonitoringOverride) {
                $monitoringOverride = Get-GlobalMonitoringOverride -ErrorAction Stop
            } else {
                $monitoringOverride = Get-ServerMonitoringOverride -Server $Server -ErrorAction Stop
            }

            foreach ($override in $monitoringOverride) {
                $monitoringOverrides.Add([PSCustomObject]@{
                        ItemType       = $override.ItemType
                        PropertyName   = $override.PropertyName
                        PropertyValue  = $override.PropertyValue
                        HealthSetName  = $override.MonitoringItemName
                        TargetResource = $override.TargetResource
                        ExpirationTime = $override.ExpirationTime
                        ApplyVersion   = $override.ApplyVersion
                        CreatedBy      = $override.CreatedBy
                        CreatedTime    = $override.CreatedTime
                        Identity       = $override.Identity
                        IsValid        = $override.IsValid
                    })
                $monitoringOverridesSimple.Add([PSCustomObject]@{
                        Identity       = $override.Identity
                        ItemType       = $override.ItemType
                        PropertyName   = $override.PropertyName
                        PropertyValue  = $override.PropertyValue
                        ApplyVersion   = $override.ApplyVersion
                        IsValid        = $override.IsValid
                        IsGlobal       = $globalMonitoringOverride
                        ExpirationTime = $override.ExpirationTime
                    })
            }
            return [PSCustomObject]@{
                MonitoringOverrides = $monitoringOverrides
                SimpleView          = $monitoringOverridesSimple
            }
        } catch {

            Write-Verbose "Failed to get the monitoring override. Inner Exception $_"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }
        }
    }
}
