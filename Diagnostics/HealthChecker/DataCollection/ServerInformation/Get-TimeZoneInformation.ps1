# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
function Get-TimeZoneInformation {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $actionsToTake = @()
        $dstIssueDetected = $false
        $registryParams = @{
            MachineName         = $MachineName
            SubKey              = "SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
            CatchActionFunction = $CatchActionFunction
        }
    }
    process {
        $dynamicDaylightTimeDisabled = Get-RemoteRegistryValue @registryParams -GetValue "DynamicDaylightTimeDisabled"
        $timeZoneKeyName = Get-RemoteRegistryValue @registryParams -GetValue "TimeZoneKeyName"
        $standardStart = Get-RemoteRegistryValue @registryParams -GetValue "StandardStart"
        $daylightStart = Get-RemoteRegistryValue @registryParams -GetValue "DaylightStart"

        if ([string]::IsNullOrEmpty($timeZoneKeyName)) {
            Write-Verbose "TimeZoneKeyName is null or empty. Action should be taken to address this."
            $actionsToTake += "TimeZoneKeyName is blank. Need to switch your current time zone to a different value, then switch it back to have this value populated again."
        }

        $standardStartNonZeroValue = ($null -ne ($standardStart | Where-Object { $_ -ne 0 }))
        $daylightStartNonZeroValue = ($null -ne ($daylightStart | Where-Object { $_ -ne 0 }))

        if ($dynamicDaylightTimeDisabled -ne 0 -and
            ($standardStartNonZeroValue -or
            $daylightStartNonZeroValue)) {
            Write-Verbose "Determined that there is a chance the settings set could cause a DST issue."
            $dstIssueDetected = $true
            $actionsToTake += "High Warning: DynamicDaylightTimeDisabled is set, Windows can not properly detect any DST rule changes in your time zone. `
            It is possible that you could be running into this issue. Set 'Adjust for daylight saving time automatically to on'"
        } elseif ($dynamicDaylightTimeDisabled -ne 0) {
            Write-Verbose "Daylight savings auto adjustment is disabled."
            $actionsToTake += "Warning: DynamicDaylightTimeDisabled is set, Windows can not properly detect any DST rule changes in your time zone."
        }

        $params = @{
            ComputerName           = $Server
            ScriptBlock            = { ([System.TimeZone]::CurrentTimeZone).StandardName }
            ScriptBlockDescription = "Getting Current Time Zone"
            CatchActionFunction    = $CatchActionFunction
        }

        $currentTimeZone = Invoke-ScriptBlockHandler @params
    }
    end {
        return [PSCustomObject]@{
            DynamicDaylightTimeDisabled = $dynamicDaylightTimeDisabled
            TimeZoneKeyName             = $timeZoneKeyName
            StandardStart               = $standardStart
            DaylightStart               = $daylightStart
            DstIssueDetected            = $dstIssueDetected
            ActionsToTake               = [array]$actionsToTake
            CurrentTimeZone             = $currentTimeZone
        }
    }
}
