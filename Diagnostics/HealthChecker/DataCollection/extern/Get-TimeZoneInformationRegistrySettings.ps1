#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-TimeZoneInformationRegistrySettings/Get-TimeZoneInformationRegistrySettings.ps1
#v21.01.22.2234
Function Get-TimeZoneInformationRegistrySettings {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Get-TimeZoneInformationRegistrySettings")
    Write-VerboseWriter("Passed: [string]MachineName: {0}" -f $MachineName)
    $timeZoneInformationSubKey = "SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    $dynamicDaylightTimeDisabled = Invoke-RegistryGetValue -MachineName $MachineName -SubKey $timeZoneInformationSubKey -GetValue "DynamicDaylightTimeDisabled" -CatchActionFunction $CatchActionFunction
    $timeZoneKeyName = Invoke-RegistryGetValue -MachineName $MachineName -Subkey $timeZoneInformationSubKey -GetValue "TimeZoneKeyName" -CatchActionFunction $CatchActionFunction
    $standardStart = Invoke-RegistryGetValue -MachineName $MachineName -SubKey $timeZoneInformationSubKey -GetValue "StandardStart" -CatchActionFunction $CatchActionFunction
    $daylightStart = Invoke-RegistryGetValue -MachineName $MachineName -SubKey $timeZoneInformationSubKey -GetValue "DaylightStart" -CatchActionFunction $CatchActionFunction

    $timeZoneInformationObject = New-Object PSCustomObject
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "DynamicDaylightTimeDisabled" -Value $dynamicDaylightTimeDisabled
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "TimeZoneKeyName" -Value $timeZoneKeyName
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "StandardStart" -Value $standardStart
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "DaylightStart" -Value $daylightStart

    $actionsToTake = @()
    if ($null -eq $timeZoneKeyName -or
        [string]::IsNullOrEmpty($timeZoneKeyName)) {
        Write-VerboseWriter("TimeZoneKeyName is null or empty. Action should be taken to address this.")
        $actionsToTake += "TimeZoneKeyName is blank. Need to switch your current time zone to a different value, then switch it back to have this value populated again."
    }
    foreach ($value in $standardStart) {
        if ($value -ne 0) {
            $standardStartNonZeroValue = $true
            break
        }
    }
    foreach ($value in $daylightStart) {
        if ($value -ne 0) {
            $daylightStartNonZeroValue = $true
            break
        }
    }
    if ($dynamicDaylightTimeDisabled -ne 0 -and (
            $standardStartNonZeroValue -or
            $daylightStartNonZeroValue
        )) {
        Write-VerboseWriter("Determined that there is a chance the settings set could cause a DST issue.")
        $dstIssueDetected = $true
        $actionsToTake += "High Warning: DynamicDaylightTimeDisabled is set, Windows can not properly detect any DST rule changes in your time zone. `
    It is possible that you could be running into this issue. Set 'Adjust for daylight saving time automatically to on'"
    } elseif ($dynamicDaylightTimeDisabled -ne 0) {
        Write-VerboseWriter("Daylight savings auto adjustment is disabled.")
        $actionsToTake += "Warning: DynamicDaylightTimeDisabled is set, Windows can not properly detect any DST rule changes in your time zone."
    }

    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "DstIssueDetected" -Value $dstIssueDetected
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "ActionsToTake" -Value $actionsToTake

    return $timeZoneInformationObject
}
