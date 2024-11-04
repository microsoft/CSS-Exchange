# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Get-RemoteRegistrySubKey.ps1
. $PSScriptRoot\..\..\..\Shared\Get-RemoteRegistryValue.ps1

# Use this after the counters have been localized.
function Get-CounterSamples {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$MachineName,

        [Parameter(Mandatory = $true)]
        [string[]]$Counter,

        [string]$CustomErrorAction = "Stop"
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    try {
        return (Get-Counter -ComputerName $MachineName -Counter $Counter -ErrorAction $CustomErrorAction).CounterSamples
    } catch {
        Write-Verbose "Failed to get counter samples"
    }
}

# Use this to localize the counters provided
function Get-LocalizedCounterSamples {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$MachineName,

        [Parameter(Mandatory = $true)]
        [string[]]$Counter,

        [string]$CustomErrorAction = "Stop"
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $localizedCounterLookup = @{}
    $localizedCounters = @()

    foreach ($computer in $MachineName) {

        foreach ($currentCounter in $Counter) {
            $counterObject = Get-CounterFullNameToCounterObject -FullCounterName $currentCounter
            $localizedCounterName = Get-LocalizedPerformanceCounterName -ComputerName $computer -PerformanceCounterName $counterObject.CounterName
            $localizedObjectName = Get-LocalizedPerformanceCounterName -ComputerName $computer -PerformanceCounterName $counterObject.ObjectName
            $localizedFullCounterName = ($counterObject.FullName.Replace($counterObject.CounterName, $localizedCounterName)).Replace($counterObject.ObjectName, $localizedObjectName)

            if (-not ($localizedCounters.Contains($localizedFullCounterName))) {
                $localizedCounters += $localizedFullCounterName
                $localizedCounterLookup.Add($localizedCounterName, $counterObject.FullName)
            }
        }
    }

    $currentErrorIndex = $Error.Count
    # Store the localized counter sample information so we can reverse engineer back to the English counter name so other code can handle it.
    $localizedCounterSamples = (Get-CounterSamples -MachineName $MachineName -Counter $localizedCounters -CustomErrorAction $CustomErrorAction)

    foreach ($localSample in $localizedCounterSamples) {
        foreach ($key in $localizedCounterLookup.Keys) {
            if ($localSample.Path -like "\\*$key") {
                # Found the localized Counter lookup, now we want to add a property to be able to find the counters in other areas of code by the English name.
                $localSample | Add-Member -MemberType NoteProperty -Name "OriginalCounterLookup" -Value $localizedCounterLookup[$key]
                break
            }
        }
    }
    Invoke-ErrorCatchActionLoopFromIndex $currentErrorIndex

    return $localizedCounterSamples
}

function Get-LocalizedPerformanceCounterName {
    [CmdletBinding()]
    [OutputType('System.String')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$PerformanceCounterName
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $baseParams = @{
        MachineName         = $ComputerName
        CatchActionFunction = ${Function:Invoke-CatchActions}
    }

    if ($null -eq $Script:EnglishOnlyOSCache) {
        $Script:EnglishOnlyOSCache = @{}
    }

    if ($null -eq $Script:Counter009Cache) {
        $Script:Counter009Cache = @{}
    }

    if ($null -eq $Script:CounterCurrentLanguageCache) {
        $Script:CounterCurrentLanguageCache = @{}
    }

    if (-not ($Script:EnglishOnlyOSCache.ContainsKey($ComputerName))) {
        $perfLib = Get-RemoteRegistrySubKey @baseParams -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib"

        if ($null -eq $perfLib) {
            Write-Verbose "No Perflib on computer. Assume EnglishOnlyOS for Get-Counter attempt"
            $Script:EnglishOnlyOSCache.Add($ComputerName, $true)
        } else {
            try {
                $englishOnlyOS = ($perfLib.GetSubKeyNames() |
                        Where-Object { $_ -like "0*" }).Count -eq 1
                Write-Verbose "Determined computer '$ComputerName' is englishOnlyOS: $englishOnlyOS"
                $Script:EnglishOnlyOSCache.Add($ComputerName, $englishOnlyOS)
            } catch {
                Write-Verbose "Failed to run GetSubKeyNames() on the opened key. Assume EnglishOnlyOS for Get-Counter attempt"
                $Script:EnglishOnlyOSCache.Add($ComputerName, $true)
                Invoke-CatchActions
            }
        }
    }

    if ($Script:EnglishOnlyOSCache[$ComputerName]) {
        Write-Verbose "English Only Machine, return same value"
        return $PerformanceCounterName
    }

    if (-not ($Script:Counter009Cache.ContainsKey($ComputerName))) {
        $params = $baseParams + @{
            SubKey    = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009"
            GetValue  = "Counter"
            ValueType = "MultiString"
        }
        $enUSCounterKeys = Get-RemoteRegistryValue @params

        if ($null -eq $enUSCounterKeys) {
            Write-Verbose "No 'en-US' (009) 'Counter' registry value found."
            Write-Verbose "Set Computer to English OS to just return PerformanceCounterName"
            $Script:EnglishOnlyOSCache[$ComputerName] = $true
            return $PerformanceCounterName
        } else {
            $Script:Counter009Cache.Add($ComputerName, $enUSCounterKeys)
        }
    }

    if (-not ($Script:CounterCurrentLanguageCache.ContainsKey($ComputerName))) {
        $params = $baseParams + @{
            SubKey    = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage"
            GetValue  = "Counter"
            ValueType = "MultiString"
        }
        $currentCounterKeys = Get-RemoteRegistryValue @params

        if ($null -eq $currentCounterKeys) {
            Write-Verbose "No 'localized' (CurrentLanguage) 'Counter' registry value found"
            Write-Verbose "Set Computer to English OS to just return PerformanceCounterName"
            $Script:EnglishOnlyOSCache[$ComputerName] = $true
            return $PerformanceCounterName
        } else {
            $Script:CounterCurrentLanguageCache.Add($ComputerName, $currentCounterKeys)
        }
    }

    $counterName = $PerformanceCounterName.ToLower()
    Write-Verbose "Trying to query ID index for Performance Counter: $counterName"
    $enUSCounterKeys = $Script:Counter009Cache[$ComputerName]
    $currentCounterKeys = $Script:CounterCurrentLanguageCache[$ComputerName]
    $counterIdIndex = ($enUSCounterKeys.ToLower().IndexOf("$counterName") - 1)

    if ($counterIdIndex -ge 0) {
        Write-Verbose "Counter ID Index: $counterIdIndex"
        Write-Verbose "Verify Value: $($enUSCounterKeys[$counterIdIndex + 1])"
        $counterId = $enUSCounterKeys[$counterIdIndex]
        Write-Verbose "Counter ID: $counterId"
        $localizedCounterNameIndex = ($currentCounterKeys.IndexOf("$counterId") + 1)

        if ($localizedCounterNameIndex -gt 0) {
            $localCounterName = $currentCounterKeys[$localizedCounterNameIndex]
            Write-Verbose "Found Localized Counter Index: $localizedCounterNameIndex"
            Write-Verbose "Localized Counter Name: $localCounterName"
            return $localCounterName
        } else {
            Write-Verbose "Failed to find Localized Counter Index"
            return $PerformanceCounterName
        }
    } else {
        Write-Verbose "Failed to find the counter ID."
        return $PerformanceCounterName
    }
}

function Get-CounterFullNameToCounterObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FullCounterName
    )

    # Supported Scenarios
    # \\adt-e2k13aio1\LogicalDisk(HardDiskVolume1)\avg. disk sec/read
    # \\adt-e2k13aio1\\LogicalDisk(HardDiskVolume1)\avg. disk sec/read
    # \LogicalDisk(HardDiskVolume1)\avg. disk sec/read
    if (-not ($FullCounterName.StartsWith("\"))) {
        throw "Full Counter Name Should start with '\'"
    } elseif ($FullCounterName.StartsWith("\\")) {
        $endOfServerIndex = $FullCounterName.IndexOf("\", 2)
        $serverName = $FullCounterName.Substring(2, $endOfServerIndex - 2)
    } else {
        $endOfServerIndex = 0
    }
    $startOfCounterIndex = $FullCounterName.LastIndexOf("\") + 1
    $endOfCounterObjectIndex = $FullCounterName.IndexOf("(")

    if ($endOfCounterObjectIndex -eq -1) {
        $endOfCounterObjectIndex = $startOfCounterIndex - 1
    } else {
        $instanceName = $FullCounterName.Substring($endOfCounterObjectIndex + 1, ($FullCounterName.IndexOf(")") - $endOfCounterObjectIndex - 1))
    }

    $doubleSlash = 0
    if (($FullCounterName.IndexOf("\\", 2) -ne -1)) {
        $doubleSlash = 1
    }

    return [PSCustomObject]@{
        FullName     = $FullCounterName
        ServerName   = $serverName
        ObjectName   = ($FullCounterName.Substring($endOfServerIndex + 1 + $doubleSlash, $endOfCounterObjectIndex - $endOfServerIndex - 1 - $doubleSlash))
        InstanceName = $instanceName
        CounterName  = $FullCounterName.Substring($startOfCounterIndex)
    }
}
