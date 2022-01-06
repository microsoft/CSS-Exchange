# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Get-RemoteRegistrySubKey.ps1
. $PSScriptRoot\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\Invoke-CatchActions.ps1

# Use this after the counters have been localized.
Function Get-CounterSamples {
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
        Write-Verbose "Failed ot get counter samples"
        Invoke-CatchActions
    }
}

# Use this to localize the counters provided
Function Get-LocalizedCounterSamples {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$MachineName,

        [Parameter(Mandatory = $true)]
        [string[]]$Counter,

        [string]$CustomErrorAction = "Stop"
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $localizedCounters = @()

    foreach ($computer in $MachineName) {

        foreach ($currentCounter in $Counter) {
            $counterObject = Get-CounterFullNameToCounterObject -FullCounterName $currentCounter
            $localizedCounterName = Get-LocalizedPerformanceCounterName -ComputerName $computer -PerformanceCounterName $counterObject.CounterName
            $localizedObjectName = Get-LocalizedPerformanceCounterName -ComputerName $computer -PerformanceCounterName $counterObject.ObjectName
            $localizedFullCounterName = ($counterObject.FullName.Replace($counterObject.CounterName, $localizedCounterName)).Replace($counterObject.ObjectName, $localizedObjectName)

            if (-not ($localizedCounters.Contains($localizedFullCounterName))) {
                $localizedCounters += $localizedFullCounterName
            }
        }
    }

    return (Get-CounterSamples -MachineName $MachineName -Counter $localizedCounters -CustomErrorAction $CustomErrorAction)
}

Function Get-LocalizedPerformanceCounterName {
    [CmdletBinding()]
    [OutputType('System.String')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$PerformanceCounterName
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

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
        $perfLib = Get-RemoteRegistrySubKey -MachineName $ComputerName `
            -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009" `
            -CatchActionFunction ${Function:Invoke-CatchActions}
        $englishOnlyOS = ($perfLib.GetSubKeyNames() |
                Where-Object { $_ -like "0*" }).Count -eq 1
        $Script:EnglishOnlyOSCache.Add($ComputerName, $englishOnlyOS)
    }

    if ($Script:EnglishOnlyOSCache[$ComputerName]) {
        Write-Verbose "English Only Machine, return same value"
        return $PerformanceCounterName
    }

    if (-not ($Script:Counter009Cache.ContainsKey($ComputerName))) {
        $enUSCounterKeys = Get-RemoteRegistryValue -MachineName $ComputerName `
            -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009" `
            -GetValue "Counter" `
            -ValueType "MultiString" `
            -CatchActionFunction ${Function:Invoke-CatchActions}

        if ($null -eq $enUSCounterKeys) {
            Write-Verbose "No 'en-US' (009) 'Counter' registry value found."
            return $null
        } else {
            $Script:Counter009Cache.Add($ComputerName, $enUSCounterKeys)
        }
    }

    if (-not ($Script:CounterCurrentLanguageCache.ContainsKey($ComputerName))) {
        $currentCounterKeys = Get-RemoteRegistryValue -MachineName $ComputerName `
            -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" `
            -GetValue "Counter" `
            -ValueType "MultiString" `
            -CatchActionFunction ${Function:Invoke-CatchActions}

        if ($null -eq $currentCounterKeys) {
            Write-Verbose "No 'localized' (CurrentLanguage) 'Counter' registry value found"
            return $null
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
        }
    } else {
        Write-Verbose "Failed to find the counter ID."
    }
}

Function Get-CounterFullNameToCounterObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FullCounterName
    )

    # Supported Scenarios
    # \\adt-e2k13aio1\logicaldisk(harddiskvolume1)\avg. disk sec/read
    # \logicaldisk(harddiskvolume1)\avg. disk sec/read
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

    return [PSCustomObject]@{
        FullName     = $FullCounterName
        ServerName   = $serverName
        ObjectName   = ($FullCounterName.Substring($endOfServerIndex + 1, $endOfCounterObjectIndex - $endOfServerIndex - 1))
        InstanceName = $instanceName
        CounterName  = $FullCounterName.Substring($startOfCounterIndex)
    }
}
