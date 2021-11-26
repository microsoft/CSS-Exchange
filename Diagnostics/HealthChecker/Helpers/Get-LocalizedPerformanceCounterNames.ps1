# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\Invoke-CatchActions.ps1

Function Get-LocalizedPerformanceCounterNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [string]$PerformanceCounterName
    )

    begin {
        Function Get-PerformanceCounterId {
            [CmdletBinding()]
            [OutputType([UInt32])]
            param (
                [Parameter(Mandatory = $true)]
                [string]$ComputerName,
                [Parameter(Mandatory = $true)]
                [string]$PerformanceCounterName
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $enUSCounterKey = Get-RemoteRegistryValue -MachineName $ComputerName `
                -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009" `
                -GetValue "Counter" `
                -ValueType "MultiString" `
                -CatchActionFunction ${Function:Invoke-CatchActions}
            try {
                if ($null -ne $enUSCounterKey) {
                    # Note: Name is case-sensitive
                    # Id of the counter is listed before the counter name so we need to substract -1 to get the index for the id
                    Write-Verbose "Trying to query ID index for Performance Counter: $($PerformanceCounterName)"
                    $counterNameIndex = ($enUSCounterKey.IndexOf("$($PerformanceCounterName)") - 1)
                    if ($counterNameIndex -ne -1) {
                        Write-Verbose "Index found: $($counterNameIndex)"
                        return $enUSCounterKey[$counterNameIndex]
                    } else {
                        Write-Verbose "No index was found"
                        return $null
                    }
                } else {
                    Write-Verbose "No 'en-US' (009) 'Counter' registry value found"
                    return $null
                }
            } catch {
                Write-Verbose "Ran into an issue when calling Split method. Parameters passed: $ComputerName , $PerformanceCounterName"
                throw
            }
        }

        Function Get-LocalizedCounterName {
            [CmdletBinding()]
            [OutputType([string])]
            param (
                [Parameter(Mandatory = $true)]
                [string]$ComputerName,
                [Parameter(Mandatory = $true)]
                [UInt32]$PerformanceCounterId
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $localizedCounterKey = Get-RemoteRegistryValue -MachineName $ComputerName `
                -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" `
                -GetValue "Counter" `
                -ValueType "MultiString" `
                -CatchActionFunction ${Function:Invoke-CatchActions}
            try {
                if ($null -ne $localizedCounterKey) {
                    # Name of the counter is listed after the counter id so we need to add +1 to get correct index for the name
                    Write-Verbose "Trying to query localized Performance Counter name for Id: $($PerformanceCounterId)"
                    $localizedCounterNameIndex = ($localizedCounterKey.IndexOf("$($PerformanceCounterId)") + 1)
                    if ($localizedCounterNameIndex -ne -1) {
                        Write-Verbose "Index found: $($localizedCounterNameIndex)"
                        return $localizedCounterKey[$localizedCounterNameIndex]
                    } else {
                        Write-Verbose "No index was found"
                        return $null
                    }
                } else {
                    Write-Verbose "No 'localized' (CurrentLanguage) 'Counter' registry value found"
                    return $null
                }
            } catch {
                Write-Verbose "Ran into an issue when calling Split method. Parameters passed: $ComputerName , $PerformanceCounterId"
                throw
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        try {
            $perfCounterSplit = $PerformanceCounterName.Split("\", [System.StringSplitOptions]::RemoveEmptyEntries)
            $perfCounterArray = @()
            $i = 0
            foreach ($perfCounterName in $perfCounterSplit) {
                $i++
                $tempPerfCounterId = $null
                $tempPerfCounterId = Get-PerformanceCounterId -PerformanceCounterName $perfCounterName `
                    -ComputerName $ComputerName `
                    -ErrorAction Stop
                if ($null -ne $tempPerfCounterId) {
                    $tempPerfCounterLocName = $null
                    $tempPerfCounterLocName = Get-LocalizedCounterName -PerformanceCounterId $tempPerfCounterId `
                        -ComputerName $ComputerName `
                        -ErrorAction Stop
                } else {
                    Write-Verbose "No valid Performane Counter Id was found"
                    throw
                }

                $perfCounterArray += $tempPerfCounterLocName
            }
        } catch {
            Write-Verbose "Unable to locate localized Performance Counter name"
            Invoke-CatchActions
        }
    } end {
        if ($perfCounterArray.Count -lt $i) {
            Write-Verbose "Unable to find a localized counter name for any counter that was passed"
            Write-Verbose "Passed: $($perfCounterSplit.Count) Localized: $($perfCounterArray.Count)"
            return $null
        }

        return $perfCounterArray
    }
}
