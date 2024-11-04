# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistrySubKey.ps1
function Get-ExchangeUpdates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Exchange2013", "Exchange2016", "Exchange2019")]
        [string]$ExchangeMajorVersion
    )
    Write-Verbose("Calling: $($MyInvocation.MyCommand) Passed: $ExchangeMajorVersion")
    $RegLocation = [string]::Empty

    if ("Exchange2013" -eq $ExchangeMajorVersion) {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2013"
    } elseif ("Exchange2016" -eq $ExchangeMajorVersion) {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2016"
    } else {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2019"
    }

    $RegKey = Get-RemoteRegistrySubKey -MachineName $Server `
        -SubKey $RegLocation `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($null -ne $RegKey) {
        $IU = $RegKey.GetSubKeyNames()
        if ($null -ne $IU) {
            Write-Verbose "Detected fixes installed on the server"
            $installedUpdates = New-Object System.Collections.Generic.List[object]
            foreach ($key in $IU) {
                $IUKey = $RegKey.OpenSubKey($key)
                $IUName = $IUKey.GetValue("PackageName")
                Write-Verbose "Found: $IUName"
                $IUInstalledDate = $IUKey.GetValue("InstalledDate")
                $installedUpdates.Add(([PSCustomObject]@{
                            PackageName   = $IUName
                            InstalledDate = $IUInstalledDate
                        }))
            }
            return $installedUpdates
        } else {
            Write-Verbose "No IUs found in the registry"
        }
    } else {
        Write-Verbose "No RegKey returned"
    }

    Write-Verbose "Exiting: Get-ExchangeUpdates"
    return $null
}
