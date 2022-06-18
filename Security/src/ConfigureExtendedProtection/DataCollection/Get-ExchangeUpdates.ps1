# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistrySubKey.ps1

function Get-ExchangeUpdates {
    param(
        [string]$Server,
        [string]$Version
    )

    if (2 -eq $Version) {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2019"
    } elseif (1 -eq $Version) {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2016"
    } else {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2013"
    }

    $RegKey = Get-RemoteRegistrySubKey -MachineName $Server -SubKey $RegLocation

    Write-Output $RegKey

    if ($null -ne $RegKey) {
        $IU = $RegKey.GetSubKeyNames()
        if ($null -ne $IU) {
            Write-Host ("Detected fixes installed on the server: {0}" -f $Server)
            $fixes = @()
            foreach ($key in $IU) {
                $IUKey = $RegKey.OpenSubKey($key)
                $IUName = $IUKey.GetValue("Server Language")
                $fixes += $IUName
            }
            Write-Host $fixes
            return $fixes
        } else {
            Write-Host ("No IUs found in the registry")
        }
    } else {
        Write-Host ("No RegKey returned")
    }
    return $null
}
