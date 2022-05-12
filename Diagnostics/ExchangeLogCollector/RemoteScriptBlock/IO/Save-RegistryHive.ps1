# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchBlockActions.ps1
. $PSScriptRoot\Save-DataInfoToFile.ps1
Function Save-RegistryHive {
    [CmdletBinding()]
    param(
        [string]$RegistryPath,
        [string]$SaveName,
        [string]$SaveToPath,
        [switch]$UseGetChildItem
    )
    Write-Verbose "Function Enter: $($MyInvocation.MyCommand)"

    try {
        if ($UseGetChildItem) {
            $results = Get-ChildItem -Path $RegistryPath -Recurse -ErrorAction Stop
        } else {
            $results = Get-Item -Path $RegistryPath -ErrorAction Stop
        }
        Write-Verbose "Successfully got registry hive information for: $RegistryPath"
        Save-DataInfoToFile -DataIn $results -SaveToLocation "$SaveToPath\$SaveName" -FormatList $false
    } catch {
        Write-Verbose "Failed to get registry hive for: $RegistryPath"
        Invoke-CatchBlockActions
    }

    $updatedRegistryPath = $RegistryPath.Replace("HKLM:", "HKEY_LOCAL_MACHINE\")
    $baseSaveName = Add-ServerNameToFileName "$SaveToPath\$SaveName"
    try {
        reg export $updatedRegistryPath "$baseSaveName.reg" | Out-Null

        if ($LASTEXITCODE) {
            Write-Verbose "Failed to export the registry hive for: $updatedRegistryPath"
        }
        reg save $updatedRegistryPath "$baseSaveName.hiv" | Out-Null

        if ($LASTEXITCODE) {
            Write-Verbose "Failed to save the registry hive for: $updatedRegistryPath"
        }
        "To read the registry hive. Run 'reg load HKLM\TempHive $SaveName.hiv'. Then Open your regedit then go to HKLM:\TempHive to view the data." |
            Out-File -FilePath "$baseSaveName`_HowToRead.txt"
    } catch {
        Write-Verbose "failed to export/save the registry hive for: $updatedRegistryPath"
        Invoke-CatchBlockActions
    }
}
