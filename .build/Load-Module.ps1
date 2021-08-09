# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Load-Module {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [string]
        $MinimumVersion
    )

    $moduleAlreadyLoaded = Get-Module -Name $Name
    if ($null -ne $moduleAlreadyLoaded) {
        if ([string]::IsNullOrEmpty($MinimumVersion) -or $moduleAlreadyLoaded.Version -ge $MinimumVersion) {
            return $true
        } else {
            Remove-Module -Name $Name
        }
    }

    $modulesOnDisk = @(Get-Module -Name $Name -ListAvailable | Sort-Object Version -Descending)
    $moduleToLoad = $null
    foreach ($module in $modulesOnDisk) {
        if ([string]::IsNullOrEmpty($MinimumVersion) -or $module.Version -ge $MinimumVersion) {
            $moduleToLoad = $module
            break
        }
    }

    if ($null -ne $moduleToLoad) {
        Import-Module $moduleToLoad
        return $true
    }

    $params = @{
        Name = $Name
    }

    if (-not [string]::IsNullOrEmpty($MinimumVersion)) {
        $params.MinimumVersion = $MinimumVersion
    }

    $errorCount = $Error.Count
    Install-Module @params -Force
    if ($Error.Count -gt $errorCount) {
        return $false
    }

    return $true
}
