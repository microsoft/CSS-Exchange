# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore accesstoken

function Load-Module {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'The token is provided at runtime via the pipeline SYSTEM_ACCESSTOKEN environment variable, not a hardcoded secret. A PSCredential is required to authenticate Install-Module against the Azure Artifacts feed.')]
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
        Name  = $Name
        Force = $true
    }

    if (-not [string]::IsNullOrEmpty($MinimumVersion)) {
        $params.MinimumVersion = $MinimumVersion
    }

    # Under Network Isolation the public PowerShell Gallery is blocked, so install
    # modules from the internal Azure Artifacts feed. These environment variables are
    # only set by the pipeline; local development continues to use the PowerShell Gallery.
    if (-not [string]::IsNullOrEmpty($env:CFS_FEED_SOURCE) -and
        -not [string]::IsNullOrEmpty($env:SYSTEM_ACCESSTOKEN)) {
        $repositoryName = "CssExchangeCfs"
        $secureToken = ConvertTo-SecureString $env:SYSTEM_ACCESSTOKEN -AsPlainText -Force
        $credential = [PSCredential]::new("azdo", $secureToken)

        # Register the feed if it is missing, otherwise normalize it in case a reused
        # agent left it pointing at a different location or not trusted. Install-Module
        # is pinned to this repository below, so the public PowerShell Gallery does not
        # need to be unregistered.
        $existingRepository = Get-PSRepository -Name $repositoryName -ErrorAction SilentlyContinue
        if ($null -eq $existingRepository) {
            Register-PSRepository -Name $repositoryName -SourceLocation $env:CFS_FEED_SOURCE -InstallationPolicy Trusted -Credential $credential
        } elseif ($existingRepository.SourceLocation -ne $env:CFS_FEED_SOURCE -or $existingRepository.InstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name $repositoryName -SourceLocation $env:CFS_FEED_SOURCE -InstallationPolicy Trusted -Credential $credential
        }

        $params.Repository = $repositoryName
        $params.Credential = $credential
    }

    $errorCount = $Error.Count
    Install-Module @params
    if ($Error.Count -gt $errorCount) {
        return $false
    }

    return $true
}
