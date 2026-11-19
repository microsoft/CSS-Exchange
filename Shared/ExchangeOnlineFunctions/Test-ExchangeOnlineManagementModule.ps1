# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Imports the ExchangeOnlineManagement module and reports whether it is available.

.DESCRIPTION
    Returns true when the module is loaded after the call and false when it is missing, which
    leaves the decision how to report a missing module to the caller. Callers can therefore keep
    their own localized message and decide whether a missing module ends the script or not.

.PARAMETER InstallIfMissing
    Installs the module for the current user when it is not present. Without this switch a missing
    module is only reported.

.EXAMPLE
    if (-not (Test-ExchangeOnlineManagementModule)) {
        Write-Warning $LocalizedStrings.EXOV2ModuleNotInstalled
        exit
    }

    Ends the script when the module is missing.

.EXAMPLE
    Test-ExchangeOnlineManagementModule -InstallIfMissing

    Installs the module for the current user when it is not present yet.
#>
function Test-ExchangeOnlineManagementModule {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$InstallIfMissing
    )

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $moduleName = "ExchangeOnlineManagement"
    }
    process {
        Import-Module -Name $moduleName -ErrorAction SilentlyContinue

        if ($null -ne (Get-Module -Name $moduleName)) {
            return $true
        }

        if (-not $InstallIfMissing) {
            Write-Verbose "The $moduleName module is not available"
            return $false
        }

        try {
            Write-Verbose "Installing the $moduleName module for the current user"
            Install-Module -Name $moduleName -Force -Scope CurrentUser -ErrorAction Stop
            Import-Module -Name $moduleName -Force -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to install the $moduleName module. Exception: $($_.Exception.Message)"
            return $false
        }

        return ($null -ne (Get-Module -Name $moduleName))
    }
}
