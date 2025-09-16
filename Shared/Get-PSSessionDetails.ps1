# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-PSSessionDetails {
    [CmdletBinding()]
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "============= PowerShell Information ==========="
    Write-Verbose "Version: $($PSVersionTable.PSVersion)"

    try {
        $modulesLoaded = Get-Module -ErrorAction Stop

        Write-Verbose "Module(s) Currently Loaded:"
        foreach ($m in $modulesLoaded) {
            Write-Verbose "Name: $($m.Name) - Type: $($m.ModuleType)"
        }
    } catch {
        Write-Verbose "Exception: $_"
    }

    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        Write-Verbose "Is Elevated? $($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    } catch {
        Write-Verbose "Exception: $_"
    }

    Write-Verbose "PowerShell Language Mode: $($ExecutionContext.SessionState.LanguageMode)"

    Write-Verbose "============= User Information ================="
    Write-Verbose "User: $env:USERNAME"
    Write-Verbose "Domain Name: $env:USERDNSDOMAIN"

    Write-Verbose "============= Computer Information ============="
    Write-Verbose "OS Version: $(([environment]::OSVersion.Version).ToString())"
    Write-Verbose "NetBIOS Name: $env:COMPUTERNAME"
    Write-Verbose "FQDN: $([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)"

    try {
        Write-Verbose "============= OS Language Information =========="
        $osLanguageInformation = Get-WinSystemLocale -ErrorAction Stop
        Write-Verbose "Name: $($osLanguageInformation.Name)"
        Write-Verbose "Display Name: $($osLanguageInformation.DisplayName)"
        # cSpell:disable-next-line
        Write-Verbose "LCID: $($osLanguageInformation.LCID)"
    } catch {
        Write-Verbose "Exception: $_"
    }

    try {
        Write-Verbose "============= UI Language Information =========="
        $uiLanguageInformation = Get-UICulture -ErrorAction Stop
        Write-Verbose "Name: $($uiLanguageInformation.Name)"
        Write-Verbose "Display Name: $($uiLanguageInformation.DisplayName)"
        # cSpell:disable-next-line
        Write-Verbose "LCID: $($uiLanguageInformation.LCID)"
    } catch {
        Write-Verbose "Exception: $_"
    }

    try {
        Write-Verbose "============= Time Zone Information ============"
        $timeZoneInformation = Get-TimeZone -ErrorAction Stop
        Write-Verbose "Id: $($timeZoneInformation.Id)"
        Write-Verbose "Display Name: $($timeZoneInformation.DisplayName)"
        Write-Verbose "DST Supported? $($timeZoneInformation.SupportsDaylightSavingTime)"
    } catch {
        Write-Verbose "Exception: $_"
    }

    Write-Verbose "================================================"
}
