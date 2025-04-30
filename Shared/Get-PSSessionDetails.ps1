# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-PSSessionDetails {
    [CmdletBinding()]
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    # cSpell:disable
    Write-Verbose "============= PowerShell Information ==========="
    Write-Verbose "Version: $($PSVersionTable.PSVersion)"

    try {
        $modulesLoaded = Get-Module -ErrorAction Stop

        Write-Verbose "Module(s) Loaded:"
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

    Write-Verbose "Language Mode: $($ExecutionContext.SessionState.LanguageMode)"

    Write-Verbose "============= User Information ================="
    Write-Verbose "User: $env:USERNAME"
    Write-Verbose "Domain Name: $env:USERDNSDOMAIN"

    Write-Verbose "============= Computer Information ============="
    Write-Verbose "NetBIOS Name: $env:COMPUTERNAME"
    Write-Verbose "FQDN: $([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)"

    try {
        $osLanguageInformation = Get-WinSystemLocale -ErrorAction Stop
        Write-Verbose "OS Language:"
        Write-Verbose "Name: $($osLanguageInformation.Name) - Display Name: $($osLanguageInformation.DisplayName) - LCID: $($osLanguageInformation.LCID)"
    } catch {
        Write-Verbose "Exception: $_"
    }

    try {
        $timeZoneInformation = Get-TimeZone -ErrorAction Stop
        Write-Verbose "Time Zone:"
        Write-Verbose "Id: $($timeZoneInformation.Id) - Display Name: $($timeZoneInformation.DisplayName) - DST supported? $($timeZoneInformation.SupportsDaylightSavingTime)"
    } catch {
        Write-Verbose "Exception: $_"
    }

    Write-Verbose "================================================"
    # cSpell:enable
}
