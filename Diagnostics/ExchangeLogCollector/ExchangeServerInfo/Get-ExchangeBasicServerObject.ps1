# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
#TODO: Create Pester Testing on this
# Used to get the Exchange Version information and what roles are set on the server.
function Get-ExchangeBasicServerObject {
    param(
        [Parameter(Mandatory = $true)][string]$ServerName,
        [Parameter(Mandatory = $false)][bool]$AddGetServerProperty = $false
    )
    Write-Verbose("Function Enter: $($MyInvocation.MyCommand)")
    Write-Verbose("Passed: [string]ServerName: {0}" -f $ServerName)
    try {
        $getExchangeServer = Get-ExchangeServer $ServerName -Status -ErrorAction Stop
    } catch {
        Write-Host "Failed to detect server $ServerName as an Exchange Server" -ForegroundColor "Red"
        Invoke-CatchActions
        return $null
    }

    $exchAdminDisplayVersion = $getExchangeServer.AdminDisplayVersion
    $exchServerRole = $getExchangeServer.ServerRole
    Write-Verbose("AdminDisplayVersion: {0} | ServerRole: {1}" -f $exchAdminDisplayVersion.ToString(), $exchServerRole.ToString())
    $buildVersionInformation = Get-ExchangeBuildVersionInformation $exchAdminDisplayVersion

    if ($buildVersionInformation.BuildVersion.Major -eq 15) {
        if ($buildVersionInformation.BuildVersion.Minor -eq 0) {
            $exchVersion = 15
        } elseif ($buildVersionInformation.BuildVersion.Minor -eq 1) {
            $exchVersion = 16
        } else {
            $exchVersion = 19
        }
    }

    $mailbox = $exchServerRole -like "*Mailbox*"
    $dagName = [string]::Empty
    $exchangeServer = $null

    if ($mailbox) {
        $getMailboxServer = Get-MailboxServer $ServerName

        if (-not([string]::IsNullOrEmpty($getMailboxServer.DatabaseAvailabilityGroup))) {
            $dagName = $getMailboxServer.DatabaseAvailabilityGroup.ToString()
        }
    }

    if ($AddGetServerProperty) {
        $exchangeServer = $getExchangeServer
    }

    $exchServerObject = [PSCustomObject]@{
        ServerName     = $getExchangeServer.Name.ToUpper()
        Mailbox        = $mailbox
        MailboxOnly    = $exchServerRole -eq "Mailbox"
        Hub            = $exchVersion -ge 15 -and (-not ($exchServerRole -eq "ClientAccess"))
        CAS            = $exchVersion -ge 16 -or $exchServerRole -like "*ClientAccess*"
        CASOnly        = $exchServerRole -eq "ClientAccess"
        Edge           = $exchServerRole -eq "Edge"
        Version        = $exchVersion
        DAGMember      = (-not ([string]::IsNullOrEmpty($dagName)))
        DAGName        = $dagName
        ExchangeServer = $exchangeServer
    }

    Write-Verbose("Mailbox: {0} | CAS: {1} | Hub: {2} | CASOnly: {3} | MailboxOnly: {4} | Edge: {5} | DAGMember {6} | Version: {7} | AnyTransportSwitchesEnabled: {8} | DAGName: {9}" -f $exchServerObject.Mailbox,
        $exchServerObject.CAS,
        $exchServerObject.Hub,
        $exchServerObject.CASOnly,
        $exchServerObject.MailboxOnly,
        $exchServerObject.Edge,
        $exchServerObject.DAGMember,
        $exchServerObject.Version,
        $Script:AnyTransportSwitchesEnabled,
        $exchServerObject.DAGName
    )

    return $exchServerObject
}
