# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
function Test-ExchangeOnlineConnection {
    try {
        $CheckExoMailbox = get-EOMailbox $UserOnline -ErrorAction Stop
        if ($null -ne $CheckExoMailbox) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}
function FetchAutoDiscoverInformation {
    if (-not $Script:AutoDiscoveryVirtualDirectory -or -not $Script:AutoDiscoveryVirtualDirectoryOAuth) {
        $Script:AutoDiscoveryVirtualDirectory = Get-AutoDiscoverVirtualDirectory -Server $server | Select-Object Identity, Name, ExchangeVersion, *authentication* -ErrorAction SilentlyContinue
        $Script:AutoDiscoveryVirtualDirectoryOAuth = $Script:AutoDiscoveryVirtualDirectory
    }
}
function FetchEWSInformation {
    if (-not $Script:WebServicesVirtualDirectory -or -not $Script:WebServicesVirtualDirectoryOAuth) {
        $Script:WebServicesVirtualDirectory = Get-WebServicesVirtualDirectory -Server $server | Select-Object Identity, Name, ExchangeVersion, *Authentication*, *url -ErrorAction SilentlyContinue
        $Script:WebServicesVirtualDirectoryOAuth = $Script:WebServicesVirtualDirectory
    }
}
function CheckIfExchangeServer {
    param (
        [string]$Server
    )
    $exchangeServer = Get-ExchangeServer $server -ErrorAction SilentlyContinue
    if (!$exchangeServer) {
        Write-Output "$Server is not an Exchange Server. This script need to be run in an Exchange Server version 2013, 2016 or 2019"
        return
    }
}
function CheckParameters {
    $MissingParameters = @()
    if ([string]::IsNullOrWhiteSpace($ExchangeOnlineDomain)) {
        $MissingParameters += "Exchange Online Domain. Example: "
    }
    if ([string]::IsNullOrWhiteSpace($exchangeOnPremLocalDomain)) {
        $MissingParameters += "Exchange On Premises Local Domain.  Example: . 'C:\scripts\FreeBusyChecker\FreeBusyChecker.ps1' -OnPremisesUser John@Contoso.com"
    }
    if ([string]::IsNullOrWhiteSpace($exchangeOnPremDomain)) {
        $MissingParameters += "Exchange On Premises Domain.  Example: -OnPremLocalDomain Contoso.local"
    }
    if ([string]::IsNullOrWhiteSpace($exchangeOnPremEWS)) {
        $MissingParameters += "Exchange On Premises EWS Virtual Directory External URL.  Example:  'C:\FreeBusyChecker.ps1' -OnPremEWSUrl https://mail.contoso.com/EWS/Exchange.asmx"
    }
    if ([string]::IsNullOrWhiteSpace($UserOnPrem)) {
        $MissingParameters += "On Premises User Mailbox.  Example: 'C:\FreeBusyChecker.ps1' -OnPremisesUser John@Contoso.com"
    }
    if ([string]::IsNullOrWhiteSpace($UserOnline)) {
        $MissingParameters += "Exchange Online Mailbox.  Example: 'C:\FreeBusyChecker.ps1' -OnlineUser John@Contoso.onmicrosoft.com"
    }

    if ($MissingParameters.Count -gt 0) {
        foreach ($param in $MissingParameters) {
            Write-Host -ForegroundColor Red "Please provide a value for $param."
        }
        exit 1
    }
    Write-Host -ForegroundColor Cyan "`n All parameters are valid."
    return
}
