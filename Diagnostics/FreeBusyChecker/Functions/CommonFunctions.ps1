# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
function Test-ExchangeOnlineConnection {
    Write-Host -ForegroundColor Green " Checking Exchange Online Configuration"
    Write-Host " Testing Connection to Exchange Online with EO Prefix."
    try {
        $CheckExoMailbox = Get-EOMailbox $Script:UserOnline -ErrorAction Stop
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
        $Script:AutoDiscoveryVirtualDirectory = Get-AutoDiscoverVirtualDirectory -Server $Script:Server | Select-Object Identity, Name, ExchangeVersion, *authentication* -ErrorAction SilentlyContinue
        $Script:AutoDiscoveryVirtualDirectoryOAuth = $Script:AutoDiscoveryVirtualDirectory
    }
}
function FetchEWSInformation {
    if (-not $Script:WebServicesVirtualDirectory -or -not $Script:WebServicesVirtualDirectoryOAuth) {
        $Script:WebServicesVirtualDirectory = Get-WebServicesVirtualDirectory -Server $Script:Server | Select-Object Identity, Name, ExchangeVersion, *Authentication*, *url -ErrorAction SilentlyContinue
        $Script:WebServicesVirtualDirectoryOAuth = $Script:WebServicesVirtualDirectory
        $Script:ExchangeOnPremEWS = ($Script:WebServicesVirtualDirectory.externalURL.AbsoluteUri)
    }
}
function CheckIfExchangeServer {
    $exchangeShell = Confirm-ExchangeShell
    if (-not($exchangeShell.ShellLoaded)) {
        Write-Host "$Server is not an Exchange Server. This script should be run in Exchange Server Management Shell"
        exit
    }
}
function CheckParameters {
    $MissingParameters = @()
    if ([string]::IsNullOrWhiteSpace($Script:ExchangeOnlineDomain)) {
        $MissingParameters += "Exchange Online Domain. Example: contoso.mail.onmicrosoft.com"
    }
    if ([string]::IsNullOrWhiteSpace($Script:ExchangeOnPremLocalDomain)) {
        $MissingParameters += "Exchange On Premises Local Domain.  Example: . 'C:\scripts\FreeBusyChecker\FreeBusyChecker.ps1' -OnPremisesUser John@Contoso.com"
    }
    if ([string]::IsNullOrWhiteSpace($exchangeOnPremDomain)) {
        $MissingParameters += "Exchange On Premises Domain.  Example: -OnPremLocalDomain Contoso.local"
    }
    if ([string]::IsNullOrWhiteSpace($exchangeOnPremEWS)) {
        $MissingParameters += "Exchange On Premises EWS Virtual Directory External URL.  Example:  'C:\FreeBusyChecker.ps1' -OnPremEWSUrl https://mail.contoso.com/EWS/Exchange.asmx"
    }
    if ([string]::IsNullOrWhiteSpace($Script:UserOnPrem)) {
        $MissingParameters += "On Premises User Mailbox.  Example: 'C:\FreeBusyChecker.ps1' -OnPremisesUser John@Contoso.com"
    }
    if ([string]::IsNullOrWhiteSpace($Script:UserOnline)) {
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
