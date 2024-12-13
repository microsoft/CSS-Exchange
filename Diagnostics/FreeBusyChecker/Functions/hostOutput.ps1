# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
function PrintDynamicWidthLine {
    $screenWidth = $host.UI.RawUI.WindowSize.Width
    if ($screenWidth -gt 180) {
        $length = [math]::floor($screenWidth / 1.65)
    } else {
        $length = [math]::floor($screenWidth - 5)
    }
    $line = "=" * $length
    Write-Host $line
}
function ShowHelp() {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Yellow "`n  Valid Input Option Parameters!"
    Write-Host -ForegroundColor White "`n  Parameter: Auth"
    Write-Host -ForegroundColor White "   Options  : DAuth; OAUth"
    Write-Host  "    DAuth             : DAuth Authentication"
    Write-Host  "    OAuth             : OAuth Authentication"
    Write-Host  "    Default Value     : No switch input means the script will collect both DAuth and OAuth Availability configuration detail"
    Write-Host -ForegroundColor White "`n  Parameter: Org"
    Write-Host -ForegroundColor White "   Options  : ExchangeOnPremise; Exchange Online"
    Write-Host  "    ExchangeOnPremise : Use ExchangeOnPremise parameter to collect Availability information in the Exchange On Premise Tenant"
    Write-Host  "    ExchangeOnline    : Use Exchange Online parameter to collect Availability information in the Exchange Online Tenant"
    Write-Host  "    Default Value     : No switch input means the script will collect both Exchange On Premise and Exchange Online Availability configuration detail"
    Write-Host -ForegroundColor White "`n  Parameter: Pause"
    Write-Host  "                 : Use the Pause parameter to use this script pausing after each test done."
    Write-Host -ForegroundColor White "`n  Parameter: Help"
    Write-Host  "                 : Use the Help parameter to use display valid parameter Options. `n`n"
}

function loadingParameters() {
    $Script:LogFile = "$PSScriptRoot\FreeBusyChecker.txt"
    $BuildVersion = ""
    $LogFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile) + "_" + $Script:startingDate + ([System.IO.Path]::GetExtension($Script:LogFile))
    Start-Transcript -Path $LogFileName -Append
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " `n  Free Busy Configuration Information Checker `n "
    Write-Host -ForegroundColor White $BuildVersion
    Write-Host -ForegroundColor Green "  Loading Parameters..... `n "
}
function ShowParameters() {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green "  Loading modules for AD, Exchange"
    PrintDynamicWidthLine
    Write-Host   "  Color Scheme"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Red "  Look out for Red!"
    Write-Host -ForegroundColor Yellow "  Yellow - Example information or Links"
    Write-Host -ForegroundColor Green "  Green - In Summary Sections it means OK. Anywhere else it's just a visual aid."
    PrintDynamicWidthLine
    Write-Host   "  Parameters:"
    PrintDynamicWidthLine
    Write-Host  -ForegroundColor White " Log File Path:"
    Write-Host -ForegroundColor Green "  $Script:LogFile"
    Write-Host  -ForegroundColor White " Office 365 Domain:"
    Write-Host -ForegroundColor Green "  $Script:ExchangeOnlineDomain"
    Write-Host  -ForegroundColor White " AD root Domain"
    Write-Host -ForegroundColor Green "  $Script:ExchangeOnPremLocalDomain"
    Write-Host -ForegroundColor White " Exchange On Premises Domain:  "
    Write-Host -ForegroundColor Green "  $exchangeOnPremDomain"
    Write-Host -ForegroundColor White " Exchange On Premises External EWS url:"
    Write-Host -ForegroundColor Green "  $exchangeOnPremEWS"
    Write-Host -ForegroundColor White " On Premises Hybrid Mailbox:"
    Write-Host -ForegroundColor Green "  $Script:UserOnPrem"
    Write-Host -ForegroundColor White " Exchange Online Mailbox:"
    Write-Host -ForegroundColor Green "  $Script:UserOnline"
    showParametersHtml
}
function hostOutputIntraOrgConEnabled($Auth) {
    PrintDynamicWidthLine
    if ($Auth -Like "DAuth") {
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled True -> Running for DAuth only as -Auth DAuth option was selected`n  "
        if ($Script:OrgRel.enabled -Like "True") {
            Write-Host -ForegroundColor White "           Organization Relationship Enabled True `n  "
        }
        Write-Host -ForegroundColor White "      This script can be Run using the -Auth All parameter to Check for both OAuth and DAuth configuration. `n `n         Example: ./FreeBusyChecker.ps1 -Auth All"
        lookupMethodDAuthHtml
    }
    if ($Auth -Like "") {
        $Auth = "OAuth"
        Write-Host -ForegroundColor White "    -> Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled"
        Write-Host -ForegroundColor White "    -> Running for OAuth only as OAuth takes precedence over DAuth;"
        Write-Host -ForegroundColor White "`n         This script can be Run using the -Auth All parameter to Check for both OAuth and DAuth configuration. `n `n         Example: ./FreeBusyChecker.ps1 -Auth All"
        Write-Host -ForegroundColor White "`n         This script can be Run using the -Auth DAuth parameter to Check for DAuth configuration only. `n `n         Example: ./FreeBusyChecker.ps1 -Auth DAuth"
        lookupMethodDAuthHtml
    }
    if ($Auth -Like "All") {
        lookupMethodCheckAllHtml
    }
    return $Auth
}
function hostOutputIntraOrgConNotEnabled() {
    if ($Auth -like "" -or $Auth -like "DAuth") {
        PrintDynamicWidthLine
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled False -> Running for DAuth only as OAuth is not enabled"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth OAuth' parameter to Check for OAuth configurations only. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth OAuth"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth All' parameter to Check for both OAuth and DAuth configuration. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth All"
        lookupMethodDAuthOauthDisabledHtml
    }
    if ($Auth -like "OAuth") {
        PrintDynamicWidthLine
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled False -> Running for OAuth only as -Auth OAuth parameter was selected"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth All' parameter to Check for both OAuth and DAuth configuration. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth All"
        lookupMethodOauthOauthDisabledHtml
    }
    if ($Auth -like "All") {
        PrintDynamicWidthLine
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled False -> Running both for OAuth and DAuth as -Auth All parameter was selected"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth OAuth' parameter to Check for OAuth configuration only. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth OAuth"
        lookupMethodAllOauthDisabledHtml
    }
}
