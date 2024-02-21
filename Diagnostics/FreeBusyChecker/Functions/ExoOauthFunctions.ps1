# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are being used in functions')]
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [String] $tdEXOIntraOrgConTarGetAddressDomains
)
function EXOIntraOrgConCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConnector | Select TarGetAddressDomains,DiscoveryEndpoint,Enabled"
    PrintDynamicWidthLine
    $exoIntraOrgCon = Get-IntraOrganizationConnector | Select-Object TarGetAddressDomains, DiscoveryEndpoint, Enabled
    $IOC = $exoIntraOrgCon | Format-List
    $IOC
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Online Intra Organization Connector"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " TarGet Address Domains: "
    if ($exoIntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $exoIntraOrgCon.TarGetAddressDomains
        $tdEXOIntraOrgConTarGetAddressDomains = $exoIntraOrgCon.TarGetAddressDomains
        $tdEXOIntraOrgConTarGetAddressDomainsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TarGet Address Domains is NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $tdEXOIntraOrgConTarGetAddressDomains = " $($exoIntraOrgCon.TarGetAddressDomains) . Should contain the $ExchangeOnpremDomain"
        $tdEXOIntraOrgConTarGetAddressDomainsColor = "red"
    }
    Write-Host -ForegroundColor White " DiscoveryEndpoint: "
    if ($exoIntraOrgCon.DiscoveryEndpoint -like $EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint) {
        Write-Host -ForegroundColor Green $exoIntraOrgCon.DiscoveryEndpoint
        $tdEXOIntraOrgConDiscoveryEndpoints = $exoIntraOrgCon.DiscoveryEndpoint
        $tdEXOIntraOrgConDiscoveryEndpointsColor = "green"
    } else {
        if ($exoIntraOrgCon.DiscoveryEndpoint -like "*resource.mailboxMigration.his.MSAppProxy.net*") {
            Write-Host -ForegroundColor Green " " $exoIntraOrgCon.DiscoveryEndpoint
            Write-Host -ForegroundColor Yellow " Discovery Endpoint includes resource.mailboxMigration.his.MSAppProxy.net. Hybrid configuration is implemented using Hybrid Agent "
            $tdEXOIntraOrgConDiscoveryEndpoints = $exoIntraOrgCon.DiscoveryEndpoint
            $tdEXOIntraOrgConDiscoveryEndpointsColor = "green"
        } else {
            Write-Host -ForegroundColor Red " DiscoveryEndpoint is NOT correct. "
            Write-Host -ForegroundColor White "  Should be " $EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint
            $tdEXOIntraOrgConDiscoveryEndpoints = "$($exoIntraOrgCon.DiscoveryEndpoint) . Should be $($EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint)"
            $tdEXOIntraOrgConDiscoveryEndpointsColor = "red"
        }
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($exoIntraOrgCon.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $tdEXOIntraOrgConEnabled = "True"
        $tdEXOIntraOrgConEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  False."
        Write-Host -ForegroundColor White " Should be True"
        $tdEXOIntraOrgConEnabled = "False . Should be True"
        $tdEXOIntraOrgConEnabledColor = "red"
    }
    EXOIntraOrgConCheckHtml
}
function EXOIntraOrgConfigCheck {
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses"
    PrintDynamicWidthLine
    #fix because there can be multiple on prem or guid's
    #$exoIntraOrgConfig = Get-OnPremisesOrganization | select OrganizationGuid | Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses
    $exoIntraOrgConfig = Get-OnPremisesOrganization | Select-Object OrganizationGuid | Get-IntraOrganizationConfiguration | Select-Object * | Where-Object { $_.OnPremiseTarGetAddresses -like "*$ExchangeOnPremDomain*" }
    #$IntraOrgConCheck
    $IOConfig = $exoIntraOrgConfig | Format-List
    $IOConfig
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Exchange Online Intra Organization Configuration"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " OnPremiseTarGetAddresses: "
    if ($exoIntraOrgConfig.OnPremiseTarGetAddresses -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $tdEXOIntraOrgConfigOnPremiseTarGetAddresses = $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor = "green"
    } else {
        Write-Host -ForegroundColor Red " OnPremise TarGet Addresses are NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $tdEXOIntraOrgConfigOnPremiseTarGetAddresses = $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor = "red"
    }
    EXOIntraOrgConfigCheckHtml
}
function EXOAuthServerCheck {
    Write-Host -ForegroundColor Green " Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | select name,IssuerIdentifier,enabled"
    PrintDynamicWidthLine
    $exoAuthServer = Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | Select-Object name, IssuerIdentifier, enabled
    #$IntraOrgConCheck
    $AuthServer = $exoAuthServer | Format-List
    $AuthServer
    $tdEXOAuthServerName = $exoAuthServer.Name
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Exchange Online Authorization Server"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " IssuerIdentifier: "
    if ($exoAuthServer.IssuerIdentifier -like "00000001-0000-0000-c000-000000000000") {
        Write-Host -ForegroundColor Green " " $exoAuthServer.IssuerIdentifier
        $tdEXOAuthServerIssuerIdentifier = $exoAuthServer.IssuerIdentifier
        $tdEXOAuthServerIssuerIdentifierColor = "green"
        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $tdEXOAuthServerEnabled = $exoAuthServer.Enabled
            $tdEXOAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $tdEXOAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $tdEXOAuthServerEnabledColor = "red"
        }
    } else {
        Write-Host -ForegroundColor Red " Authorization Server object is NOT correct."
        Write-Host -ForegroundColor White " Enabled: "
        $tdEXOAuthServerIssuerIdentifier = "$($exoAuthServer.IssuerIdentifier) - Authorization Server object should be 00000001-0000-0000-c000-000000000000"
        $tdEXOAuthServerIssuerIdentifierColor = "red"

        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $tdEXOAuthServerEnabled = $exoAuthServer.Enabled
            $tdEXOAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $tdEXOAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $tdEXOAuthServerEnabledColor = "red"
        }
    }
    EXOAuthServerCheckHtml
}
function ExoTestOAuthCheck {
    Write-Host -ForegroundColor Green " Test-OAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $UserOnline "
    PrintDynamicWidthLine
    $ExoTestOAuth = Test-OAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $UserOnline
    if ($ExoTestOAuth.ResultType.Value -like 'Success' ) {
        $tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType.Value) - OAuth Test was completed successfully"
        $tdOAuthConnectivityResultTypeColor = "green"
    } else {
        $ExoTestOAuth | Format-List
        $tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType) - OAuth Test was completed with Error. Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS target URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $tdOAuthConnectivityResultTypeColor = "red"
    }

    if ($ExoTestOAuth.Detail.FullId -like '*(401) Unauthorized*') {
        Write-Host -ForegroundColor Red "The remote Server returned an error: (401) Unauthorized"
    }

    if ($ExoTestOAuth.Detail.FullId -like '*The user specified by the user-context in the token does not exist*') {
        Write-Host -ForegroundColor Yellow "The user specified by the user-context in the token does not exist"
        Write-Host "Please run Test-OAuthConnectivity with a different Exchange Online Mailbox"
    }

    if ($ExoTestOAuth.Detail.FullId -like '*error_category="invalid_token"*') {
        Write-Host -ForegroundColor Yellow "This token profile 'S2SAppActAs' is not applicable for the current protocol"
    }
    Write-Host -ForegroundColor Green " Summary - Test-OAuthConnectivity"
    PrintDynamicWidthLine
    if ($ExoTestOAuth.ResultType.value -like "Success") {
        Write-Host -ForegroundColor Green " OAuth Test was completed successfully "
        $tdOAuthConnectivityResultType = "  OAuth Test was completed successfully"
        $tdOAuthConnectivityResultTypeColor = "green"
    } else {
        Write-Host -ForegroundColor Red " OAuth Test was completed with Error. "
        Write-Host -ForegroundColor White " Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS tarGet URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType) - OAuth Test was completed with Error. Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS tarGet URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $tdOAuthConnectivityResultTypeColor = "red"
    }
    Write-Host -ForegroundColor Green "`n References: "
    Write-Host -ForegroundColor White " Configure OAuth authentication between Exchange and Exchange Online organizations"
    Write-Host -ForegroundColor Yellow " https://technet.microsoft.com/en-us/library/dn594521(v=exchg.150).aspx"
    ExoTestOAuthCheckHtml
}
