# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function EXOIntraOrgConCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConnector | Select TarGetAddressDomains,DiscoveryEndpoint,Enabled"
    PrintDynamicWidthLine
    $exoIntraOrgCon = Get-EOIntraOrganizationConnector | Select-Object TarGetAddressDomains, DiscoveryEndpoint, Enabled
    $IOC = $exoIntraOrgCon | Format-List
    $IOC
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Online Intra Organization Connector"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " TarGet Address Domains: "
    if ($exoIntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $exoIntraOrgCon.TarGetAddressDomains
        $Script:tdEXOIntraOrgConTarGetAddressDomains = $exoIntraOrgCon.TarGetAddressDomains
        $Script:tdEXOIntraOrgConTarGetAddressDomainsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TarGet Address Domains is NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $Script:tdEXOIntraOrgConTarGetAddressDomains = " $($exoIntraOrgCon.TarGetAddressDomains) . Should contain the $ExchangeOnpremDomain"
        $Script:tdEXOIntraOrgConTarGetAddressDomainsColor = "red"
    }
    Write-Host -ForegroundColor White " DiscoveryEndpoint: "
    if ($exoIntraOrgCon.DiscoveryEndpoint -like $EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint) {
        Write-Host -ForegroundColor Green $exoIntraOrgCon.DiscoveryEndpoint
        $Script:tdEXOIntraOrgConDiscoveryEndpoints = $exoIntraOrgCon.DiscoveryEndpoint
        $Script:tdEXOIntraOrgConDiscoveryEndpointsColor = "green"
    } else {
        if ($exoIntraOrgCon.DiscoveryEndpoint -like "*resource.mailboxMigration.his.MSAppProxy.net*") {
            Write-Host -ForegroundColor Green " " $exoIntraOrgCon.DiscoveryEndpoint
            Write-Host -ForegroundColor Yellow " Discovery Endpoint includes resource.mailboxMigration.his.MSAppProxy.net. Hybrid configuration is implemented using Hybrid Agent "
            $Script:tdEXOIntraOrgConDiscoveryEndpoints = $exoIntraOrgCon.DiscoveryEndpoint
            $Script:tdEXOIntraOrgConDiscoveryEndpointsColor = "green"
        } else {
            Write-Host -ForegroundColor Red " DiscoveryEndpoint is NOT correct. "
            Write-Host -ForegroundColor White "  Should be " $EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint
            $Script:tdEXOIntraOrgConDiscoveryEndpoints = "$($exoIntraOrgCon.DiscoveryEndpoint) . Should be $($EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint)"
            $Script:tdEXOIntraOrgConDiscoveryEndpointsColor = "red"
        }
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($exoIntraOrgCon.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $Script:tdEXOIntraOrgConEnabled = "True"
        $Script:tdEXOIntraOrgConEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  False."
        Write-Host -ForegroundColor White " Should be True"
        $Script:tdEXOIntraOrgConEnabled = "False . Should be True"
        $Script:tdEXOIntraOrgConEnabledColor = "red"
    }
    EXOIntraOrgConCheckHtml
}
function EXOIntraOrgConfigCheck {
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses"
    PrintDynamicWidthLine
    $exoIntraOrgConfig = Get-EOOnPremisesOrganization | Select-Object OrganizationGuid | Get-EOIntraOrganizationConfiguration | Select-Object * | Where-Object { $_.OnPremiseTarGetAddresses -like "*$ExchangeOnPremDomain*" }
    $IOConfig = $exoIntraOrgConfig | Format-List
    $IOConfig
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Exchange Online Intra Organization Configuration"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " OnPremiseTarGetAddresses: "
    if ($exoIntraOrgConfig.OnPremiseTarGetAddresses -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $Script:tdEXOIntraOrgConfigOnPremiseTarGetAddresses = $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $Script:tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor = "green"
    } else {
        Write-Host -ForegroundColor Red " OnPremise TarGet Addresses are NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $Script:tdEXOIntraOrgConfigOnPremiseTarGetAddresses = $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $Script:tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor = "red"
    }
    EXOIntraOrgConfigCheckHtml
}
function EXOAuthServerCheck {
    Write-Host -ForegroundColor Green " Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | select name,IssuerIdentifier,enabled"
    PrintDynamicWidthLine
    $exoAuthServer = Get-EOAuthServer -Identity 00000001-0000-0000-c000-000000000000 | Select-Object name, IssuerIdentifier, enabled
    $AuthServer = $exoAuthServer | Format-List
    $AuthServer
    $Script:tdEXOAuthServerName = $exoAuthServer.Name
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Exchange Online Authorization Server"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " IssuerIdentifier: "
    if ($exoAuthServer.IssuerIdentifier -like "00000001-0000-0000-c000-000000000000") {
        Write-Host -ForegroundColor Green " " $exoAuthServer.IssuerIdentifier
        $Script:tdEXOAuthServerIssuerIdentifier = $exoAuthServer.IssuerIdentifier
        $Script:tdEXOAuthServerIssuerIdentifierColor = "green"
        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $Script:tdEXOAuthServerEnabled = $exoAuthServer.Enabled
            $Script:tdEXOAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $Script:tdEXOAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $Script:tdEXOAuthServerEnabledColor = "red"
        }
    } else {
        Write-Host -ForegroundColor Red " Authorization Server object is NOT correct."
        Write-Host -ForegroundColor White " Enabled: "
        $Script:tdEXOAuthServerIssuerIdentifier = "$($exoAuthServer.IssuerIdentifier) - Authorization Server object should be 00000001-0000-0000-c000-000000000000"
        $Script:tdEXOAuthServerIssuerIdentifierColor = "red"

        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $Script:tdEXOAuthServerEnabled = $exoAuthServer.Enabled
            $Script:tdEXOAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $Script:tdEXOAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $Script:tdEXOAuthServerEnabledColor = "red"
        }
    }
    EXOAuthServerCheckHtml
}
function ExoTestOAuthCheck {
    Write-Host -ForegroundColor Green " Test-OAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $UserOnline "
    PrintDynamicWidthLine
    $ExoTestOAuth = Test-EOOAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $UserOnline -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($ExoTestOAuth.ResultType.Value -like 'Success' ) {
        $Script:tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType.Value) - OAuth Test was completed successfully"
        $Script:tdOAuthConnectivityResultTypeColor = "green"
    } else {
        $ExoTestOAuth | Format-List
        $Script:tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType) - OAuth Test was completed with Error. Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS target URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $Script:tdOAuthConnectivityResultTypeColor = "red"
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
        $Script:tdOAuthConnectivityResultType = "  OAuth Test was completed successfully"
        $Script:tdOAuthConnectivityResultTypeColor = "green"
    } else {
        Write-Host -ForegroundColor Red " OAuth Test was completed with Error. "
        Write-Host -ForegroundColor White " Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS tarGet URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $Script:tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType) - OAuth Test was completed with Error. Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS tarGet URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $Script:tdOAuthConnectivityResultTypeColor = "red"
    }
    Write-Host -ForegroundColor Green "`n References: "
    Write-Host -ForegroundColor White " Configure OAuth authentication between Exchange and Exchange Online organizations"
    Write-Host -ForegroundColor Yellow " https://technet.microsoft.com/en-us/library/dn594521(v=exchg.150).aspx"
    ExoTestOAuthCheckHtml
}
