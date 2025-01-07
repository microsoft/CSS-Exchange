# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function EXOIntraOrgConCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConnector | Select TarGetAddressDomains,DiscoveryEndpoint,Enabled"
    PrintDynamicWidthLine
    $Script:ExoIntraOrgCon = Get-EOIntraOrganizationConnector | Select-Object TarGetAddressDomains, DiscoveryEndpoint, Enabled
    $IOC = $Script:ExoIntraOrgCon | Format-List
    $IOC
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Online Intra Organization Connector"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " TarGet Address Domains: "
    if ($Script:ExoIntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $Script:ExoIntraOrgCon.TarGetAddressDomains
        $Script:tdExoIntraOrgConTarGetAddressDomains = $Script:ExoIntraOrgCon.TarGetAddressDomains
        $Script:tdExoIntraOrgConTarGetAddressDomainsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TarGet Address Domains is NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $Script:tdExoIntraOrgConTarGetAddressDomains = " $($Script:ExoIntraOrgCon.TarGetAddressDomains) . Should contain the $ExchangeOnpremDomain"
        $Script:tdExoIntraOrgConTarGetAddressDomainsColor = "red"
    }
    Write-Host -ForegroundColor White " DiscoveryEndpoint: "
    if ($Script:ExoIntraOrgCon.DiscoveryEndpoint -like $Script:EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint) {
        Write-Host -ForegroundColor Green $Script:ExoIntraOrgCon.DiscoveryEndpoint
        $Script:tdExoIntraOrgConDiscoveryEndpoints = $Script:ExoIntraOrgCon.DiscoveryEndpoint
        $Script:tdExoIntraOrgConDiscoveryEndpointsColor = "green"
    } else {
        if ($Script:ExoIntraOrgCon.DiscoveryEndpoint -like "*resource.mailboxMigration.his.MSAppProxy.net*") {
            Write-Host -ForegroundColor Green " " $Script:ExoIntraOrgCon.DiscoveryEndpoint
            Write-Host -ForegroundColor Yellow " Discovery Endpoint includes resource.mailboxMigration.his.MSAppProxy.net. Hybrid configuration is implemented using Hybrid Agent "
            $Script:tdExoIntraOrgConDiscoveryEndpoints = $Script:ExoIntraOrgCon.DiscoveryEndpoint
            $Script:tdExoIntraOrgConDiscoveryEndpointsColor = "green"
        } else {
            Write-Host -ForegroundColor Red " DiscoveryEndpoint is NOT correct. "
            Write-Host -ForegroundColor White "  Should be " $Script:EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint
            $Script:tdExoIntraOrgConDiscoveryEndpoints = "$($Script:ExoIntraOrgCon.DiscoveryEndpoint) . Should be $($Script:EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint)"
            $Script:tdExoIntraOrgConDiscoveryEndpointsColor = "red"
        }
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($Script:ExoIntraOrgCon.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $Script:tdExoIntraOrgConEnabled = "True"
        $Script:tdExoIntraOrgConEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  False."
        Write-Host -ForegroundColor White " Should be True"
        $Script:tdExoIntraOrgConEnabled = "False . Should be True"
        $Script:tdExoIntraOrgConEnabledColor = "red"
    }
    EXOIntraOrgConCheckHtml
}
function EXOIntraOrgConfigCheck {
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses"
    PrintDynamicWidthLine
    $Script:ExoIntraOrgConfig = Get-EOOnPremisesOrganization | Select-Object OrganizationGuid | Get-EOIntraOrganizationConfiguration | Select-Object * | Where-Object { $_.OnPremiseTarGetAddresses -like "*$ExchangeOnPremDomain*" }
    $IOConfig = $Script:ExoIntraOrgConfig | Format-List
    $IOConfig
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Exchange Online Intra Organization Configuration"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " OnPremiseTarGetAddresses: "
    if ($Script:ExoIntraOrgConfig.OnPremiseTarGetAddresses -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $Script:ExoIntraOrgConfig.OnPremiseTarGetAddresses
        $Script:tdExoIntraOrgConfigOnPremiseTarGetAddresses = $Script:ExoIntraOrgConfig.OnPremiseTarGetAddresses
        $Script:tdExoIntraOrgConfigOnPremiseTarGetAddressesColor = "green"
    } else {
        Write-Host -ForegroundColor Red " OnPremise TarGet Addresses are NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $Script:tdExoIntraOrgConfigOnPremiseTarGetAddresses = $Script:ExoIntraOrgConfig.OnPremiseTarGetAddresses
        $Script:tdExoIntraOrgConfigOnPremiseTarGetAddressesColor = "red"
    }
    EXOIntraOrgConfigCheckHtml
}
function EXOAuthServerCheck {
    Write-Host -ForegroundColor Green " Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | select name,IssuerIdentifier,enabled"
    PrintDynamicWidthLine
    $exoAuthServer = Get-EOAuthServer -Identity 00000001-0000-0000-c000-000000000000 | Select-Object name, IssuerIdentifier, enabled
    $AuthServer = $exoAuthServer | Format-List
    $AuthServer
    $Script:tdExoAuthServerName = $exoAuthServer.Name
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Exchange Online Authorization Server"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " IssuerIdentifier: "
    if ($exoAuthServer.IssuerIdentifier -like "00000001-0000-0000-c000-000000000000") {
        Write-Host -ForegroundColor Green " " $exoAuthServer.IssuerIdentifier
        $Script:tdExoAuthServerIssuerIdentifier = $exoAuthServer.IssuerIdentifier
        $Script:tdExoAuthServerIssuerIdentifierColor = "green"
        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $Script:tdExoAuthServerEnabled = $exoAuthServer.Enabled
            $Script:tdExoAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $Script:tdExoAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $Script:tdExoAuthServerEnabledColor = "red"
        }
    } else {
        Write-Host -ForegroundColor Red " Authorization Server object is NOT correct."
        Write-Host -ForegroundColor White " Enabled: "
        $Script:tdExoAuthServerIssuerIdentifier = "$($exoAuthServer.IssuerIdentifier) - Authorization Server object should be 00000001-0000-0000-c000-000000000000"
        $Script:tdExoAuthServerIssuerIdentifierColor = "red"

        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $Script:tdExoAuthServerEnabled = $exoAuthServer.Enabled
            $Script:tdExoAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $Script:tdExoAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $Script:tdExoAuthServerEnabledColor = "red"
        }
    }
    EXOAuthServerCheckHtml
}
function ExoTestOAuthCheck {
    Write-Host -ForegroundColor Green " Test-OAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $Script:UserOnline "
    PrintDynamicWidthLine
    $ExoTestOAuth = Test-EOOAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $Script:UserOnline -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
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
