# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
function OrgRelCheck($OrgRelParameter) {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-OrganizationRelationship  | Where{($_.DomainNames -like $ExchangeOnlineDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled, ArchiveAccessEnabled"
    PrintDynamicWidthLine
    $OrgRelParameter
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Get-OrganizationRelationship"
    PrintDynamicWidthLine
    $settingsList = New-Object System.Collections.ArrayList
    function AddSettingToList($list, $name, $value, $color) {
        $list.Add([PSCustomObject]@{
                Name  = $name
                Value = $value
                Color = $color
            }) | Out-Null
    }
    # Domain Names
    if ($OrgRelParameter.DomainNames -like $ExchangeOnlineDomain) {
        AddSettingToList -list $settingsList -name "Domain Names" -value "Domain Names include the $ExchangeOnlineDomain Domain" -color "green"
    } else {
        AddSettingToList -list $settingsList -name "Domain Names" -value "Domain Names do Not Include the $ExchangeOnlineDomain Domain" -color "red"
    }
    # FreeBusyAccessEnabled
    if ($OrgRelParameter.FreeBusyAccessEnabled -like "True") {
        AddSettingToList -list $settingsList -name "FreeBusyAccessEnabled" -value "FreeBusyAccessEnabled is set to True" -color "green"
    } else {
        AddSettingToList -list $settingsList -name "FreeBusyAccessEnabled" -value "FreeBusyAccessEnabled is set to False" -color "red"
        $countOrgRelIssues++
    }
    # TarGetOwAUrl
    $standardValues = @("http://outlook.com/owa/$($ExchangeOnlineDomain).", "https://outlook.office.com/mail.")
    if ([string]::IsNullOrWhiteSpace($OrgRelParameter.TarGetOwAUrl)) {
        AddSettingToList -list $settingsList -name "TarGetOwAUrl" -value "TarGetOwAUrl Is Blank. Can also be configured to be $($standardValues[0]) or $($standardValues[1])" -color "green"
    } elseif ($OrgRelParameter.TarGetOwAUrl -in $standardValues) {
        AddSettingToList -list $settingsList -name "TarGetOwAUrl" -value "TarGetOwAUrl Is $($OrgRelParameter.TarGetOwAUrl). This is a possible standard value." -color "green"
    } else {
        $countOrgRelIssues++
    }
    # TarGetSharingEpr
    if ([string]::IsNullOrWhitespace($OrgRelParameter.TarGetSharingEpr) -or $OrgRelParameter.TarGetSharingEpr -eq "https://outlook.office365.com/EWS/Exchange.asmx") {
        AddSettingToList -list $settingsList -name "TarGetSharingEpr" -value "TarGetSharingEpr Is ideally blank. If set, should be Office 365 EWS endpoint. Example: https://outlook.office365.com/EWS/Exchange.asmx" -color "green"
    } else {
        AddSettingToList -list $settingsList -name "TarGetSharingEpr" -value "TarGetSharingEpr Should be blank or https://outlook.office365.com/EWS/Exchange.asmx. If set, should be Office 365 EWS endpoint." -color "red"
        $countOrgRelIssues++
    }
    # FreeBusyAccessScope
    if ([string]::IsNullOrWhitespace($OrgRelParameter.FreeBusyAccessScope)) {
        AddSettingToList -list $settingsList -name "FreeBusyAccessScope" -value "FreeBusyAccessScope Is blank, this is the standard Value." -color "green"
    } else {
        AddSettingToList -list $settingsList -name "FreeBusyAccessScope" -value "FreeBusyAccessScope Should be Blank, that is the standard Value." -color "red"
        $countOrgRelIssues++
    }
    # TarGetAutoDiscoverEpr
    $OrgRelTarGetAutoDiscoverEpr = $OrgRelParameter.TarGetAutoDiscoverEpr
    if ([string]::IsNullOrWhitespace($OrgRelTarGetAutoDiscoverEpr)) {
        $OrgRelTarGetAutoDiscoverEpr = "Blank"
    }
    if ($OrgRelParameter.TarGetAutoDiscoverEpr -like "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity") {
        AddSettingToList -list $settingsList -name "TarGetAutoDiscoverEpr" -value "TarGetAutoDiscoverEpr Is correct" -color "green"
    } else {
        AddSettingToList -list $settingsList -name "TarGetAutoDiscoverEpr" -value "TarGetAutoDiscoverEpr Is not correct. Should be https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity" -color "red"
        $countOrgRelIssues++
    }
    # Enabled
    if ($OrgRelParameter.enabled -like "True") {
        AddSettingToList -list $settingsList -name "Enabled" -value "Enabled is set to True" -color "green"
    } else {
        AddSettingToList -list $settingsList -name "Enabled" -value "Enabled is set to False. This may be intentional if Hybrid Free Busy lookups are done with OAuth and Intra Organization Connector." -color "yellow"
        $countOrgRelIssues++
    }
    # Display the settings list
    if ($countOrgRelIssues -eq '0') {
        Write-Host -ForegroundColor Green " Configurations Seem Correct"
    } else {
        Write-Host -ForegroundColor Red "  Configurations may not be Correct"
    }
    foreach ($setting in $settingsList) {
        Write-Host -ForegroundColor White " $($setting.Name):"
        Write-Host -ForegroundColor $setting.Color " $($setting.Value)"
    }
    $OrgRelDomainNames = ""
    foreach ($domain in $OrgRelParameter.DomainNames.Domain) {
        if ($OrgRelDomainNames -ne "") {
            $OrgRelDomainNames += "; "
        }
        $OrgRelDomainNames += $domain
    }
    orgRelHtml
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/exchange/create-an-organization-relationship-exchange-2013-help"
}
function FedInfoCheck {
    Write-Host -ForegroundColor Green " Get-FederationInformation -DomainName $ExchangeOnlineDomain  -BypassAdditionalDomainValidation | fl"
    PrintDynamicWidthLine
    $FedInfo = Get-federationInformation -DomainName $ExchangeOnlineDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue | Select-Object *
    if (!$FedInfo) {
        $FedInfo = Get-federationInformation -DomainName $ExchangeOnlineDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue | Select-Object *
    }
    $FedInfo
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Federation Information"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White   "  Domain Names: "
    if ($FedInfo.DomainNames -like "*$ExchangeOnlineDomain*") {
        Write-Host -ForegroundColor Green "   Domain Names include the Exchange Online Domain "$ExchangeOnlineDomain
        $Script:tdDomainNamesColor = "green"
        $Script:tdDomainNamesFL = "Domain Names include the Exchange Online Domain $ExchangeOnlineDomain"
    } else {
        Write-Host -ForegroundColor Red "   Domain Names seem not to include the Exchange Online Domain "$ExchangeOnlineDomain
        Write-Host  "   Domain Names: "$FedInfo.DomainNames
        $Script:tdDomainNamesColor = "Red"
        $Script:tdDomainNamesFL = "Domain Names seem not to include the Exchange Online Domain: $ExchangeOnlineDomain"
    }
    Write-Host  -ForegroundColor White  "  TokenIssuerUris: "
    if ($FedInfo.TokenIssuerUris -like "*urn:federation:MicrosoftOnline*") {
        Write-Host -ForegroundColor Green "  "  $FedInfo.TokenIssuerUris
        $Script:tdTokenIssuerUrisColor = "green"
        $Script:tdTokenIssuerUrisFL = $FedInfo.TokenIssuerUris
    } else {
        Write-Host "   " $FedInfo.TokenIssuerUris
        Write-Host  -ForegroundColor Red "   TokenIssuerUris should be urn:federation:MicrosoftOnline"
        $Script:tdTokenIssuerUrisColor = "red"
        $Script:tdTokenIssuerUrisFL = "   TokenIssuerUris should be urn:federation:MicrosoftOnline"
    }
    Write-Host -ForegroundColor White   "  TarGetApplicationUri:"
    if ($FedInfo.TarGetApplicationUri -like "Outlook.com") {
        Write-Host -ForegroundColor Green "  "$FedInfo.TarGetApplicationUri
        $Script:tdTarGetApplicationUriColor = "green"
        $Script:tdTarGetApplicationUriFL = $FedInfo.TarGetApplicationUri
    } else {
        Write-Host -ForegroundColor Red "   "$FedInfo.TarGetApplicationUri
        Write-Host -ForegroundColor Red   "   TarGetApplicationUri should be Outlook.com"
        $Script:tdTarGetApplicationUriColor = "red"
        $Script:tdTarGetApplicationUriFL = "   TarGetApplicationUri should be Outlook.com"
    }
    Write-Host -ForegroundColor White   "  TarGetAutoDiscoverEpr:"
    if ($FedInfo.TarGetAutoDiscoverEpr -like "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity") {
        Write-Host -ForegroundColor Green "   "$FedInfo.TarGetAutoDiscoverEpr
        $Script:tdTarGetAutoDiscoverEprColor = "green"
        $Script:tdTarGetAutoDiscoverEprFL = $FedInfo.TarGetAutoDiscoverEpr
    } else {
        Write-Host -ForegroundColor Red "   "$FedInfo.TarGetAutoDiscoverEpr
        Write-Host -ForegroundColor Red   " TarGetAutoDiscoverEpr should be https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
        $Script:tdTarGetAutoDiscoverEprColor = "red"
        $Script:tdTarGetAutoDiscoverEprFL = "   TarGetAutoDiscoverEpr should be https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
    }
    Write-Host -ForegroundColor White "  Federation Information TarGetApplicationUri vs Organization Relationship TarGetApplicationUri "
    if ($FedInfo.TarGetApplicationUri -like "Outlook.com") {
        if ($OrgRel.TarGetApplicationUri -like $FedInfo.TarGetApplicationUri) {
            Write-Host -ForegroundColor Green "   => Federation Information TarGetApplicationUri matches the Organization Relationship TarGetApplicationUri "
            Write-Host  "       Organization Relationship TarGetApplicationUri:"  $OrgRel.TarGetApplicationUri
            Write-Host  "       Federation Information TarGetApplicationUri:   "  $FedInfo.TarGetApplicationUri
            $Script:tdFederationInformationTAColor = "green"
            $Script:tdFederationInformationTA_FL = " => Federation Information TarGetApplicationUri matches the Organization Relationship TarGetApplicationUri"
        } else {
            Write-Host -ForegroundColor Red "   => Federation Information TarGetApplicationUri should be Outlook.com and match the Organization Relationship TarGetApplicationUri "
            Write-Host  "       Organization Relationship TarGetApplicationUri:"  $OrgRel.TarGetApplicationUri
            Write-Host  "       Federation Information TarGetApplicationUri:   "  $FedInfo.TarGetApplicationUri
            $Script:tdFederationInformationTAColor = "red"
            $Script:tdFederationInformationTA_FL = " => Federation Information TarGetApplicationUri should be Outlook.com and match the Organization Relationship TarGetApplicationUri"
        }
    }
    Write-Host -ForegroundColor White  "  Federation Information TarGetAutoDiscoverEpr vs Organization Relationship TarGetAutoDiscoverEpr "
    if ($OrgRel.TarGetAutoDiscoverEpr -like $FedInfo.TarGetAutoDiscoverEpr) {
        Write-Host -ForegroundColor Green "   => Federation Information TarGetAutoDiscoverEpr matches the Organization Relationship TarGetAutoDiscoverEpr "
        Write-Host  "       Organization Relationship TarGetAutoDiscoverEpr:"  $OrgRel.TarGetAutoDiscoverEpr
        Write-Host  "       Federation Information TarGetAutoDiscoverEpr:   "  $FedInfo.TarGetAutoDiscoverEpr
        $Script:tdTarGetAutoDiscoverEprVSColor = "green"
        $Script:tdTarGetAutoDiscoverEprVS_FL = "=> Federation Information TarGetAutoDiscoverEpr matches the Organization Relationship TarGetAutoDiscoverEpr"
    } else {
        Write-Host -ForegroundColor Red "   => Federation Information TarGetAutoDiscoverEpr should match the Organization Relationship TarGetAutoDiscoverEpr"
        Write-Host  "       Organization Relationship TarGetAutoDiscoverEpr:"  $OrgRel.TarGetAutoDiscoverEpr
        Write-Host  "       Federation Information TarGetAutoDiscoverEpr:   "  $FedInfo.TarGetAutoDiscoverEpr
        $Script:tdTarGetAutoDiscoverEprVSColor = "red"
        $Script:tdTarGetAutoDiscoverEprVS_FL = "=> Federation Information TarGetAutoDiscoverEpr should match the Organization Relationship TarGetAutoDiscoverEpr"
    }
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/exchange/configure-a-federation-trust-exchange-2013-help#what-do-you-need-to-know-before-you-begin"
    PrintDynamicWidthLine
    $FedInfoDomainNames = ""
    $FedInfoDomainNames = ""
    foreach ($domain in $FedInfo.DomainNames.Domain) {
        if ($FedInfoDomainNames -ne "") {
            $FedInfoDomainNames += "; "
        }
        $FedInfoDomainNames += $domain
    }
    $Script:aux = $FedInfo.DomainNames
    $Script:FedInfoTokenIssuerUris = $FedInfo.TokenIssuerUris
    $Script:FedInfoTarGetAutoDiscoverEpr = $FedInfo.TarGetAutoDiscoverEpr
    $Script:FedInfoTarGetApplicationUri = $FedInfo.TarGetApplicationUri
    FedInfoHtml
}
function FedTrustCheck {
    Write-Host -ForegroundColor Green " Get-FederationTrust | fl ApplicationUri,TokenIssuerUri,OrgCertificate,TokenIssuerCertificate,
    TokenIssuerPrevCertificate, TokenIssuerMetadataEpr,TokenIssuerEpr"
    PrintDynamicWidthLine
    $Script:FedTrust = Get-FederationTrust | Select-Object ApplicationUri, TokenIssuerUri, OrgCertificate, TokenIssuerCertificate, TokenIssuerPrevCertificate, TokenIssuerMetadataEpr, TokenIssuerEpr
    $FedTrust
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Federation Trust"
    PrintDynamicWidthLine
    $CurrentTime = Get-Date
    Write-Host -ForegroundColor White " Federation Trust Application Uri:"
    if ($FedTrust.ApplicationUri -like "FYDIBOHF25SPDLT.$ExchangeOnpremDomain") {
        Write-Host -ForegroundColor Green " " $FedTrust.ApplicationUri
        $Script:tdFedTrustApplicationUriColor = "green"
        $Script:tdFedTrustApplicationUriFL = $FedTrust.ApplicationUri
    } else {
        Write-Host -ForegroundColor Red "  Federation Trust Application Uri Should be "$FedTrust.ApplicationUri
        $Script:tdFedTrustApplicationUriColor = "red"
        $Script:tdFedTrustApplicationUriFL = "  Federation Trust Application Uri Should be $FedTrust.ApplicationUri"
    }
    Write-Host -ForegroundColor White " TokenIssuerUri:"
    if ($FedTrust.TokenIssuerUri.AbsoluteUri -like "urn:federation:MicrosoftOnline") {
        Write-Host -ForegroundColor Green " "$FedTrust.TokenIssuerUri.AbsoluteUri
        $Script:tdFedTrustTokenIssuerUriColor = "green"
        $Script:tdFedTrustTokenIssuerUriFL = $FedTrust.TokenIssuerUri.AbsoluteUri
    } else {
        Write-Host -ForegroundColor Red " Federation Trust TokenIssuerUri should be urn:federation:MicrosoftOnline"
        $Script:tdFedTrustTokenIssuerUriColor = "red"
        $Script:tdFedTrustTokenIssuerFL = " Federation Trust TokenIssuerUri is currently $FedTrust.TokenIssuerUri.AbsoluteUri but should be urn:federation:MicrosoftOnline"
    }
    Write-Host -ForegroundColor White " Federation Trust Certificate Expiry:"
    if ($FedTrust.OrgCertificate.NotAfter.Date -gt $CurrentTime) {
        Write-Host -ForegroundColor Green "  Not Expired"
        Write-Host  "   - Expires on " $FedTrust.OrgCertificate.NotAfter.DateTime
        $Script:tdFedTrustOrgCertificateNotAfterDateColor = "green"
        $Script:tdFedTrustOrgCertificateNotAfterDateFL = $FedTrust.OrgCertificate.NotAfter.DateTime
    } else {
        Write-Host -ForegroundColor Red " Federation Trust Certificate is Expired on " $FedTrust.OrgCertificate.NotAfter.DateTime
        $Script:tdFedTrustOrgCertificateNotAfterDateColor = "red"
        $Script:tdFedTrustOrgCertificateNotAfterDateFL = $FedTrust.OrgCertificate.NotAfter.DateTime
    }
    Write-Host -ForegroundColor White " `Federation Trust Token Issuer Certificate Expiry:"
    if ($FedTrust.TokenIssuerCertificate.NotAfter.DateTime -gt $CurrentTime) {
        Write-Host -ForegroundColor Green "  Not Expired"
        Write-Host  "   - Expires on " $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
        $Script:tdFedTrustTokenIssuerCertificateNotAfterDateTimeColor = "green"
        $Script:tdFedTrustTokenIssuerCertificateNotAfterDateTimeFL = $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
    } else {
        Write-Host -ForegroundColor Red "  Federation Trust TokenIssuerCertificate Expired on " $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
        $Script:tdFedTrustTokenIssuerCertificateNotAfterDateTimeColor = "red"
        $Script:tdFedTrustTokenIssuerCertificateNotAfterDateTimeFL = $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
    }
    $FedTrustTokenIssuerMetadataEpr = "https://nexus.microsoftonline-p.com/FederationMetadata/2006-12/FederationMetadata.xml"
    Write-Host -ForegroundColor White " `Token Issuer Metadata EPR:"
    if ($FedTrust.TokenIssuerMetadataEpr.AbsoluteUri -like $FedTrustTokenIssuerMetadataEpr) {
        Write-Host -ForegroundColor Green "  Token Issuer Metadata EPR is " $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
        #test if it can be reached
        $Script:tdFedTrustTokenIssuerMetadataEprAbsoluteUriColor = "green"
        $Script:tdFedTrustTokenIssuerMetadataEprAbsoluteUriFL = $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
    } else {
        Write-Host -ForegroundColor Red " Token Issuer Metadata EPR is Not " $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
        $Script:tdFedTrustTokenIssuerMetadataEprAbsoluteUriColor = "red"
        $Script:tdFedTrustTokenIssuerMetadataEprAbsoluteUriFL = $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
    }
    $FedTrustTokenIssuerEpr = "https://login.microsoftonline.com/extSTS.srf"
    Write-Host -ForegroundColor White " Token Issuer EPR:"
    if ($FedTrust.TokenIssuerEpr.AbsoluteUri -like $FedTrustTokenIssuerEpr) {
        Write-Host -ForegroundColor Green "  Token Issuer EPR is:" $FedTrust.TokenIssuerEpr.AbsoluteUri
        #test if it can be reached
        $Script:tdFedTrustTokenIssuerEprAbsoluteUriColor = "green"
        $Script:tdFedTrustTokenIssuerEprAbsoluteUriFL = $FedTrust.TokenIssuerEpr.AbsoluteUri
    } else {
        Write-Host -ForegroundColor Red "  Token Issuer EPR is Not:" $FedTrust.TokenIssuerEpr.AbsoluteUri
        $Script:tdFedTrustTokenIssuerEprAbsoluteUriColor = "red"
        $Script:tdFedTrustTokenIssuerEprAbsoluteUriFL = $FedTrust.TokenIssuerEpr.AbsoluteUri
    }
    $Script:FedInfoTokenIssuerUris = $FedInfo.TokenIssuerUris
    $Script:FedInfoTarGetApplicationUri = $FedInfo.TarGetApplicationUri
    $script:FedInfoTarGetAutoDiscoverEpr = $FedInfo.TarGetAutoDiscoverEpr
    fedTrustHtml
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/exchange/configure-a-federation-trust-exchange-2013-help"
}
function AvailabilityAddressSpaceCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-AvailabilityAddressSpace $ExchangeOnlineDomain | fl ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name"
    PrintDynamicWidthLine
    $AvailabilityAddressSpace = Get-AvailabilityAddressSpace $ExchangeOnlineDomain -ErrorAction SilentlyContinue | Select-Object ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name
    if (!$AvailabilityAddressSpace) {
        $AvailabilityAddressSpace = Get-AvailabilityAddressSpace $ExchangeOnlineDomain -ErrorAction SilentlyContinue | Select-Object ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name
    }
    $AvailabilityAddressSpace
    $Script:tdAvailabilityAddressSpaceName = $AvailabilityAddressSpace.Name
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - On-Prem Availability Address Space Check"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " ForestName: "
    if ($AvailabilityAddressSpace.ForestName -like $ExchangeOnlineDomain) {
        Write-Host -ForegroundColor Green " " $AvailabilityAddressSpace.ForestName
        $Script:tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $Script:tdAvailabilityAddressSpaceForestColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ForestName appears not to be correct."
        Write-Host -ForegroundColor White " Should contain the " $ExchangeOnlineDomain
        $Script:tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $Script:tdAvailabilityAddressSpaceForestColor = "red"
    }
    Write-Host -ForegroundColor White " UserName: "
    if ($AvailabilityAddressSpace.UserName -like "") {
        Write-Host -ForegroundColor Green "  Blank"
        $Script:tdAvailabilityAddressSpaceUserName = " Blank"
        $Script:tdAvailabilityAddressSpaceUserNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red " UserName is NOT correct. "
        Write-Host -ForegroundColor White "  Normally it should be blank"
        $Script:tdAvailabilityAddressSpaceUserName = $AvailabilityAddressSpace.UserName
        $Script:tdAvailabilityAddressSpaceUserNameColor = "red"
    }
    Write-Host -ForegroundColor White " UseServiceAccount: "
    if ($AvailabilityAddressSpace.UseServiceAccount -like "True") {
        Write-Host -ForegroundColor Green "  True"
        $Script:tdAvailabilityAddressSpaceUseServiceAccount = $AvailabilityAddressSpace.UseServiceAccount
        $Script:tdAvailabilityAddressSpaceUseServiceAccountColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UseServiceAccount appears not to be correct."
        Write-Host -ForegroundColor White "  Should be True"
        $Script:tdAvailabilityAddressSpaceUseServiceAccount = $AvailabilityAddressSpace.UseServiceAccount
        $Script:tdAvailabilityAddressSpaceUseServiceAccountColor = "red"
    }
    Write-Host -ForegroundColor White " AccessMethod:"
    if ($AvailabilityAddressSpace.AccessMethod -like "InternalProxy") {
        Write-Host -ForegroundColor Green "  InternalProxy"
        $Script:tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $Script:tdAvailabilityAddressSpaceAccessMethodColor = "green"
    } else {
        Write-Host -ForegroundColor Red " AccessMethod appears not to be correct."
        Write-Host -ForegroundColor White " Should be InternalProxy"
        $Script:tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $Script:tdAvailabilityAddressSpaceAccessMethodColor = "red"
    }
    Write-Host -ForegroundColor White " ProxyUrl: "
    $Script:tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
    if ([String]::Equals($Script:tdAvailabilityAddressSpaceProxyUrl, $Script:ExchangeOnPremEWS, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ProxyUrl
        #$Script:tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $Script:tdAvailabilityAddressSpaceProxyUrlColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ProxyUrl appears not to be correct."
        Write-Host -ForegroundColor White "  Should be $Script:ExchangeOnPremEWS[0] and not $Script:tdAvailabilityAddressSpaceProxyUrl"
        #$Script:tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $Script:tdAvailabilityAddressSpaceProxyUrlColor = "red"
    }
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/powershell/module/exchange/Get-availabilityaddressspace?view=exchange-ps"
    AvailabilityAddressSpaceHtml
}
function AutoDVirtualDCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-AutoDiscoverVirtualDirectory -Server $($server) | Select Identity,Name,ExchangeVersion,*authentication*"
    PrintDynamicWidthLine
    FetchAutoDiscoverInformation
    $Script:AutoDiscoveryVirtualDirectory
    #$AutoDFL = $Script:AutoDiscoveryVirtualDirectory | Format-List
    $script:html += ""
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - On-Prem Get-AutoDiscoverVirtualDirectory"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White "  WSSecurityAuthentication:"
    if ($Script:AutoDiscoveryVirtualDirectory.WSSecurityAuthentication -eq "True") {
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication)"
            $Script:AutoD_VD_Identity = $ser.Identity
            $Script:AutoD_VD_Name = $ser.Name
            $Script:AutoD_VD_InternalAuthenticationMethods = $ser.InternalAuthenticationMethods
            $Script:AutoD_VD_ExternalAuthenticationMethods = $ser.ExternalAuthenticationMethods
            $Script:AutoD_VD_WSAuthentication = $ser.WSSecurityAuthentication
            $Script:AutoD_VD_WSAuthenticationColor = "green"
            $Script:AutoD_VD_WindowsAuthentication = $ser.WindowsAuthentication
            if ($Script:AutoD_VD_WindowsAuthentication -eq "True") {
                $Script:AutoD_VD_WindowsAuthenticationColor = "green"
            } else {
                $Script:AutoD_VD_WindowsAuthenticationColor = "red"
            }
            $Script:AutoD_VD_InternalNblBypassUrl = $ser.InternalNblBypassUrl
            $Script:AutoD_VD_InternalUrl = $ser.InternalUrl
            $Script:AutoD_VD_ExternalUrl = $ser.ExternalUrl
            autoDVDHtmlOK
            $Script:serWSSecurityAuthenticationColor = "Green"
        }
    } else {
        Write-Host -ForegroundColor Red " WSSecurityAuthentication is NOT correct."
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication)"
            $Script:serWSSecurityAuthenticationColor = "Red"
            Write-Host " $($ser.Identity) "
            $Script:AutoD_VD_Identity = $ser.Identity
            $Script:AutoD_VD_Name = $ser.Name
            $Script:AutoD_VD_InternalAuthenticationMethods = $ser.InternalAuthenticationMethods
            $Script:AutoD_VD_ExternalAuthenticationMethods = $ser.ExternalAuthenticationMethods
            $Script:AutoD_VD_WSAuthentication = $ser.WSSecurityAuthentication
            $Script:AutoD_VD_WSAuthenticationColor = "green"
            $Script:AutoD_VD_WindowsAuthentication = $ser.WindowsAuthentication
            if ($Script:AutoD_VD_WindowsAuthentication -eq "True") {
                $Script:AutoD_VD_WindowsAuthenticationColor = "green"
            } else {
                $Script:AutoD_VD_WindowsAuthenticationColor = "red"
            }
            $Script:AutoD_VD_InternalNblBypassUrl = $ser.InternalNblBypassUrl
            $Script:AutoD_VD_InternalUrl = $ser.InternalUrl
            $Script:AutoD_VD_ExternalUrl = $ser.ExternalUrl
            autoDVDHtmlNotOK
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication)"
            $Script:serWSSecurityAuthenticationColor = "Red"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($Script:AutoDiscoveryVirtualDirectory.WindowsAuthentication -eq "True") {
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication is NOT correct."
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/powershell/module/exchange/Get-AutoDiscovervirtualdirectory?view=exchange-ps"
}
function EWSVirtualDirectoryCheck {
    Write-Host -ForegroundColor Green " Get-WebServicesVirtualDirectory -Server $($server)| Select Identity,Name,ExchangeVersion,*Authentication*,*url"
    PrintDynamicWidthLine
    FetchEWSInformation
    $Script:WebServicesVirtualDirectory
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Get-WebServicesVirtualDirectory"
    PrintDynamicWidthLine
    EWSVirtualDHeaderHtml
    Write-Host -ForegroundColor White "  WSSecurityAuthentication:"
    if ($Script:WebServicesVirtualDirectory.WSSecurityAuthentication -like "True") {
        foreach ( $EWS in $Script:WebServicesVirtualDirectory) {
            Write-Host " $($EWS.Identity)"
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($EWS.WSSecurityAuthentication) "
            $Script:EwsVDIdentity = $EWS.Identity
            $Script:EwsVDName = $EWS.Name
            $Script:EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $Script:EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $Script:EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
            $Script:EwsVD_WSAuthenticationColor = "green"
            $Script:EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
            if ($Script:EwsVDWindowsAuthentication -eq "True") {
                $Script:EwsVDWindowsAuthenticationColor = "green"
            } else {
                $Script:EWS_DWindowsAuthenticationColor = "red"
            }
            $Script:EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $Script:EwsVDInternalUrl = $EWS.InternalUrl
            $Script:EwsVDExternalUrl = $EWS.ExternalUrl
            EwsVDHtmlOK
        }
    } else {
        Write-Host -ForegroundColor Red " WSSecurityAuthentication should be True."
        foreach ( $EWS in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication) "
            $Script:EwsVDIdentity = $EWS.Identity
            $Script:EwsVDName = $EWS.Name
            $Script:EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $Script:EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $Script:EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
            $Script:EwsVD_WSAuthenticationColor = "green"
            $Script:EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
            if ($Script:EwsVDWindowsAuthentication -eq "True") {
                $Script:EwsVDWindowsAuthenticationColor = "green"
            } else {
                $Script:EWS_DWindowsAuthenticationColor = "red"
            }
            $Script:EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $Script:EwsVDInternalUrl = $EWS.InternalUrl
            $Script:EwsVDExternalUrl = $EWS.ExternalUrl
        }
        Write-Host -ForegroundColor White "  Should be True"
    }
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($Script:WebServicesVirtualDirectory.WindowsAuthentication -like "True") {
        foreach ( $EWS in $Script:WebServicesVirtualDirectory) {
            Write-Host " $($EWS.Identity)"
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($EWS.WindowsAuthentication) "
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication should be True."
        foreach ( $EWS in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication) "
        }
        Write-Host -ForegroundColor White "  Should be True"
    }
    $html | Out-File -FilePath $htmlFile
}
function TestOrgRel {
    PrintDynamicWidthLine
    #$Script:TestFail = 0
    $OrgRelIdentity = $OrgRel.Identity
    $OrgRelTarGetApplicationUri = $OrgRel.TarGetApplicationUri
    if ( $OrgRelTarGetApplicationUri -like "Outlook.com" -OR $OrgRelTarGetApplicationUri -like "outlook.com") {
        Write-Host -ForegroundColor Green "Test-OrganizationRelationship -Identity $OrgRelIdentity  -UserIdentity $UserOnPrem"
        #need to grab errors and provide alerts in error case
        PrintDynamicWidthLine
        $TestOrgRel = Test-OrganizationRelationship -Identity "$($OrgRelIdentity)"  -UserIdentity $UserOnPrem -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        #$TestOrgRel
        if ($TestOrgRel[16] -like "No Significant Issues to Report") {
            Write-Host -ForegroundColor Green "`n No Significant Issues to Report"
            TestOrgRelHtmlOK
        } else {
            TestOrgRelHtmlNotOK
            Write-Host -ForegroundColor Red "`n Test Organization Relationship Completed with errors"
        }
        $TestOrgRel[0]
        $TestOrgRel[1]
        $i = 0
        while ($i -lt $TestOrgRel.Length) {
            $element = $TestOrgRel[$i]
            #if ($element.Contains("RESULT: Success.")) {
            if ($element -like "*RESULT: Success.*") {
                $TestOrgRelStep = $TestOrgRel[$i - 1]
                $TestOrgRelStep
                Write-Host -ForegroundColor Green "$element"
                if (![string]::IsNullOrWhitespace($TestOrgRelStep)) {
                    $Script:html += "
                    <div></b> <span style='color:black'> <b> $TestOrgRelStep :</b></span> <span style='color:green'>$element</span></div>"
                }
            }

            else {
                if ($element -like "*RESULT: Error*") {
                    $TestOrgRelStep = $TestOrgRel[$i - 1]
                    $TestOrgRelStep
                    Write-Host -ForegroundColor Red "$element"
                    if (![string]::IsNullOrWhitespace($TestOrgRelStep)) {
                        $Script:html += "
                        <div></b> <span style='color:black'> <b> $TestOrgRelStep : </b></span> <span style='color:red'>$element</span></div>"
                    }
                }
            }
            $i++
        }
    } else {
        Write-Host -ForegroundColor Green " Test-OrganizationRelationship -Identity $OrgRelIdentity  -UserIdentity $UserOnPrem"
        #need to grab errors and provide alerts in error case
        PrintDynamicWidthLine
        Write-Host -ForegroundColor Red "`n Test-OrganizationRelationship can't be run if the Organization Relationship TarGet Application uri is not correct. Organization Relationship TarGet Application Uri should be Outlook.com"
        TestOrgRelHtmlNoUri
    }
    Write-Host -ForegroundColor Yellow "`n  Reference: https://techcommunity.microsoft.com/t5/exchange-team-blog/how-to-address-federation-trust-issues-in-hybrid-configuration/ba-p/1144285"
    PrintDynamicWidthLine
    $Script:html += "</td>
    </tr>"
    $html | Out-File -FilePath $htmlFile
}
function TestFedTrust {
    PrintDynamicWidthLine
    $TestFedTrustFail = 0
    $a = Test-FederationTrust -UserIdentity $UserOnPrem -verbose -ErrorAction SilentlyContinue #fails the first time on multiple occasions so we have a ghost FedTrustCheck
    if ($a) {
        #Using to suppress waring for unused variable
    }
    Write-Host -ForegroundColor Green  " Test-FederationTrust -UserIdentity $UserOnPrem -verbose"
    PrintDynamicWidthLine
    $TestFedTrust = Test-FederationTrust -UserIdentity $UserOnPrem -verbose -ErrorAction SilentlyContinue
    $TestFedTrust
    $Script:html += "<tr>
    <th ColSpan='2' style='color:white;'><b>Summary - On Premise Test-FederationTrust</b></th>
    </tr>
    <tr>
    <td><b> Test-FederationTrust -UserIdentity $UserOnPrem</b></td>
    <td>"
    $i = 0
    while ($i -lt $TestFedTrust.type.Count) {
        $test = $TestFedTrust.type[$i]
        $testType = $TestFedTrust.Type[$i]
        $testMessage = $TestFedTrust.Message[$i]
        $TestFedTrustID = $($TestFedTrust.ID[$i])
        if ($test -eq "Error") {
            $Script:html += "

            <div> <span style='color:red'><b>$testType :</b></span> - <div> <b>$TestFedTrustID </b> - $testMessage  </div>
            "
            $TestFedTrustFail++
        }
        if ($test -eq "Success") {

            $Script:html += "

            <div> <span style='color:green'><b>$testType :</b> </span> - <b>$TestFedTrustID </b> - $testMessage</div>"
        }
        $i++
    }

    if ($TestFedTrustFail -eq 0) {
        Write-Host -ForegroundColor Green " Federation Trust Successfully tested"
        $Script:html += "
        <p></p>
        <div class=�green�> <span style='color:green'> Federation Trust Successfully tested </span></div>"
    } else {
        Write-Host -ForegroundColor Red " Federation Trust test with Errors"
        $Script:html += "
        <p></p>
        <div class=�red�> <span style='color:red'> Federation Trust tested with Errors </span></div>"
    }
    $TestFederationTrustCertificate = Test-FederationTrustCertificate -ErrorAction SilentlyContinue
    if ($TestFederationTrustCertificate) {
        PrintDynamicWidthLine
        Write-Host -ForegroundColor Green " Test-FederationTrustCertificate"
        PrintDynamicWidthLine
        $TestFederationTrustCertificate
        $Script:html += "<tr>
                <th ColSpan='2' style='color:white;'><b>Summary - Test-FederationTrustCertificate</b></th>
                </tr>
                <tr>
                <td><b> Test-FederationTrustCertificate</b></td>
                <td>"
        $j = 0
        while ($j -lt $TestFederationTrustCertificate.Count) {
            $TestFederationTrustCertificateJ = "<div>" + $TestFederationTrustCertificate.site[$j] + "</div><div>" + $TestFederationTrustCertificate.state[$j] + "</div><div>" + $TestFederationTrustCertificate.Thumbprint[$j] + "</div>"
            $Script:html += "
                $TestFederationTrustCertificateJ
                "
            $j++
        }
        $Script:html += "</td>"
    }
    $html | Out-File -FilePath $htmlFile
}
