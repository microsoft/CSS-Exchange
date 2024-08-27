# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
function IntraOrgConCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConnector | Select Name,TarGetAddressDomains,DiscoveryEndpoint,Enabled"
    PrintDynamicWidthLine
    $IOC = $IntraOrgCon | Format-List
    $IOC
    $Script:tdIntraOrgTarGetAddressDomain = $IntraOrgCon.TarGetAddressDomains
    $Script:tdDiscoveryEndpoint = $IntraOrgCon.DiscoveryEndpoint
    $Script:tdEnabled = $IntraOrgCon.Enabled

    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Get-IntraOrganizationConnector"
    PrintDynamicWidthLine
    $IntraOrgTarGetAddressDomain = $IntraOrgCon.TarGetAddressDomains.Domain
    $IntraOrgTarGetAddressDomain = $IntraOrgTarGetAddressDomain.ToLower()
    Write-Host -ForegroundColor White " TarGet Address Domains: "
    if ($IntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnlineDomain*" -Or $IntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnlineAltDomain*" ) {
        Write-Host -ForegroundColor Green " " $IntraOrgCon.TarGetAddressDomains
        $Script:tdIntraOrgTarGetAddressDomainColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TarGet Address Domains appears not to be correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnlineDomain domain or the $ExchangeOnlineAltDomain domain."
        $Script:tdIntraOrgTarGetAddressDomainColor = "red"
    }
    Write-Host -ForegroundColor White " DiscoveryEndpoint: "
    if ($IntraOrgCon.DiscoveryEndpoint -like "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc") {
        Write-Host -ForegroundColor Green "  https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc"
        $Script:tdDiscoveryEndpointColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  The DiscoveryEndpoint appears not to be correct. "
        Write-Host -ForegroundColor White "  It should represent the address of EXO AutoDiscover endpoint."
        Write-Host  "  Examples: https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc; https://outlook.office365.com/AutoDiscover/AutoDiscover.svc "
        $Script:tdDiscoveryEndpointColor = "red"
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($IntraOrgCon.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $Script:tdEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  On-Prem Intra Organization Connector is not Enabled"
        Write-Host -ForegroundColor White "  In order to use OAuth it Should be True."
        Write-Host "  If it is set to False, the Organization Relationship (DAuth) , if enabled, is used for the Hybrid Availability Sharing"
        $Script:tdEnabledColor = "red"
    }
    Write-Host -ForegroundColor Yellow "https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-hybrid-free-busy-what-are-the-moving-parts/ba-p/607704"
    IntraOrgConCheckHtml
}
function AuthServerCheck {
    #PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-AuthServer | Select Name,IssuerIdentifier,TokenIssuingEndpoint,AuthMetadatAUrl,Enabled"
    PrintDynamicWidthLine
    $AuthServer = Get-AuthServer | Where-Object { $_.Name -like "ACS*" } | Select-Object Name, IssuerIdentifier, TokenIssuingEndpoint, AuthMetadatAUrl, Enabled
    $AuthServer
    $Script:tDAuthServerIssuerIdentifier = $AuthServer.IssuerIdentifier
    $Script:tDAuthServerTokenIssuingEndpoint = $AuthServer.TokenIssuingEndpoint
    $Script:tDAuthServerAuthMetadatAUrl = $AuthServer.AuthMetadatAUrl
    $Script:tDAuthServerEnabled = $AuthServer.Enabled
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Auth Server"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " IssuerIdentifier: "
    if ($AuthServer.IssuerIdentifier -like "00000001-0000-0000-c000-000000000000" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.IssuerIdentifier
        $Script:tDAuthServerIssuerIdentifierColor = "green"
    } else {
        Write-Host -ForegroundColor Red " IssuerIdentifier appears not to be correct."
        Write-Host -ForegroundColor White " Should be 00000001-0000-0000-c000-000000000000"
        $Script:tDAuthServerIssuerIdentifierColor = "red"
    }
    Write-Host -ForegroundColor White " TokenIssuingEndpoint: "
    if ($AuthServer.TokenIssuingEndpoint -like "https://accounts.accesscontrol.windows.net/*" -and $AuthServer.TokenIssuingEndpoint -like "*/tokens/OAuth/2" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.TokenIssuingEndpoint
        $Script:tDAuthServerTokenIssuingEndpointColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TokenIssuingEndpoint appears not to be correct."
        Write-Host -ForegroundColor White " Should be  https://accounts.accesscontrol.windows.net/<Cloud Tenant ID>/tokens/OAuth/2"
        $Script:tDAuthServerTokenIssuingEndpointColor = "red"
    }
    Write-Host -ForegroundColor White " AuthMetadatAUrl: "
    if ($AuthServer.AuthMetadatAUrl -like "https://accounts.accesscontrol.windows.net/*" -and $AuthServer.TokenIssuingEndpoint -like "*/tokens/OAuth/2" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.AuthMetadatAUrl
        $Script:tDAuthServerAuthMetadatAUrlColor = "green"
    } else {
        Write-Host -ForegroundColor Red " AuthMetadatAUrl appears not to be correct."
        Write-Host -ForegroundColor White " Should be  https://accounts.accesscontrol.windows.net/<Cloud Tenant ID>/metadata/json/1"
        $Script:tDAuthServerAuthMetadatAUrlColor = "red"
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($AuthServer.Enabled -like "True" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.Enabled
        $Script:tDAuthServerEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red " Enabled: False "
        Write-Host -ForegroundColor White " Should be True"
        $Script:tDAuthServerEnabledColor = "red"
    }
    AuthServerCheckHtml
}
function PartnerApplicationCheck {
    #PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-PartnerApplication |  ?{`$_.ApplicationIdentifier -eq '00000002-0000-0ff1-ce00-000000000000'
    -and `$_.Realm -eq ''} | Select Enabled, ApplicationIdentifier, CertificateStrings, AuthMetadatAUrl, Realm, UseAuthServer,
    AcceptSecurityIdentifierInformation, LinkedAccount, IssuerIdentifier, AppOnlyPermissions, ActAsPermissions, Name"
    PrintDynamicWidthLine
    $PartnerApplication = Get-PartnerApplication | Where-Object { $_.ApplicationIdentifier -eq '00000002-0000-0ff1-ce00-000000000000' -and $_.Realm -eq '' } | Select-Object Enabled, ApplicationIdentifier, CertificateStrings, AuthMetadatAUrl, Realm, UseAuthServer, AcceptSecurityIdentifierInformation, LinkedAccount, IssuerIdentifier, AppOnlyPermissions, ActAsPermissions, Name
    $PartnerApplication
    $Script:tdPartnerApplicationEnabled = $PartnerApplication.Enabled
    $Script:tdPartnerApplicationApplicationIdentifier = $PartnerApplication.ApplicationIdentifier
    $Script:tdPartnerApplicationCertificateStrings = $PartnerApplication.CertificateStrings
    $Script:tdPartnerApplicationAuthMetadataUrl = $PartnerApplication.AuthMetadatAUrl
    $Script:tdPartnerApplicationRealm = $PartnerApplication.Realm
    $Script:tdPartnerApplicationUseAuthServer = $PartnerApplication.UseAuthServer
    $Script:tdPartnerApplicationAcceptSecurityIdentifierInformation = $PartnerApplication.AcceptSecurityIdentifierInformation
    $Script:tdPartnerApplicationLinkedAccount = $PartnerApplication.LinkedAccount
    $Script:tdPartnerApplicationIssuerIdentifier = $PartnerApplication.IssuerIdentifier
    $Script:tdPartnerApplicationAppOnlyPermissions = $PartnerApplication.AppOnlyPermissions
    $Script:tdPartnerApplicationActAsPermissions = $PartnerApplication.ActAsPermissions
    $Script:tdPartnerApplicationName = $PartnerApplication.Name
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Partner Application"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " Enabled: "
    if ($PartnerApplication.Enabled -like "True" ) {
        Write-Host -ForegroundColor Green " " $PartnerApplication.Enabled
        $Script:tdPartnerApplicationEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red " Enabled: False "
        Write-Host -ForegroundColor White " Should be True"
        $Script:tdPartnerApplicationEnabledColor = "red"
    }
    Write-Host -ForegroundColor White " ApplicationIdentifier: "
    if ($PartnerApplication.ApplicationIdentifier -like "00000002-0000-0ff1-ce00-000000000000" ) {
        Write-Host -ForegroundColor Green " " $PartnerApplication.ApplicationIdentifier
        $Script:tdPartnerApplicationApplicationIdentifierColor = "green"
    } else {
        Write-Host -ForegroundColor Red " ApplicationIdentifier does not appear to be correct"
        Write-Host -ForegroundColor White " Should be 00000002-0000-0ff1-ce00-000000000000"
        $Script:tdPartnerApplicationApplicationIdentifierColor = "red"
    }
    Write-Host -ForegroundColor White " AuthMetadatAUrl: "
    if ([string]::IsNullOrWhitespace( $PartnerApplication.AuthMetadatAUrl)) {
        Write-Host -ForegroundColor Green "  Blank"
        $Script:tdPartnerApplicationAuthMetadataUrlColor = "green"
        $Script:tdPartnerApplicationAuthMetadataUrl = "Blank"
    } else {
        Write-Host -ForegroundColor Red " AuthMetadatAUrl does not seem to be correct"
        Write-Host -ForegroundColor White " Should be Blank"
        $Script:tdPartnerApplicationAuthMetadataUrlColor = "red"
        $Script:tdPartnerApplicationAuthMetadataUrl = " Should be Blank"
    }
    Write-Host -ForegroundColor White " Realm: "
    if ([string]::IsNullOrWhitespace( $PartnerApplication.Realm)) {
        Write-Host -ForegroundColor Green "  Blank"
        $Script:tdPartnerApplicationRealmColor = "green"
        $Script:tdPartnerApplicationRealm = "Blank"
    } else {
        Write-Host -ForegroundColor Red "  Realm does not seem to be correct"
        Write-Host -ForegroundColor White " Should be Blank"
        $Script:tdPartnerApplicationRealmColor = "Red"
        $Script:tdPartnerApplicationRealm = "Should be Blank"
    }
    Write-Host -ForegroundColor White " LinkedAccount: "
    if ($PartnerApplication.LinkedAccount -like "$exchangeOnPremDomain/Users/Exchange Online-ApplicationAccount" -or $PartnerApplication.LinkedAccount -like "$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount"  ) {
        Write-Host -ForegroundColor Green " " $PartnerApplication.LinkedAccount
        $Script:tdPartnerApplicationLinkedAccountColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  LinkedAccount value does not appear to be correct"
        Write-Host -ForegroundColor White "  Should be $exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount"
        Write-Host "  If you value is empty, set it to correspond to the Exchange Online-ApplicationAccount which is located at the root of Users container in AD. After you make the change, reboot the Servers."
        Write-Host "  Example: contoso.com/Users/Exchange Online-ApplicationAccount"
        $Script:tdPartnerApplicationLinkedAccountColor = "red"
        $Script:tdPartnerApplicationLinkedAccount
    }
    PartnerApplicationCheckHtml
}
function ApplicationAccountCheck {
    #PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-user '$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount' | Select Name, RecipientType, RecipientTypeDetails, UserAccountControl"
    PrintDynamicWidthLine
    $ApplicationAccount = Get-user "$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount" | Select-Object Name, RecipientType, RecipientTypeDetails, UserAccountControl
    $ApplicationAccount
    $Script:tdApplicationAccountRecipientType = $ApplicationAccount.RecipientType
    $Script:tdApplicationAccountRecipientTypeDetails = $ApplicationAccount.RecipientTypeDetails
    $Script:tdApplicationAccountUserAccountControl = $ApplicationAccount.UserAccountControl
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Application Account"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " RecipientType: "
    if ($ApplicationAccount.RecipientType -like "User" ) {
        Write-Host -ForegroundColor Green " " $ApplicationAccount.RecipientType
        $Script:tdApplicationAccountRecipientTypeColor = "green"
    } else {
        Write-Host -ForegroundColor Red " RecipientType value is $ApplicationAccount.RecipientType "
        Write-Host -ForegroundColor White " Should be User"
        $Script:tdApplicationAccountRecipientTypeColor = "red"
    }
    Write-Host -ForegroundColor White " RecipientTypeDetails: "
    if ($ApplicationAccount.RecipientTypeDetails -like "LinkedUser" ) {
        Write-Host -ForegroundColor Green " " $ApplicationAccount.RecipientTypeDetails
        $Script:tdApplicationAccountRecipientTypeDetailsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " RecipientTypeDetails value is $ApplicationAccount.RecipientTypeDetails"
        Write-Host -ForegroundColor White " Should be LinkedUser"
        $Script:tdApplicationAccountRecipientTypeDetailsColor = "red"
    }
    Write-Host -ForegroundColor White " UserAccountControl: "
    if ($ApplicationAccount.UserAccountControl -like "AccountDisabled, PasswordNotRequired, NormalAccount" ) {
        Write-Host -ForegroundColor Green " " $ApplicationAccount.UserAccountControl
        $Script:tdApplicationAccountUserAccountControlColor = "green"
    } else {
        Write-Host -ForegroundColor Red " UserAccountControl value does not seem correct"
        Write-Host -ForegroundColor White " Should be AccountDisabled, PasswordNotRequired, NormalAccount"
        $Script:tdApplicationAccountUserAccountControlColor = "red"
    }
    ApplicationAccountCheckHtml
}
function ManagementRoleAssignmentCheck {
    Write-Host -ForegroundColor Green " Get-ManagementRoleAssignment -RoleAssignee Exchange Online-ApplicationAccount | Select Name,Role -AutoSize"
    PrintDynamicWidthLine
    $ManagementRoleAssignment = Get-ManagementRoleAssignment -RoleAssignee "Exchange Online-ApplicationAccount" | Select-Object Name, Role
    $M = $ManagementRoleAssignment | Out-String
    $M
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Management Role Assignment for the Exchange Online-ApplicationAccount"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " Role: "
    if ($ManagementRoleAssignment.Role -like "*UserApplication*" ) {
        Write-Host -ForegroundColor Green "  UserApplication Role Assigned"
        $Script:tdManagementRoleAssignmentUserApplication = " UserApplication Role Assigned"
        $Script:tdManagementRoleAssignmentUserApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UserApplication Role not present for the Exchange Online-ApplicationAccount"
        $Script:tdManagementRoleAssignmentUserApplication = " UserApplication Role not present"
        $Script:tdManagementRoleAssignmentUserApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*ArchiveApplication*" ) {
        Write-Host -ForegroundColor Green "  ArchiveApplication Role Assigned"
        $Script:tdManagementRoleAssignmentArchiveApplication = " ArchiveApplication Role Assigned"
        $Script:tdManagementRoleAssignmentArchiveApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ArchiveApplication Role not present for the Exchange Online-ApplicationAccount"
        $Script:tdManagementRoleAssignmentArchiveApplication = " ArchiveApplication Role not Assigned"
        $Script:tdManagementRoleAssignmentArchiveApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*LegalHoldApplication*" ) {
        Write-Host -ForegroundColor Green "  LegalHoldApplication Role Assigned"
        $Script:tdManagementRoleAssignmentLegalHoldApplication = " LegalHoldApplication Role Assigned"
        $Script:tdManagementRoleAssignmentLegalHoldApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  LegalHoldApplication Role not present for the Exchange Online-ApplicationAccount"
        $Script:tdManagementRoleAssignmentLegalHoldApplication = " LegalHoldApplication Role Assigned"
        $Script:tdManagementRoleAssignmentLegalHoldApplicationColor = "green"
    }
    if ($ManagementRoleAssignment.Role -like "*Mailbox Search*" ) {
        Write-Host -ForegroundColor Green "  Mailbox Search Role Assigned"
        $Script:tdManagementRoleAssignmentMailboxSearch = " Mailbox Search Role Assigned"
        $Script:tdManagementRoleAssignmentMailboxSearchColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Mailbox Search Role not present for the Exchange Online-ApplicationAccount"
        $Script:tdManagementRoleAssignmentMailboxSearch = " Mailbox Search Role Not Assigned"
        $Script:tdManagementRoleAssignmentMailboxSearchColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*TeamMailboxLifecycleApplication*" ) {
        Write-Host -ForegroundColor Green "  TeamMailboxLifecycleApplication Role Assigned"
        $Script:tdManagementRoleAssignmentTeamMailboxLifecycleApplication = " TeamMailboxLifecycleApplication Role Assigned"
        $Script:tdManagementRoleAssignmentTeamMailboxLifecycleApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  TeamMailboxLifecycleApplication Role not present for the Exchange Online-ApplicationAccount"
        $Script:tdManagementRoleAssignmentTeamMailboxLifecycleApplication = " TeamMailboxLifecycleApplication Role Not Assigned"
        $Script:tdManagementRoleAssignmentTeamMailboxLifecycleApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*MailboxSearchApplication*" ) {
        Write-Host -ForegroundColor Green "  MailboxSearchApplication Role Assigned"
        $Script:tdManagementRoleMailboxSearchApplication = " MailboxSearchApplication Role Assigned"
        $Script:tdManagementRoleMailboxSearchApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  MailboxSearchApplication Role not present for the Exchange Online-ApplicationAccount"
        $Script:tdManagementRoleMailboxSearchApplication = " MailboxSearchApplication Role Not Assigned"
        $Script:tdManagementRoleMailboxSearchApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*MeetingGraphApplication*" ) {
        Write-Host -ForegroundColor Green "  MeetingGraphApplication Role Assigned"
        $Script:tdManagementRoleMeetingGraphApplication = " MeetingGraphApplication Role Assigned"
        $Script:tdManagementRoleMeetingGraphApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  MeetingGraphApplication Role not present for the Exchange Online-ApplicationAccount"
        $Script:tdManagementRoleMeetingGraphApplication = " MeetingGraphApplication Role Not Assigned"
        $Script:tdManagementRoleMeetingGraphApplicationColor = "red"
    }
    $Script:tdManagementRoleMeetingGraphApplication = " MailboxSearchApplication Role Assigned"
    $Script:tdManagementRoleMeetingGraphApplicationColor = "green"
    ManagementRoleAssignmentCheckHtml
}
function AuthConfigCheck {
    Write-Host -ForegroundColor Green " Get-AuthConfig | Select *Thumbprint, ServiceName, Realm, Name"
    PrintDynamicWidthLine
    $AuthConfig = Get-AuthConfig | Select-Object *Thumbprint, ServiceName, Realm, Name
    $AC = $AuthConfig | Format-List
    $AC
    $Script:tDAuthConfigName = $AuthConfig.Name
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Auth Config"
    PrintDynamicWidthLine
    if (![string]::IsNullOrWhitespace($AuthConfig.CurrentCertificateThumbprint)) {
        Write-Host " Thumbprint: "$AuthConfig.CurrentCertificateThumbprint
        Write-Host -ForegroundColor Green " Certificate is Assigned"
        $Script:tDAuthConfigCurrentCertificateThumbprint = $AuthConfig.CurrentCertificateThumbprint
        $Script:tDAuthConfigCurrentCertificateThumbprintColor = "green"
    } else {
        Write-Host " Thumbprint: "$AuthConfig.CurrentCertificateThumbprint
        Write-Host -ForegroundColor Red " No valid certificate Assigned "
        $Script:tDAuthConfigCurrentCertificateThumbprintColor = "red"
        $Script:tDAuthConfigCurrentCertificateThumbprint = "$AuthConfig.CurrentCertificateThumbprint - No valid certificate Assigned "
    }
    if ($AuthConfig.ServiceName -like "00000002-0000-0ff1-ce00-000000000000" ) {
        Write-Host " ServiceName: "$AuthConfig.ServiceName
        Write-Host -ForegroundColor Green " Service Name Seems correct"
        $Script:tDAuthConfigServiceNameColor = "green"
        $Script:tDAuthConfigServiceName = $AuthConfig.ServiceName
    } else {
        Write-Host " ServiceName: "$AuthConfig.ServiceName
        Write-Host -ForegroundColor Red " Service Name does not Seems correct. Should be 00000002-0000-0ff1-ce00-000000000000"
        $Script:tDAuthConfigServiceNameColor = "red"
        $Script:tDAuthConfigServiceName = "$AuthConfig.ServiceName  Should be 00000002-0000-0ff1-ce00-000000000000"
    }
    if ([string]::IsNullOrWhitespace($AuthConfig.Realm)) {
        Write-Host " Realm: "
        Write-Host -ForegroundColor Green " Realm is Blank"
        $Script:tDAuthConfigRealmColor = "green"
        $Script:tDAuthConfigRealm = " Realm is Blank"
    } else {
        Write-Host " Realm: "$AuthConfig.Realm
        Write-Host -ForegroundColor Red " Realm should be Blank"
        $Script:tDAuthConfigRealmColor = "red"
        $Script:tDAuthConfigRealm = "$Script:tDAuthConfig.Realm - Realm should be Blank"
    }
    AuthConfigCheckHtml
}
function CurrentCertificateThumbprintCheck {
    $thumb = Get-AuthConfig | Select-Object CurrentCertificateThumbprint
    $thumbprint = $thumb.CurrentCertificateThumbprint
    #PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-ExchangeCertificate -Thumbprint $thumbprint | Select FriendlyName, Issuer, Services, NotAfter, Status, HasPrivateKey, Subject, Thumb*"
    PrintDynamicWidthLine
    $CurrentCertificate = Get-ExchangeCertificate $thumb.CurrentCertificateThumbprint | Select-Object  FriendlyName, Issuer, Services, NotAfter, Status, HasPrivateKey, Subject, Thumb*
    $CC = $CurrentCertificate | Format-List
    $CC

    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Microsoft Exchange Server Auth Certificate"
    PrintDynamicWidthLine
    if ($CurrentCertificate.Issuer -like "CN=Microsoft Exchange Server Auth Certificate" ) {
        Write-Host " Issuer: " $CurrentCertificate.Issuer
        Write-Host -ForegroundColor Green " Issuer is CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateIssuer = "   $($CurrentCertificate.Issuer) - Issuer is CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateIssuerColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Issuer is not CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateIssuer = "   $($CurrentCertificate.Issuer) - Issuer is Not CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateIssuerColor = "red"
    }
    if ($CurrentCertificate.Services -like "SMTP" ) {
        Write-Host " Services: " $CurrentCertificate.Services
        Write-Host -ForegroundColor Green "  Certificate enabled for SMTP"
        $Script:tdCurrentCertificateServices = "  $($tdCurrentCertificate.Services) - Certificate enabled for SMTP"
        $Script:tdCurrentCertificateServicesColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Certificate Not enabled for SMTP"
        $Script:tdCurrentCertificateServices = "  $($tdCurrentCertificate.Services) - Certificate Not enabled for SMTP"
        $Script:tdCurrentCertificateServicesColor = "red"
    }
    if ($CurrentCertificate.Status -like "Valid" ) {
        Write-Host " Status: " $CurrentCertificate.Status
        Write-Host -ForegroundColor Green "  Certificate is valid"
        $Script:tdCurrentCertificateStatus = "  Certificate is valid"
        $Script:tdCurrentCertificateStatusColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Certificate is not Valid"
        $Script:tdCurrentCertificateStatus = "  Certificate is Not Valid"
        $Script:tdCurrentCertificateStatusColor = "red"
    }
    if ($CurrentCertificate.Subject -like "CN=Microsoft Exchange Server Auth Certificate" ) {
        Write-Host " Subject: " $CurrentCertificate.Subject
        Write-Host -ForegroundColor Green "  Subject is CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateSubject = "  Subject is CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateSubjectColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Subject is not CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateSubject = "  $($CurrentCertificate.Subject) - Subject should be CN=Microsoft Exchange Server Auth Certificate"
        $Script:tdCurrentCertificateSubjectColor = "red"
    }
    Write-Host -ForegroundColor White "`n Checking Exchange Auth Certificate Distribution `n"
    $CheckAuthCertDistribution = foreach ($name in (Get-ExchangeServer).name) { Get-ExchangeCertificate -Thumbprint (Get-AuthConfig).CurrentCertificateThumbprint -Server $name -ErrorAction SilentlyContinue | Select-Object Identity, thumbprint, Services, subject }
    foreach ($Server in $CheckAuthCertDistribution) {
        $ServerName = ($Server -split "\.")[0]
        Write-Host -ForegroundColor White  "  Server: " $ServerName
        #Write-Host  "   Thumbprint: " $Thumbprint
        if ($Server.Thumbprint -like $thumbprint) {
            Write-Host  "   Thumbprint: "$Server.Thumbprint
            Write-Host  "   Subject: "$Server.Subject
            $ServerIdentity = $Server.Identity
            $Script:tdCheckAuthCertDistribution = "   <div>Certificate with Thumbprint: $($Server.Thumbprint) Subject: $($Server.Subject) is present in Server $ServerIdentity</div>"
            $Script:tdCheckAuthCertDistributionColor = "green"
        }
        if ($Server.Thumbprint -ne $thumbprint) {
            Write-Host -ForegroundColor Red "  Auth Certificate seems Not to be present in $ServerName"
            $Script:tdCheckAuthCertDistribution = "   Auth Certificate seems Not to be present in $ServerName"
            $Script:tdCheckAuthCertDistributionColor = "Red"
        }
    }
    CurrentCertificateThumbprintCheckHtml
}
function OAuthConnectivityCheck {
    Write-Host -ForegroundColor Green " Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $UserOnPrem"
    PrintDynamicWidthLine
    $Script:OAuthConnectivity = Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $UserOnPrem
    if ($Script:OAuthConnectivity.ResultType -eq 'Success' ) {
        #$Script:OAuthConnectivity.ResultType
    } else {
        $Script:OAuthConnectivity
    }
    if ($Script:OAuthConnectivity.Detail.FullId -like '*(401) Unauthorized*') {
        Write-Host -ForegroundColor Red "Error: The remote Server returned an error: (401) Unauthorized"
        if ($Script:OAuthConnectivity.Detail.FullId -like '*The user specified by the user-context in the token does not exist*') {
            Write-Host -ForegroundColor Yellow "The user specified by the user-context in the token does not exist"
            Write-Host "Please run Test-OAuthConnectivity with a different Exchange On Premises Mailbox"
        }
    }
    Write-Host -ForegroundColor Green " Summary - Test OAuth Connectivity"
    PrintDynamicWidthLine
    if ($Script:OAuthConnectivity.ResultType -like "Success") {
        Write-Host -ForegroundColor Green "$($Script:OAuthConnectivity.ResultType). OAuth Test was completed successfully "
        $Script:OAuthConnectivityResultType = " OAuth Test was completed successfully "
        $Script:OAuthConnectivityResultTypeColor = "green"
    } else {
        Write-Host -ForegroundColor Red " $Script:OAuthConnectivity.ResultType - OAuth Test was completed with Error. "
        Write-Host -ForegroundColor White " Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $Script:OAuthConnectivityResultType = " <div>OAuth Test was completed with Error.</div><div>Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox <On Premises Mailbox> | fl to confirm the test failure</div>"
        $Script:OAuthConnectivityResultTypeColor = "red"
    }
    Write-Host -ForegroundColor Green " Reference: "
    Write-Host -ForegroundColor White " Configure OAuth authentication between Exchange and Exchange Online organizations"
    Write-Host -ForegroundColor Yellow " https://technet.microsoft.com/en-us/library/dn594521(v=exchg.150).aspx"
    OAuthConnectivityCheckHtml
}
function AutoDVirtualDCheckOauth {
    Write-Host -ForegroundColor Green " Get-AutoDiscoverVirtualDirectory -Server $($server) | Select Identity, Name,ExchangeVersion,*authentication*"
    PrintDynamicWidthLine
    FetchAutoDiscoverInformation
    $AD = $AutoDiscoveryVirtualDirectoryOAuth | Format-List
    $AD
    AutoDVirtualDCheckOauthHtmlHead
    if ($Auth -contains "OAuth") {
    }
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Get-AutoDiscoverVirtualDirectory"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White "  InternalAuthenticationMethods"
    if ($AutoDiscoveryVirtualDirectoryOAuth.InternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  InternalAuthenticationMethods Include OAuth Authentication Method "
            $Script:AutoD_VD_Identity = $EWS.Identity
            $Script:AutoD_VD_Name = $EWS.Name
            $Script:AutoD_VD_InternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $Script:AutoD_VD_ExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $Script:AutoD_VD_WSAuthentication = $EWS.WSSecurityAuthentication
            $Script:AutoD_VD_WSAuthenticationColor = "green"
            $Script:AutoD_VD_WindowsAuthentication = $EWS.WindowsAuthentication
            $Script:AutoD_VD_OAuthAuthentication = $EWS.OAuthAuthentication
            if ($Script:AutoD_VD_WindowsAuthentication -eq "True") {
                $Script:AutoD_VD_WindowsAuthenticationColor = "green"
            } else {
                $Script:AutoD_VD_WindowsAuthenticationColor = "red"
            }
            if ($Script:AutoD_VD_OAuthAuthentication -eq "True") {
                $Script:AutoD_VD_OAuthAuthenticationColor = "green"
            } else {
                $Script:AutoD_VD_OAuthAuthenticationColor = "red"
            }
            $Script:AutoD_VD_InternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $Script:AutoD_VD_InternalUrl = $EWS.InternalUrl
            $Script:AutoD_VD_ExternalUrl = $EWS.ExternalUrl
            AutoDVirtualDCheckOauthHtmlOk
        }
    } else {
        Write-Host -ForegroundColor Red "  InternalAuthenticationMethods seems not to include OAuth Authentication Method."
        $Script:AutoD_VD_Identity = $EWS.Identity
        $Script:AutoD_VD_Name = $EWS.Name
        $Script:AutoD_VD_InternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
        $Script:AutoD_VD_ExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
        $Script:AutoD_VD_WSAuthentication = $EWS.WSSecurityAuthentication
        $Script:AutoD_VD_WSAuthenticationColor = "green"
        $Script:AutoD_VD_OAuthAuthentication = $EWS.OAuthAuthentication
        $Script:AutoD_VD_WindowsAuthentication = $EWS.WindowsAuthentication
        if ($Script:AutoD_VD_WindowsAuthentication -eq "True") {
            $Script:AutoD_VD_WindowsAuthenticationColor = "green"
        } else {
            $Script:AutoD_VD_WindowsAuthenticationColor = "red"
        }
        $Script:AutoD_VD_InternalNblBypassUrl = $EWS.InternalNblBypassUrl
        $Script:AutoD_VD_InternalUrl = $EWS.InternalUrl
        $Script:AutoD_VD_ExternalUrl = $EWS.ExternalUrl
    }
    Write-Host -ForegroundColor White "`n  ExternalAuthenticationMethods"
    if ($AutoDiscoveryVirtualDirectoryOAuth.ExternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  ExternalAuthenticationMethods Include OAuth Authentication Method "
        }
    } else {
        Write-Host -ForegroundColor Red "  ExternalAuthenticationMethods seems not to include OAuth Authentication Method."
    }
    Write-Host -ForegroundColor White "`n  WSSecurityAuthentication:"
    if ($AutoDiscoveryVirtualDirectoryOAuth.WSSecurityAuthentication -like "True") {
        foreach ( $AdVd in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($AdVd.Identity) "
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($AdVd.WSSecurityAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red "  WSSecurityAuthentication settings are NOT correct."
        foreach ( $AdVd in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($AdVd.Identity) "
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($AdVd.WSSecurityAuthentication).  WSSecurityAuthentication setting should be True."
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($AutoDiscoveryVirtualDirectoryOAuth.WindowsAuthentication -eq "True") {
        foreach ( $ser in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication is NOT correct."
        foreach ( $ser in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
}
function EWSVirtualDirectoryCheckOAuth {
    Write-Host -ForegroundColor Green " Get-WebServicesVirtualDirectory  -Server $($server)| Select Identity,Name,ExchangeVersion,*Authentication*,*url"
    PrintDynamicWidthLine
    FetchEWSInformation
    $W = $WebServicesVirtualDirectoryOAuth | Format-List
    $W
    EWSVirtualDirectoryCheckOAuthHtmlHead
    if ($Auth -contains "OAuth") {
    }
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - On-Prem Get-WebServicesVirtualDirectory"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White "  InternalAuthenticationMethods"
    if ($WebServicesVirtualDirectoryOAuth.InternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $WebServicesVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  InternalAuthenticationMethods Include OAuth Authentication Method "
            $Script:EwsVDIdentity = $EWS.Identity
            $Script:EwsVDName = $EWS.Name
            $Script:EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $Script:EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $Script:EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
            $Script:EwsVD_WSAuthenticationColor = "green"
            $Script:EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
            $Script:EwsVDOAuthAuthentication = $EWS.OAuthAuthentication
            if ($Script:EwsVDWindowsAuthentication -eq "True") {
                $Script:EwsVDWindowsAuthenticationColor = "green"
            } else {
                $Script:EWS_VDWindowsAuthenticationColor = "red"
            }
            if ($EwsVDOAuthAuthentication -eq "True") {
                $Script:EwsVDW_OAuthAuthenticationColor = "green"
            } else {
                $Script:EWS_DOAuthAuthenticationColor = "red"
            }
            $Script:EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $Script:EwsVDInternalUrl = $EWS.InternalUrl
            $Script:EwsVDExternalUrl = $EWS.ExternalUrl
            EWSVirtualDirectoryCheckOAuthHtmlOk
        }
    } else {
        Write-Host -ForegroundColor Red "  InternalAuthenticationMethods seems not to include OAuth Authentication Method."
        $Script:EwsVDIdentity = $EWS.Identity
        $Script:EwsVDName = $EWS.Name
        $Script:EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
        $Script:EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
        $Script:EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
        $Script:EwsVD_WSAuthenticationColor = "green"
        $Script:EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
        $Script:EwsVDOAuthAuthentication = $EWS.OAuthAuthentication
        if ($Script:EwsVDWindowsAuthentication -eq "True") {
            $Script:EwsVDWindowsAuthenticationColor = "green"
        } else {
            $Script:EWS_DWindowsAuthenticationColor = "red"
        }
        if ($EwsVDOAuthAuthentication -eq "True") {
            $Script:EwsVDW_OAuthAuthenticationColor = "green"
        } else {
            $Script:EWS_DOAuthAuthenticationColor = "red"
        }
        $Script:EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
        $Script:EwsVDInternalUrl = $EWS.InternalUrl
        $Script:EwsVDExternalUrl = $EWS.ExternalUrl
        EWSVirtualDirectoryCheckOAuthHtmlNotOk
    }
    Write-Host -ForegroundColor White "`n  ExternalAuthenticationMethods"
    if ($WebServicesVirtualDirectoryOAuth.ExternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $WebServicesVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  ExternalAuthenticationMethods Include OAuth Authentication Method "
        }
    } else {
        Write-Host -ForegroundColor Red "  ExternalAuthenticationMethods seems not to include OAuth Authentication Method."
    }
    Write-Host -ForegroundColor White "`n  WSSecurityAuthentication:"
    if ($WebServicesVirtualDirectoryOAuth.WSSecurityAuthentication -like "True") {
        foreach ( $EWS in $WebServicesVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($EWS.WSSecurityAuthentication) "
        }
    } else {
        Write-Host -ForegroundColor Red "  WSSecurityAuthentication is NOT correct."
        foreach ( $EWS in $WebServicesVirtualDirectoryOauth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($EWS.WSSecurityAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True"
    }
    #PrintDynamicWidthLine
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($WebServicesVirtualDirectoryOauth.WindowsAuthentication -eq "True") {
        foreach ( $ser in $WebServicesVirtualDirectoryOauth) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication is NOT correct."
        foreach ( $ser in $WebServicesVirtualDirectoryOauth) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
}
