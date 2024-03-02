# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are being used in functions')]
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [String] $tdDomainNamesColor
)
#On Prem DAuth
function showParametersHtml() {
    $script:html = "<!DOCTYPE html>
 <!DOCTYPE html>
<html>
<head>
  <title>Hybrid Free Busy Configuration Checker</title>
  <style>
    body {
      font-family: Arial;
      background-color: white;
    }
    table, th {
    max-width: 95%;
    margin-left: 2%;
    margin-right: 2%;
      border: 1px solid black;
      border-collapse: collapse;
      padding: 5px;
      font-family: Courier;
      background-color: white;
      table-layout: fixed;
       font-family: Arial;
    }
    td {
      border: 1px solid black;
      border-collapse: collapse;
      padding: 5px;
      font-family: Arial;
      background-color: white;
      width: 50%;
      max-width: 50%;
      word-wrap: break-word;
    }
    th {
      background-color: blue;
      text-align: left;
       font-family: Arial;
    }
    .green { color: green; }
    .red { color: red; }
    .yellow { color: yellow; }
    .white { color: white; }
    .black { color: black; }
    .orange { color: orange; }
    .Black {
      font-weight: 500;
    }
     p {
      font-weight : 548;
    }
    h1 {
      color: #00a2ed;
      padding-left: 2%;
    }
    h2 {
      color: #00a2ed;
      padding-left: 2%;
    }
    h3 {
      color: #00a2ed;
      padding-left: 2%;
    }
    ul {
      padding-left: 8%;
    }

   .microsoft {
    background-color: #f25022;
    box-shadow:
        28px 0 0 0 #7fba00,
        0 28px 0 0 #00a4ef,
        28px 28px 0 0 #ffb900;
    height: 25px;
    width: 25px;
    margin-top: 1%;
    margin-right: 1%;
}
  </style>
</head>
<body>
            <div class='Black' style='display: -webkit-box;margin-left: 2%;'>
            <div class='microsoft'></div>
            <h1 style='padding-left: 2%;'>Microsoft CSS - Exchange Hybrid Free Busy Configuration Checker</h1></div>


	       <div class='Black' style = 'padding-left: 0%;'>
              <h2><b>Parameters:</b></h2>
              <ul>
                <li>
                  <p>Log File Path:</p>
                  <span style='color:green; font-weight:500; padding-left:2%;'>$LogFile</span>
                </li>
                <li>
                  <p>Office 365 Domain:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$ExchangeOnlineDomain</span>
                </li>
                <li>
                  <p>AD root Domain:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$exchangeOnPremLocalDomain</span>
                </li>
                <li>
                  <p>Exchange On Premises Domain:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$exchangeOnPremDomain</span>
                </li>
                <li>
                  <p>Exchange On Premises External EWS url:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$exchangeOnPremEWS</span>
                </li>
                <li>
                  <p>On Premises Hybrid Mailbox:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$UserOnPrem</span>
                </li>
                <li>
                  <p>Exchange Online Mailbox:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$UserOnline</span>
                </li>
              </ul>
            </div>
            <div class='Black'  style = 'padding-left: 0%;'><h2Configuration:</h2></div>
            <p style='margin-left:2%;'>TLS 1.2 should be Enabled in order for Hybrid Free Busy to work. To confirm TLS Settings please Run the HealthChecker Script</p>
              <ul>
                <li><a href='https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/'>Microsoft Exchange Health Checker Script</a></li>
              </ul>
            <h3>Useful Links</h3>
              <ul>
                <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-hybrid-free-busy-finding-errors-and-troubleshooting/ba-p/607727'>Demystifying Hybrid Free Busy: Finding Errors and Troubleshooting</a></li>
                <li><a href='https://support.microsoft.com/en-us/topic/how-to-troubleshoot-free-busy-issues-in-a-hybrid-deployment-of-on-premises-exchange-Server-and-exchange-online-in-office-365-ae03e199-b439-a84f-8db6-11bc0d7fbdf0'>How to Troubleshoot Free Busy Issues in a Hybrid Deployment of On-Premises Exchange Server and Exchange Online in Office 365</a></li>
                <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/the-hybrid-mesh/ba-p/605910'>The Hybrid Mesh</a></li>
                <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/how-to-address-federation-trust-issues-in-hybrid-configuration/ba-p/1144285'>How to Address Federation Trust Issues in Hybrid Configuration</a></li>
                <li><a href='https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?redirectSourcePath=%252farticle%252fOffice-365-URLs-and-IP-address-ranges-8548a211-3fe7-47cb-abb1-355ea5aa88a2&view=o365-worldwide'>Office 365 URLs and IP Address Ranges</a></li>
                <li><a href='https://techcommunity.microsoft.com/legacyfs/online/media/2019/01/FB_Errors.FixesV6.pdf'>Free Busy Errors and Fixes</a></li>
              </ul>
              "
    $html | Out-File -FilePath $htmlFile
}
function orgRelHtml() {
    $script:html += @"
     <div class='Black'><p></p></div>
     <div class='Black'><h2><b>`n Exchange On Premise Free Busy Configuration: `n</b></h2></div>
     <div class='Black'><p></p></div>
    <table style='width:100%'>
    <tr>
    <th ColSpan='2' style='text-align:center; color:white;'><b>Exchange On Premise DAuth Configuration</b></th>
    </tr>
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-OrganizationRelationship</th>
    </tr>
    <tr>
    <td><b>Get-OrganizationRelationship</b></td>
    <td>
"@
    foreach ($setting in $settingsList) {
        $color = $setting.Color
        if ($color -eq 'yellow') {
            $color = 'red'
        }
        $script:html += @"
        <div> <b>$($setting.Name): </b> <span style='color: $($color)'>$($setting.Value)</span></div>
"@
    }
    $script:html += @"
    </td>
    </tr>
"@
    $script:html | Out-File -FilePath $htmlFile
}
function FedInfoHtml() {
    $script:html += "
  <tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-FederationInformation</th>
  </tr>
  <tr>
  <td><b>Get-FederationInformation -Domain $ExchangeOnPremDomain</b></td>
  <td>
      <div> <b>Domain Names: </b> <span style='color:$tdDomainNamesColor'>$tdDomainNamesFL</span></div>
      <div> <b>TokenIssuerUris: </b> <span style='color:$tdTokenIssuerUrisColor'>$tdTokenIssuerUrisFL</span></div>
      <div> <b>TarGetApplicationUri: </b> <span style='color:$tdTarGetApplicationUriColor'>$tdTarGetApplicationUriFL</span></div>
      <div> <b>TarGetAutoDiscoverEpr: </b> <span style='color:$tdTarGetAutoDiscoverEprColor'>$tdTarGetAutoDiscoverEprFL</span></div>
      <div> <b>TarGetApplicationUri - Federation Information vs Organization Relationship: </b> <span style='color:$tdTarGetAutoDiscoverEprVSColor'>$tdFederationInformationTA_FL</span></div>
      <div> <b>TarGetAutoDiscoverEpr - Federation Information vs Organization Relationship:</b> <span style='color:$tdTarGetAutoDiscoverEprVSColor'>$tdTarGetAutoDiscoverEprVS_FL</span></div>
  </td>
</tr>
"
    $html | Out-File -FilePath $htmlFile
}
function fedTrustHtml() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Test-FederationTrust</th>
</tr>
<tr>
<td><b>Get-FederationTrust | select ApplicationUri, TokenIssuerUri, OrgCertificate, TokenIssuerCertificate, TokenIssuerPrevCertificate, TokenIssuerMetadataEpr, TokenIssuerEpr</b></td>
<td>
    <div> <b>Application Uri: </b> <span style='color:$tdFedTrustApplicationUriColor'>$tdFedTrustApplicationUriFL</span></div>
    <div> <b>TokenIssuerUris: </b> <span style='color:$tdFedTrustTokenIssuerUriColor'>$tdFedTrustTokenIssuerUriFL</span></div>
    <div> <b>Certificate Expiry: </b> <span style='color:$tdFedTrustOrgCertificateNotAfterDateColor'>$tdFedTrustOrgCertificateNotAfterDateFL</span></div>
    <div> <b>Token Issuer Certificate Expiry: </b> <span style='color:$tdFedTrustTokenIssuerCertificateNotAfterDateTimeColor'>$tdFedTrustTokenIssuerCertificateNotAfterDateTimeFL</span></div>
    <div> <b>Token Issuer Metadata EPR:</b> <span style='color:$tdFedTrustTokenIssuerMetadataEprAbsoluteUriColor'>$tdFedTrustTokenIssuerMetadataEprAbsoluteUriFL</span></div>
    <div> <b>Token Issuer EPR: </b> <span style='color:$tdFedTrustTokenIssuerEprAbsoluteUriColor'>$tdFedTrustTokenIssuerEprAbsoluteUriFL</span></div>

</td>
</tr>
"
    $html | Out-File -FilePath $htmlFile
}
function AvailabilityAddressSpaceHtml() {
    $script:html += "
  <tr>
  <th ColSpan='2' style='color:white;'>Summary - On-Premise Get-AvailabilityAddressSpace</th>
  </tr>
  <tr>
  <td><b> Get-AvailabilityAddressSpace $ExchangeOnlineDomain | fl ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name</b></td>
  <td>
  <div> <b>Forest Name: </b> $tdAvailabilityAddressSpaceForestName</div>
  <div> <b>Name: </b> $tdAvailabilityAddressSpaceName</div>
  <div> <b>UserName: </b> <span style='color:$tdAvailabilityAddressSpaceUserNameColor'>$tdAvailabilityAddressSpaceUserName</span></div>
  <div> <b>Access Method: </b> <span style='color:$tdAvailabilityAddressSpaceAccessMethodColor'>$tdAvailabilityAddressSpaceAccessMethod</span></div>
  <div> <b>ProxyUrl: </b> <span style='color:$tdAvailabilityAddressSpaceProxyUrlColor'>$tdAvailabilityAddressSpaceProxyUrl</span></div>
  </td>
  </tr>"
    $html | Out-File -FilePath $htmlFile
}
function autoDVDHtmlOK() {
    $script:html +=
    "<tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
  </tr>
  <tr>
  <td><b>Get-AutoDiscoverVirtualDirectory | Select Identity,Name,ExchangeVersion,*authentication*</b></td>
  <td>
  <div><b>============================</b></div>
  <div><b>Identity:</b> $AutoD_VD_Identity</div>
  <div><b>Name:</b> $AutoD_VD_Name </div>
  <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
  <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
  <div><b>WSAuthentication:</b> <span style='color:green'>$AutoD_VD_WSAuthentication</span></div>
  <div><b>WindowsAuthentication:</b> <span style='color:green'>$AutoD_VD_WindowsAuthentication</span></div>
  "
    $html | Out-File -FilePath $htmlFile
}
function autoDVDHtmlNotOK() {
    $script:html +=
    "<tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
  </tr>
  <tr>
  <td><b>Get-AutoDiscoverVirtualDirectory | Select Identity,Name,ExchangeVersion,*authentication*</b></td>
  <td>
  <div><b>============================</b></div>
  <div><b>Identity:</b> $AutoD_VD_Identity</div>
  <div><b>Name:</b> $AutoD_VD_Name </div>
  <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
  <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
  <div><b>WSAuthentication:</b> <span style='color:green'>$AutoD_VD_WSAuthentication</span></div>
  <div><b>WindowsAuthentication:</b> <span style='color:green'>$AutoD_VD_WindowsAuthentication</span></div>
  "
    $html | Out-File -FilePath $htmlFile
}
function EWSVirtualDHeaderHtml() {
    $script:html += "
  <tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-WebServicesVirtualDirectory</th>
  </tr>
  <tr>
  <td><b> Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url</b></td>
  <td >"
}
function EwsVDHtmlOK() {
    $script:html +=
    " <div><b>============================</b></div>
  <div><b>Identity:</b> $EwsVDIdentity</div>
  <div><b>Name:</b> $EwsVDName </div>
  <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
  <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
  <div><b>WSAuthentication:</b> <span style='color:green'>$EwsVD_WSAuthentication</span></div>
  <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
  <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
  <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>
  </td>
  </tr>  "
    $html | Out-File -FilePath $htmlFile
}
function EwsVDHtmlNotOK() {
    $script:html +=
    " <div><b>============================</b></div>
    <div><b>Identity:</b> $EwsVDIdentity</div>
    <div><b>Name:</b> $EwsVDName </div>
    <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
    <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
    <div><b>WSAuthentication:</b> <span style='color:red'>$EwsVD_WSAuthentication</span></div>
    <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
    <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
    <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>
    </td>
    </tr>  "
    $html | Out-File -FilePath $htmlFile
}
function TestOrgRelHtmlOK() {
    $Script:html += "<tr>
  <th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
  </tr>
  <tr>
  <td><b>Test-OrganizationRelationship -Identity $OrgRelIdentity  -UserIdentity $UserOnPrem</b></td>
  <td>
  <div class='green'> <b>No Significant Issues to Report</b><div>"
}
function TestOrgRelHtmlNotOK() {
    $Script:html += "<tr>
  <th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
  </tr>
  <tr>
  <td><b>Test-OrganizationRelationship -Identity $OrgRelIdentity  -UserIdentity $UserOnPrem</b></td>
  <td>
  <div class='red'> <b>Test Organization Relationship Completed with errors</b><div>"
}
function TestOrgRelHtmlNoUri() {
    $Script:html += "
  <tr>
  <th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
  </tr>
  <tr>
  <td><b>Test-OrganizationRelationship</b></td>
  <td>
  <div class='red'> <b> Test-OrganizationRelationship can't be run if the Organization Relationship Target Application uri is not correct. Organization Relationship Target Application Uri should be Outlook.com</b><div>"
}
#On Prem OAuth
function IntraOrgConCheckHtml() {
    # Build HTML table row
    if ($Auth -like "OAuth") {
        $Script:html += "
      <div class='Black'><p></p></div>
      <div class='Black'><h2><b>`n Exchange On Premise Free Busy Configuration: `n</b></h2></div>
      <div class='Black'><p></p></div>"
    }
    $Script:html += "
    <table style='width:100%'>
    <tr>
    <th ColSpan='2' style='text-align:center; color:white;'>Exchange On Premise OAuth Configuration</th>
    </tr>
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-IntraOrganizationConnector</th>
    </tr>
    <tr>
    <td><b>Get-IntraOrganizationConnector:</b></td>
    <td>
      <div><b>TarGet Address Domains:</b><span style='color: $tdIntraOrgTarGetAddressDomainColor'>$($tdIntraOrgTarGetAddressDomain)</span></div>
      <div><b>Discovery Endpoint:</b><span style='color: $tdDiscoveryEndpointColor;'>$($tdDiscoveryEndpoint)</span></div>
      <div><b>Enabled:</b><span style='color: $tdEnabledColor;'>$($tdEnabled)</span></div>
    </td>
    </tr>
    "
    $html | Out-File -FilePath $htmlFile
}
function AuthServerCheckHtml() {
    $Script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-AuthServer</th>
    </tr>
    <tr>
      <td><b> Get-AuthServer | Select Name,IssuerIdentifier,TokenIssuingEndpoint,AuthMetadatAUrl,Enabled</b></td>
      <td>
        <div><b>IssuerIdentifier:</b><span style='color: $tDAuthServerIssuerIdentifierColor'>$($tDAuthServerIssuerIdentifier)</span></div>
        <div><b>TokenIssuingEndpoint:</b><span style='color: $tDAuthServerTokenIssuingEndpointColor;'>$($tDAuthServerTokenIssuingEndpoint)</span></div>
        <div><b>AuthMetadatAUrl:</b><span style='color: $tDAuthServerAuthMetadatAUrlColor;'>$($tDAuthServerAuthMetadatAUrl)</span></div>
        <div><b>Enabled:</b><span style='color: $tDAuthServerEnabledColor;'>$($tDAuthServerEnabled)</span></div>
      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function PartnerApplicationCheckHtml() {
    $Script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-PartnerApplication</th>
    </tr>
    <tr>
      <td><b> Get-PartnerApplication |  ?{`$_.ApplicationIdentifier -eq '00000002-0000-0ff1-ce00-000000000000'
    -and `$_.Realm -eq ''} | Select Enabled, ApplicationIdentifier, CertificateStrings, AuthMetadatAUrl, Realm, UseAuthServer,
    AcceptSecurityIdentifierInformation, LinkedAccount, IssuerIdentifier, AppOnlyPermissions, ActAsPermissions, Name</b></td>
      <td>
        <div><b>Enabled:</b><span style='color: $tdPartnerApplicationEnabledColor'>$($tdPartnerApplicationEnabled)</span></div>
        <div><b>ApplicationIdentifier:</b><span style='color: $tdPartnerApplicationApplicationIdentifierColor;'>$($tdPartnerApplicationApplicationIdentifier)</span></div>
        <div><b>CertificateStrings:</b><span style='color: $tdPartnerApplicationCertificateStringsColor;'>$($tdPartnerApplicationCertificateStrings)</span></div>
        <div><b>AuthMetadatAUrl:</b><span style='color: $tdPartnerApplicationAuthMetadatAUrlColor;'>$($tdPartnerApplicationAuthMetadatAUrl)</span></div>
        <div><b>Realm:</b><span style='color: $tdPartnerApplicationRealmColor'>$($tdPartnerApplicationRealm)</span></div>
        <div><b>LinkedAccount:</b><span style='color: $tdPartnerApplicationLinkedAccountColor;'>$($tdPartnerApplicationLinkedAccount)</span></div>
        <div><b>IssuerIdentifier:</b><span style='color: $tdPartnerApplicationEnabledColor'>$($tdPartnerApplicationEnabled)</span></div>
        <div><b>AppOnlyPermissions:</b><span style='color: $tdPartnerApplicationApplicationIdentifierColor;'>$($tdPartnerApplicationApplicationIdentifier)</span></div>
        <div><b>ActAsPermissions:</b><span style='color: $tdPartnerApplicationCertificateStringsColor;'>$($tdPartnerApplicationCertificateStrings)</span></div>
        <div><b>Name:</b><span style='color: $tdPartnerApplicationAuthMetadatAUrlColor;'>$($tdPartnerApplicationAuthMetadatAUrl)</span></div>
      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function ApplicationAccountCheckHtml() {
    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-User ApplicationAccount</th>
    </tr>
    <tr>
      <td><b>  Get-user '$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount' | Select Name, RecipientType, RecipientTypeDetails, UserAccountControl':</b></td>
      <td>
        <div><b>RecipientType:</b><span style='color: $tdApplicationAccountRecipientTypeColor'>$($tdApplicationAccountRecipientType)</span></div>
        <div><b>RecipientTypeDetails:</b><span style='color: $tdApplicationAccountRecipientTypeDetailsColor;'>$($tdApplicationAccountRecipientTypeDetails)</span></div>
        <div><b>UserAccountControl:</b><span style='color: $tdApplicationAccountUserAccountControlColor;'>$($tdApplicationAccountUserAccountControl)</span></div>

      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function ManagementRoleAssignmentCheckHtml() {
    $Script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-ManagementRoleAssignment</th>
  </tr>
  <tr>
    <td><b>  Get-ManagementRoleAssignment -RoleAssignee Exchange Online-ApplicationAccount | Select Name,Role</b></td>
    <td>
      <div><b>UserApplication Role:</b><span style='color: $tdManagementRoleAssignmentUserApplicationColor'>$($tdManagementRoleAssignmentUserApplication)</span></div>
      <div><b>ArchiveApplication Role:</b><span style='color: $tdManagementRoleAssignmentArchiveApplicationColor;'>$($tdManagementRoleAssignmentArchiveApplication)</span></div>
      <div><b>LegalHoldApplication Role:</b><span style='color: $tdManagementRoleAssignmentLegalHoldApplicationColor;'>$($tdManagementRoleAssignmentLegalHoldApplication)</span></div>
      <div><b>Mailbox Search Role:</b><span style='color: $tdManagementRoleAssignmentMailboxSearchColor'>$($tdManagementRoleAssignmentMailboxSearch)</span></div>
      <div><b>TeamMailboxLifecycleApplication Role:</b><span style='color: $tdManagementRoleAssignmentTeamMailboxLifecycleApplicationColor;'>$($tdManagementRoleAssignmentTeamMailboxLifecycleApplication)</span></div>
      <div><b>MailboxSearchApplication Role:</b><span style='color: $tdManagementRoleMailboxSearchApplicationColor;'>$($tdManagementRoleMailboxSearchApplication)</span></div>
      <div><b>MeetingGraphApplication Role:</b><span style='color: $tdManagementRoleMeetingGraphApplicationColor;'>$($tdManagementRoleMeetingGraphApplication)</span></div>
    </td>
  </tr>
"
    $html | Out-File -FilePath $htmlFile
}
function AuthConfigCheckHtml() {
    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-AuthConfig</th>
    </tr>
    <tr>
      <td><b>  Get-AuthConfig | Select-Object *Thumbprint, ServiceName, Realm, Name</b></td>
      <td>
        <div><b>Name:</b><span >$($tDAuthConfigName)</span></div>
        <div><b>Thumbprint:</b><span style='color: $tDAuthConfigCurrentCertificateThumbprintColor'>$($tDAuthConfigCurrentCertificateThumbprint)</span></div>
        <div><b>ServiceName:</b><span style='color:$tDAuthConfigServiceNameColor;'>$( $tDAuthConfigServiceName)</span></div>
        <div><b>Realm:</b><span style='color: $tDAuthConfigRealmColor;'>$($tDAuthConfigRealm)</span></div>
      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function CurrentCertificateThumbprintCheckHtml() {
    $Script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-ExchangeCertificate AuthCertificate</th>
  </tr>
  <tr>
    <td><b>  Get-ExchangeCertificate $thumb.CurrentCertificateThumbprint | Select-Object *</b></td>
    <td>
      <div><b>Issuer:</b><span style='color: $tdCurrentCertificateIssuerColor'>$($tdCurrentCertificateIssuer)</span></div>
      <div><b>Services:</b><span style='color: $tdCurrentCertificateServicesColor'>$($tdCurrentCertificateServices)</span></div>
      <div><b>Status:</b><span style='color:$tdCurrentCertificateStatusColor;'>$( $tdCurrentCertificateStatus)</span></div>
      <div><b>Subject:</b><span style='color: $tdCurrentCertificateSubjectColor;'>$($tdCurrentCertificateSubject)</span></div>
      <div><b>Distribution:</b><span style='color: $tdCheckAuthCertDistributionColor;'>$($tdCheckAuthCertDistribution)</span></div>
    </td>
  </tr>
"
    $html | Out-File -FilePath $htmlFile
}
function OAuthConnectivityCheckHtml() {
    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Test-OAuthConnectivity</th>
    </tr>
    <tr>
      <td><b>  Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $UserOnPrem | fl</b></td>
      <td>
        <div><b>Result:</b><span style='color: $OAuthConnectivityResultTypeColor'> $OAuthConnectivityResultType</span></div>
      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function AvailabilityAddressSpaceCheckOAuth() {
    Write-Host -ForegroundColor Green " Get-AvailabilityAddressSpace $ExchangeOnlineDomain | Select ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name"
    PrintDynamicWidthLine
    $AvailabilityAddressSpace = Get-AvailabilityAddressSpace $ExchangeOnlineDomain | Select-Object ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name
    $AAS = $AvailabilityAddressSpace | Format-List
    $AAS
    if ($Auth -contains "OAuth") {
    }
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - On-Prem Availability Address Space"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " ForestName: "
    if ($AvailabilityAddressSpace.ForestName -like $ExchangeOnlineDomain) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red " ForestName is NOT correct. "
        Write-Host -ForegroundColor White " Should be $ExchangeOnlineDomain "
        $tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestNameColor = "red"
    }
    Write-Host -ForegroundColor White " UserName: "
    if ($AvailabilityAddressSpace.UserName -like "") {
        Write-Host -ForegroundColor Green "  Blank "
        $tdAvailabilityAddressSpaceUserName = "  Blank. This is the correct value. "
        $tdAvailabilityAddressSpaceUserNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UserName is NOT correct. "
        Write-Host -ForegroundColor White "  Should be blank "
        $tdAvailabilityAddressSpaceUserName = "  Blank. This is the correct value. "
        $tdAvailabilityAddressSpaceUserNameColor = "red"
    }
    Write-Host -ForegroundColor White " UseServiceAccount: "
    if ($AvailabilityAddressSpace.UseServiceAccount -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $tdAvailabilityAddressSpaceUseServiceAccount = $AvailabilityAddressSpace.UseServiceAccount
        $tdAvailabilityAddressSpaceUseServiceAccountColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UseServiceAccount is NOT correct."
        Write-Host -ForegroundColor White "  Should be True "
        $tdAvailabilityAddressSpaceUseServiceAccount = "$($tAvailabilityAddressSpace.UseServiceAccount). Should be True"
        $tdAvailabilityAddressSpaceUseServiceAccountColor = "red"
    }
    Write-Host -ForegroundColor White " AccessMethod: "
    if ($AvailabilityAddressSpace.AccessMethod -like "InternalProxy") {
        Write-Host -ForegroundColor Green "  InternalProxy "
        $tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $tdAvailabilityAddressSpaceAccessMethodColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  AccessMethod is NOT correct. "
        Write-Host -ForegroundColor White "  Should be InternalProxy "
        $tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $tdAvailabilityAddressSpaceAccessMethodColor = "red"
    }
    Write-Host -ForegroundColor White " ProxyUrl: "
    if ($AvailabilityAddressSpace.ProxyUrl -like $exchangeOnPremEWS) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrlColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ProxyUrl is NOT correct. "
        Write-Host -ForegroundColor White "  Should be $exchangeOnPremEWS"
        $tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrlColor = "red"
    }
    AvailabilityAddressSpaceCheckOAuthHtml
}
function  AvailabilityAddressSpaceCheckOAuthHtml() {
    $Script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-AvailabilityAddressSpace</th>
  </tr>
  <tr>
    <td><b>  Get-AvailabilityAddressSpace $ExchangeOnlineDomain | Select ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name</b></td>
    <td>
      <div><b>AddressSpaceForestName:</b><span style='color: $tdAvailabilityAddressSpaceForestNameColor'>$($tdAvailabilityAddressSpaceForestName)</span></div>
      <div><b>AddressSpaceUserName:</b><span style='color: $tdAvailabilityAddressSpaceUserNameColor'>$($tdAvailabilityAddressSpaceUserName)</span></div>
      <div><b>UseServiceAccount:</b><span style='color:$tdAvailabilityAddressSpaceUseServiceAccountColor;'>$( $tdAvailabilityAddressSpaceUseServiceAccount)</span></div>
      <div><b>AccessMethod:</b><span style='color: $tdAvailabilityAddressSpaceAccessMethodColor;'>$($tdAvailabilityAddressSpaceAccessMethod)</span></div>
      <div><b>ProxyUrl:</b><span style='color: $tdAvailabilityAddressSpaceProxyUrlColor;'>$($tdAvailabilityAddressSpaceProxyUrl)</span></div>
    </td>
  </tr>
"
    $html | Out-File -FilePath $htmlFile
}
function AutoDVirtualDCheckOauthHtmlHead() {
    $script:html += "<tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
    </tr>
    <tr>
    <td><b>Get-AutoDiscoverVirtualDirectory:</b></td>
    <td>"
    $html | Out-File -FilePath $htmlFile
}
function  AutoDVirtualDCheckOauthHtmlOk() {
    $script:html +=
    " <div><b>============================</b></div>
            <div><b>Identity:</b> $AutoD_VD_Identity</div>
            <div><b>Name:</b> $AutoD_VD_Name </div>
            <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:green'>$AutoD_VD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:green'>$AutoD_VD_WindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$AutoD_VD_OAuthAuthenticationColor'>$AutoD_VD_OAuthAuthentication</span></div>
            "
    $html | Out-File -FilePath $htmlFile
}
function  AutoDVirtualDCheckOauthHtmlNotOk() {
    $script:html +=
    " <div><b>============================</b></div>
            <div><b>Identity:</b> $AutoD_VD_Identity</div>
            <div><b>Name:</b> $AutoD_VD_Name </div>
            <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:red'>$AutoD_VD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$AutoD_VD_WindowsAuthenticationColor'>$AutoD_VD_WindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$AutoD_VD_OAuthAuthenticationColor'>$AutoD_VD_OAuthAuthentication</span></div>
            "
    $html | Out-File -FilePath $htmlFile
}
function EWSVirtualDirectoryCheckOAuthHtmlHead() {
    $script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-WebServicesVirtualDirectory</th>
    </tr>
    <tr>
    <td><b>Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url</b></td>
    <td >"
    $html | Out-File -FilePath $htmlFile
}
function  EWSVirtualDirectoryCheckOAuthHtmlOk() {
    $script:html +=
    " <div><b>============================</b></div>
            <div><b>Identity:</b> $EwsVDIdentity</div>
            <div><b>Name:</b> $EwsVDName </div>
            <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:green'>$EwsVD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$EwsVDW_OAuthAuthenticationColor'>$EwsVDOAuthAuthentication</span></div>
            <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
            <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>  "
    $html | Out-File -FilePath $htmlFile
}
function  EWSVirtualDirectoryCheckOAuthHtmlNotOk() {
    $script:html +=
    " <div><b>============================</b></div>
            <div><b>Identity:</b> $EwsVDIdentity</div>
            <div><b>Name:</b> $EwsVDName </div>
            <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:red'>$EwsVD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$EwsVDW_OAuthAuthenticationColor'>$EwsVDOAuthAuthentication</span></div>
            <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
            <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>  "
    $html | Out-File -FilePath $htmlFile
}
#Exo HTML DAuth output
function ExoOrgRelCheckHtml() {
    $script:html += "
  <div class='Black'><p></p></div>
  <div class='Black'><p></p></div>
   <tr>
      <th ColSpan='2' style='text-align:center; color:white;'>Exchange Online DAuth Configuration</th>
   </tr>
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-OrganizationRelationship</th>
  </tr>
  <tr>
    <td><b>  Get-OrganizationRelationship  | Where{($_.DomainNames -like $ExchangeOnPremDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled</b></td>
    <td>
      <div><b>Domain Names:</b><span >$($tdEXOOrgRelDomainNames)</span></div>
      <div><b>FreeBusyAccessEnabled:</b><span style='color: $tdEXOOrgRelFreeBusyAccessEnabledColor'>$($tdEXOOrgRelFreeBusyAccessEnabled)</span></div>
      <div><b>FreeBusyAccessLevel::</b><span style='color:$tdEXOOrgRelFreeBusyAccessLevelColor;'>$( $tdEXOOrgRelFreeBusyAccessLevel)</span></div>
      <div><b>TarGetApplicationUri:</b><span style='color: $tdEXOOrgRelTarGetApplicationUriColor;'>$($tdEXOOrgRelTarGetApplicationUri)</span></div>
      <div><b>TarGetOwAUrl:</b><span >$($tdEXOOrgRelTarGetOwAUrl)</span></div>
      <div><b>TarGetSharingEpr:</b><span style='color: $tdEXOOrgRelTarGetSharingEprColor'>$($tdEXOOrgRelTarGetSharingEpr)</span></div>
      <div><b>TarGetAutoDiscoverEpr:</b><span style='color:$tdEXOOrgRelFreeBusyAccessScopeColor;'>$( $tdEXOOrgRelFreeBusyAccessScope)</span></div>
      <div><b>Enabled:</b><span style='color: $tdEXOOrgRelEnabledColor;'>$($tdEXOOrgRelEnabled)</span></div>
    </td>
  </tr>
"
    $html | Out-File -FilePath $htmlFile
}
function EXOFedOrgIdCheckHtml() {
    $script:html += "
<tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-FederatedOrganizationIdentifier</th>
</tr>
<tr>
  <td><b>  Get-FederatedOrganizationIdentifier | select AccountNameSpace,Domains,Enabled</b></td>
  <td>
    <div><b>Domains:</b><span style='color: $tdEXOFedOrgIdDomainsColor;'>$($tdEXOFedOrgIdDomains)</span></div>
    <div><b>Enabled:</b><span style='color: $tdEXOFedOrgIdEnabledColor;'>$($tdEXOFedOrgIdEnabled)</span></div>
  </td>
</tr>
"
    $html | Out-File -FilePath $htmlFile
}
function SharingPolicyCheckHtml() {
    $script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-SharingPolicy</th>
    </tr>
    <tr>
      <td><b>  Get-SharingPolicy | select Domains,Enabled,Name,Identity</b></td>
      <td>
        <div><b>Exchange On Premises Sharing domains:</b></div>
        <div><b>Domain:</b>$($SPOnprem.Domains.Domain[0])</div>
        <div><b>Action:</b>$($SPOnprem.Domains.Actions[0])</div>
        <div><b>Domain:</b>$($SPOnprem.Domains.Domain[1])</div>
        <div><b>Action:</b>$($SPOnprem.Domains.Actions[1])</div>
        <div><p></p></div>
        <div><b>Exchange Online Sharing domains:</b></div>
        <div><b>Domain:</b>$($domain1[0])</div>
        <div><b>Action:</b>$( $domain1[1])</div>
        <div><b>Domain:</b>$($domain2[0])</div>
        <div><b>Action:</b>$( $domain2[1])</div>
        <div><p></p></div>
        <div><b>Sharing Policy - Exchange Online vs Exchange On Premise:</b></div>
        <div><span style='color: $tdSharpingPolicyCheckColor;'>$($tdSharpingPolicyCheck)</span></div>
      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function ExoTestOrgRelCheckHtml() {
    $exoIdentity = $ExoOrgRel.Identity
    $exoOrgRelTarGetApplicationUri = $exoOrgRel.TarGetApplicationUri
    $exoOrgRelTarGetOWAUrl = $ExoOrgRel.TarGetOwAUrl
    $script:html += "
      <tr>
          <th ColSpan='2' style='color:white;'>Summary - Test-OrganizationRelationship</th>
      </tr>
      <tr>
          <td><b>  Test-OrganizationRelationship -Identity $exoIdentity -UserIdentity $UserOnline</b></td>
      <td>"
    if ((![string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and (![string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl))) {
        $i = 2
        while ($i -lt $ExoTestOrgRel.Length) {
            $element = $ExoTestOrgRel[$i]
            $aux = "0"
            if ($element -like "*RESULT:*" -and $aux -like "0") {
                $el = $element.TrimStart()
                if ($element -like "*Success.*") {
                    $Script:html += "
                  <div> <b> $ExoTestOrgRelStep </b> <span style='color:green'> $el</span>"
                    $aux = "1"
                } elseif ($element -like "*Error*" -or $element -like "*Unable*") {
                    $Script:html += "
                  <div> <b> $ExoTestOrgRelStep </b> <span style='color:red'> $el</span>"
                    $aux = "1"
                }
            } elseif ($aux -like "0" ) {
                if ($element -like "*STEP*" -or $element -like "*Complete*") {
                    $Script:html += "
                  <p></p>
                  <div> <b> $ExoTestOrgRelStep </b> <span style='color:black'> $element</span></div>"
                    $aux = "1"
                } else {
                    $ID = $element.ID
                    $Status = $element.Status
                    $Description = $element.Description
                    if (![string]::IsNullOrWhitespace($ID)) {
                        $Script:html += "<div> <b>ID: </b> <span style='color:black'> $ID</span></div>"
                        if ($Status -like "*Success*") {
                            $Script:html += "<div> <b>Status:</b> <span style='color:green'> $Status</span></div>"
                        }

                        if ($status -like "*error*") {
                            $Script:html += "<div> <b>Status:</b> <span style='color:red'> $Status</span></div>"
                        }

                        $Script:html += "<div> <b>Description: </b> <span style='color:black'> $Description</span></div>
                      <div><span style='color:blue'>Note: Test-Organization Relationship fails on Step 3 with error MismatchedFederation if Hybrid Agent is in use</span></div>"
                    }
                    #$element
                    $aux = "1"
                }
            }
            $i++
        }
    }

    elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and ([string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl)))) {
        $Script:html += "
      <div> <span style='color:red'> Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri and TarGetOwAUrl are not set</span>"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        $Script:html += "
      <div> <span style='color:red'> Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set</span>"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        $Script:html += "
      <div> <span style='color:red'> Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set</span>"
    }
    $Script:html += "</td>
  </tr>"
    $html | Out-File -FilePath $htmlFile
}
#Exo Oauth Functions
function EXOIntraOrgConCheckHtml() {
    $script:html += "
  <tr>
    <th ColSpan='2' style='text-align:center; color:white;'><b>Exchange Online OAuth Configuration</b></th>
  </tr>
  <tr>
    <th ColSpan='2' style=' color:white;'><b>Summary - Get-IntraOrganizationConnector</b></th>
  </tr>
  <tr>
    <td><b>  Get-IntraOrganizationConnector | Select-Object TarGetAddressDomains, DiscoveryEndpoint, Enabled</b></td>
    <td>
      <div><b>TarGet Address Domains:</b><span style='color: $tdEXOIntraOrgConTarGetAddressDomainsColor;'>' $($tdEXOIntraOrgConTarGetAddressDomains)'</span></div>
      <div><b>DiscoveryEndpoint:</b><span style='color: $tdEXOIntraOrgConDiscoveryEndpointsColor;'>' $($tdEXOIntraOrgConDiscoveryEndpoints)'</span></div>
      <div><b>Enabled:</b><span style='color:$tdEXOIntraOrgConEnabledColor;'> $($tdEXOIntraOrgConEnabled)</span></div>
    </td>
  </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function EXOIntraOrgConfigCheckHtml() {
    $script:html += "
    <tr>
      <th ColSpan='2' style=color:white;'><b>Summary - Get-IntraOrganizationConfiguration</b></th>
    </tr>
    <tr>
      <td><b>  Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses</b></td>
      <td>
        <div><b>OnPremiseTarGetAddresses:</b><span style='color: $tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor;'>$($tdEXOIntraOrgConfigOnPremiseTarGetAddresses)</span></div>
      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function EXOAuthServerCheckHtml() {
    $script:html += "
<tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-AuthServer</th>
</tr>
<tr>
  <td><b>  Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | select name,IssuerIdentifier,enabled</b></td>
  <td>
    <div><b>Name:</b><span style='color: $tdEXOAuthServerNameColor;'>$($tdEXOAuthServerName)</span></div>
    <div><b>IssuerIdentifier:</b><span style='color: $tdEXOAuthServerIssuerIdentifierColor;'>$($tdEXOAuthServerIssuerIdentifier)</span></div>
    <div><b>Enabled:</b><span style='color: $tdEXOAuthServerEnabledColor;'>$($tdEXOAuthServerEnabled)</span></div>
  </td>
</tr>
"
    $html | Out-File -FilePath $htmlFile
}
function ExoTestOAuthCheckHtml() {
    $script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'><b>Summary - Test-OAuthConnectivity</b></th>
    </tr>
    <tr>
      <td><b>  Test-OAuthConnectivity -Service EWS -TarGetUri $($Script:ExchangeOnPremEWS) -Mailbox $UserOnline </b></td>
      <td>
        <div><b>Result:</b><span style='color: $tdOAuthConnectivityResultTypeColor;'>$($tdOAuthConnectivityResultType)</span></div>
      </td>
    </tr>
  "
    $html | Out-File -FilePath $htmlFile
}
function lookupMethodDAuthHtml() {
    $Script:html += "
                        <div  style = 'padding-left: 0%;'>
                          <h3>Intra Organization Connector Enabled: <b>True</b></h3>
                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking DAuth only as -Auth DAuth option was selected</span></p>
                        </div>
                        <div  style = 'padding-left: 0%;'>
                          <ul>
                            <li>
                              This script can be run using the <b>-Auth OAuth</b> parameter to Check for DAuth configurations only.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth
                              </span>
                            </li>
                            <br />
                            <li>
                              This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "
    $html | Out-File -FilePath $htmlFile
}
function lookupMethodOauthHtml() {
    $Script:html += "
      <div  style = 'padding-left: 0%;'>
        <h3>Intra Organization Connector Enabled: <b>True</b></h3>
        <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking OAuth only as Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled</span></p>
      </div>
      <div  style = 'padding-left: 0%;'>
        <ul>
          <li>
            This script can be run using the <b>-Auth DAuth</b> parameter to Check for DAuth configurations only.
            <br />
            <span style='padding-left: 2%;'>
              <br />
              <b>Example:</b> ./FreeBusyChecker.ps1 -Auth DAuth
            </span>
          </li>
          <br />
          <li>
            This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
            <br />
            <span style='padding-left: 2%;'>
              <br />
              <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
            <span style='padding:2%;'>
          </li>
        </ul>
      </div>
"
    $html | Out-File -FilePath $htmlFile
}
function lookupMethodCheckAllHtml() {
    $Auth = ""
    Write-Host -ForegroundColor White "    -> Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled"
    Write-Host -ForegroundColor White "    -> Checking both OAuth and DAuth as -Auth All option was selected"
    $Script:html += "
                  <div  style = 'padding-left: 0%;'>
                    <h3>Intra Organization Connector Enabled: <b>True</b></h3>
                    <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking both OAuth and DAuth as -Auth All option was selected</span></p>
                  </div>
                  <div  style = 'padding-left: 0%;'>
                    <ul>
                      <li>
                        This script can be run using the <b>-Auth DAuth</b> parameter to Check for DAuth configurations only.
                        <br />
                        <span style='padding-left: 2%;'>
                          <br />
                          <b>Example:</b> ./FreeBusyChecker.ps1 -Auth DAuth
                        </span>
                      </li>
                      <br />
                      <li>
                        This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                        <br />
                        <span style='padding-left: 2%;'>
                          <br />
                          <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                        <span style='padding:2%;'>
                      </li>
                    </ul>
                  </div>
"
    $html | Out-File -FilePath $htmlFile
}
function lookupMethodDAuthOauthDisabledHtml() {
    $Script:html += "
                        <div  style = 'padding-left: 0%;'>
                          <h3>Intra Organization Connector Enabled: <b>False</b></h3>
                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking DAuth as OAuth is not Enabled</span></p>
                        </div>
                        <div  style = 'padding-left: 0%;'>
                          <ul>
                            <li>
                              This script can be run using the <b>-Auth OAuth</b> parameter to Check for OAuth configurations only.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth
                              </span>
                            </li>
                            <br />
                            <li>
                              This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "
    $html | Out-File -FilePath $htmlFile
}
function lookupMethodOauthOauthDisabledHtml() {
    $Script:html += "
                      <div  style = 'padding-left: 0%;'>
                        <h3>Intra Organization Connector Enabled: <b>False</b></h3>
                        <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking OAuth as -Auth OAuth parameter was selected</span></p>
                      </div>
                      <div  style = 'padding-left: 0%;'>
                        <ul>
                          <li>
                            This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                            <br />
                            <span style='padding-left: 2%;'>
                              <br />
                              <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                            <span style='padding:2%;'>
                          </li>
                        </ul>
                      </div>
  "
    $html | Out-File -FilePath $htmlFile
}
function lookupMethodAllOauthDisabledHtml() {
    $Script:html += "
                  <div  style = 'padding-left: 0%;'>
                    <h3>Intra Organization Connector Enabled: <b>False</b></h3>
                    <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking both for OAuth and DAuth as -Auth All parameter was selected</span></p>
                  </div>
                  <div  style = 'padding-left: 0%;'>
                    <ul>
                      <li>
                        This script can be run using the <b>-Auth OAuth</b> parameter to Check for OAuth only.
                        <br />
                        <span style='padding-left: 2%;'>
                          <br />
                          <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth
                        <span style='padding:2%;'>
                      </li>
                    </ul>
                  </div>
"
    $html | Out-File -FilePath $htmlFile
}
function exoHeaderHtml() {
    $Script:html += "
     </table>
      <div class='Black'><p></p></div>
      <div class='Black'><p></p></div>
             <div class='Black'><h2><b>`n Exchange Online Free Busy Configuration: `n</b></h2></div>
             <div class='Black'><p></p></div>
             <div class='Black'><p></p></div>
     <table style='width:100%; margin-top:30px;'>
    "
}
