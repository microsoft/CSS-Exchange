# Auth Certificate Check

## Description

The Auth Configuration and Auth Certificate are used by Microsoft Exchange server to enable server-to-server authentication using the `Open Authorization (OAuth)` protocol standard. The Auth Certificate is also used by several Exchange Server security features which makes it important to be valid and available on all servers (except Edge Transport Servers) within the organization.

An invalid Auth Certificate can lead to these and other issues:

- Access to OWA or ECP isn't working

- Management of your Exchange servers via Exchange Management Shell isn't working as expected

### What does the check do?

The HealthChecker script validates multiple configurations which are having a dependency to the Auth Certificate. The script will show you if the Auth Certificate which is configured, was found on the server against which the script is currently running. It will also highlight if the certificate has been expired.

HealthChecker will display the certificate, which is configured as the next Auth Certificate (if there is one) and the effective date from which it becomes available for use by the AuthAdmin servicelet (Auth Certificate rotation to ensure a smooth transition to a new one).

**Note:** It's required to run the Hybrid Configuration Wizard (HCW), if you are running an Exchange Server hybrid configuration and the primary Auth Certificate has been replaced by a new one.

## Included in HTML Report?

Yes

## Additional resources

[Maintain (rotate) the Exchange Server Auth Certificate](https://learn.microsoft.com/Exchange/plan-and-deploy/integration-with-sharepoint-and-skype/maintain-oauth-certificate?view=exchserver-2019)

[Replace the Auth Certificate if it has already expired or isn't available](https://learn.microsoft.com/exchange/troubleshoot/administration/cannot-access-owa-or-ecp-if-oauth-expired#resolution)

[Exchange OAuth authentication couldn't find the authorization certificate with thumbprint error when running Hybrid Configuration](https://learn.microsoft.com/exchange/troubleshoot/administration/exchange-oauth-authentication-could-not-find-the-authorization)

[MonitorExchangeAuthCertificate.ps1 script](https://aka.ms/MonitorExchangeAuthCertificate)
