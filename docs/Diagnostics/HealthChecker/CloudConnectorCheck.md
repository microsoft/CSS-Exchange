# Cloud Connector Check

This check performs testings against the Exchange Send- and Receive Connectors which are enabled for cloud usage if a hybrid configuration was detected. We run `Get-HybridConfiguration` to validate if hybrid has been configured for the environment.

A proper configured Send- and Receive Connector is important - especially in hybrid scenarios. A misconfigured connector can lead to multiple issues including broken tenant attribution and email classification (internal / anonymous) which can then lead to false-positive/false-negative.

We to make sure that the mail flow between Exchange on-premises and Exchange Online works as expected

If a Send Connector has the following setting set, it means that the connector is eligable for cloud mail usage:

- CloudServicesMailEnabled

If a Receive Connector has the following setting set, it means that the connector is eligable for cloud mail usage:

- TlsDomainCapabilities

We only perform testings for the Receive Connectors if:

- TransportRole is set to FrontendTransport

We run the following checks:

- Connector enabled check:
    - We show a yellow warning, if the connector is not enabled

- TlsCertificateName configuration check:
    - We check if TlsCertificateName has been set
    - We check if the certificate which is configured in TlsCertificateName exists on the server
    - If a certificate was configured and detected on the system, we then check if it expires within the next 60 days
    - If a certificate was configured, we compare it with the TlsCertificateName returned by `Get-HybridConfiguration`
    - If a certificate was configured, we check if the syntax is correct and not corrupt. Expected syntax: `<I>X.500Issuer<S>X.500Subject`

**Included in HTML Report?**

Yes

**Additional resources:**

[Certificate requirements for hybrid deployments](https://docs.microsoft.com/exchange/certificate-requirements)

[Demystifying and troubleshooting hybrid mail flow: when is a message internal?](https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-and-troubleshooting-hybrid-mail-flow-when-is-a/ba-p/1420838)