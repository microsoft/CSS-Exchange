# PowerShell Serialization Payload Signing

## Description

Certificate-based signing of PowerShell Serialization Payload is a defense-in-depth security feature to prevent malicious manipulation of serialized data exchanged in Exchange Management Shell (EMS) sessions.

The Serialized Data Signing feature was introduced with the January 2023 Exchange Server Security Update (SU). It's available on Exchange Server 2013, Exchange Server 2016 and Exchange Server 2019 and enabled by default with the November 2023 Security Update.

The HealthChecker check validates that the feature is enabled on supported Exchange builds.

!!! success "Documentation Moved"

      This documentation has been moved to Microsoft Learn. Please read [Configure certificate signing of PowerShell serialization payloads in Exchange Server](https://learn.microsoft.com/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-serialization-payload-sign) for more information.

## Included in HTML Report?

Yes

## Additional resources

[Released: January 2023 Exchange Server Security Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-january-2023-exchange-server-security-updates/ba-p/3711808)

[Released: November 2023 Exchange Server Security Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-november-2023-exchange-server-security-updates/ba-p/3980209)

[MonitorExchangeAuthCertificate.ps1 script](https://aka.ms/MonitorExchangeAuthCertificate)
