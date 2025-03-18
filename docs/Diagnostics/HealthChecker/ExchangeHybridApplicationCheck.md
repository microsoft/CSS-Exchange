# Dedicated Exchange Hybrid Application

When Microsoft Exchange Server is deployed in a hybrid configuration, features such as Free/Busy sharing, MailTips, and Profile pictures are made available between Exchange Server and Exchange Online. This configuration ensures a seamless user experience. These features are automatically configured the first time the Hybrid Configuration Wizard (HCW) runs.

To enable hybrid functionality, Exchange Server uses a shared service principal with Exchange Online for secure communication. However, this process will be revised in the near future as Exchange Server transitions from using the EWS API to the Microsoft Graph API for requesting data from Exchange Online. To prepare for this significant change, a configuration update will be required in your Exchange hybrid environment.

This check validates whether the so-called `dedicated Exchange hybrid application` is configured in your Exchange environment if Exchange hybrid was detected. See the [Additional Resources](#additional-resources) for more information about the feature and configuration instructions.

## Included in HTML Report?

Yes

## Additional resources

[Deploy dedicated Exchange hybrid app](https://aka.ms/ConfigureExchangeHybridApplication-Docs)

[Exchange Server Security Changes for Hybrid Deployments](https://techcommunity.microsoft.com/blog/exchange/exchange-server-security-changes-for-hybrid-deployments/4396833)

[Released: April 2025 Exchange Server Hotfix Updates](https://techcommunity.microsoft.com/blog/exchange/released-april-2025-exchange-server-hotfix-updates/4402471)
