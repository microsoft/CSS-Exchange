# Exchange Online Connector Check

This is a simple check that can be performed from the Exchange On Prem side to quickly determine if the EXO connector is misconfigured. This does not completely determine if the connector is misconfigured, as Health Checker script is not designed to connect to Exchange Online to properly determine if everything is correctly configured for the way you want your mail flow to work. It does not take into account if you are routing your OnPrem mail through EXO to External domains and may flag the connector as not properly configured because `CloudServicesMailEnabled` is not set to `$true`. It is only here to check for Internal mail between OnPrem and your tenant EXO mailboxes.

A Send Connector is determined to be destined for Exchange Online if one of the following is true:

- SmartHost endpoint has a `*.mail.protection.outlook.com`
- AddressSpaces address has a `*.mail.onmicrosoft.com`

For those connectors, we then determine a misconfiguration if one of the following is true:

- TLSCertificateName is not set
- CloudServicesMailEnabled is not set to true

These are now being flagged as an issue due to some recent changes within Exchange Online.

Some additional configuration concerns are also warned about if one of the following is true:

- TLSAuthLevel is not set to `CertificateValidation` or `DomainValidation`
- TLSDomain is not set to `mail.protection.outlook.com` if TLSAuthLevel is set to `DomainValidation`

## Included in HTML Report?

Yes

## Additional resources

[Set up connectors to route mail between Microsoft 365 or Office 365 and your own email servers](https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail)

[Updated Requirements for SMTP Relay through Exchange Online](https://techcommunity.microsoft.com/t5/exchange-team-blog/updated-requirements-for-smtp-relay-through-exchange-online/ba-p/3851357)
