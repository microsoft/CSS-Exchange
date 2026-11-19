# Import-MailPublicFolders

Download the latest release: [Import-MailPublicFolders.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Import-MailPublicFolders.ps1)

## Syntax

```powershell
Import-MailPublicFolders.ps1
  [-Credential <PSCredential>]
  [-ToCloud]
  [-ConnectionUri <String>]
  [-AzureADAuthorizationEndpointUri <String>]
  [-ScriptUpdateOnly]
  [-SkipVersionCheck]
  [<CommonParameters>]
```

## Parameters

- `-AzureADAuthorizationEndpointUri` (optional): Microsoft Entra authorization endpoint passed to `Connect-ExchangeOnline`. Use with the appropriate `-ConnectionUri` for your environment. When omitted, the module's default authorization endpoint is unchanged. Available during normal operation, not with `-ScriptUpdateOnly`.
- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.

## Usage

To override the Exchange Online endpoints, supply the connection and authorization URI values for your environment:

```powershell
.\Import-MailPublicFolders.ps1 -ToCloud -ConnectionUri $connectionUri -AzureADAuthorizationEndpointUri $authorizationEndpointUri
```

For usage details, please see [Configure Exchange Online public folders for a hybrid deployment | Microsoft Learn](https://learn.microsoft.com/en-us/exchange/collaboration-exo/public-folders/set-up-exo-hybrid-public-folders#configure-exchange-online-public-folders-for-a-hybrid-deployment).
