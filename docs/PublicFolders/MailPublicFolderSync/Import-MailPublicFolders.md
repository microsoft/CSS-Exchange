# Import-MailPublicFolders

Download the latest release: [Import-MailPublicFolders.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Import-MailPublicFolders.ps1)

## Syntax

```powershell
Import-MailPublicFolders.ps1
  [-Credential <PSCredential>]
  [-ToCloud]
  [-ConnectionUri <String>]
  [-ScriptUpdateOnly]
  [-SkipVersionCheck]
  [<CommonParameters>]
```

## Parameters

- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.

## Usage

For usage details, please see [Configure Exchange Online public folders for a hybrid deployment | Microsoft Learn](https://learn.microsoft.com/en-us/exchange/collaboration-exo/public-folders/set-up-exo-hybrid-public-folders#configure-exchange-online-public-folders-for-a-hybrid-deployment).
