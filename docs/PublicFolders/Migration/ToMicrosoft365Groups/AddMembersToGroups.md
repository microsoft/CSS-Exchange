# AddMembersToGroups

Download the latest release: [AddMembersToGroups.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/AddMembersToGroups.ps1)

## Syntax

```powershell
AddMembersToGroups.ps1
  -MappingCsv <String>
  -BackupDir <String>
  [-Credential <PSCredential>]
  [-ArePublicFoldersLocked <Boolean>]
  [-ArePublicFoldersOnPremises <Boolean>]
  [-ConnectionUri <String>]
  [-AzureADAuthorizationEndpointUri <String>]
  [-WhatIf]
  [-ScriptUpdateOnly]
  [-SkipVersionCheck]
  [<CommonParameters>]
```

## Parameters

- `-AzureADAuthorizationEndpointUri` (optional): Microsoft Entra authorization endpoint passed to `Connect-ExchangeOnline` when `-ArePublicFoldersOnPremises $true` creates a connection. Use with the appropriate `-ConnectionUri` for your environment. When omitted, the module's default authorization endpoint is unchanged. Available during normal operation, not with `-ScriptUpdateOnly`.
- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.

## Usage

To override the Exchange Online endpoints while migrating on-premises public folders, supply the connection and authorization URI values for your environment:

```powershell
.\AddMembersToGroups.ps1 -MappingCsv .\map.csv -BackupDir C:\PFToGroupMigration -ArePublicFoldersOnPremises $true -ConnectionUri $connectionUri -AzureADAuthorizationEndpointUri $authorizationEndpointUri
```

For public folders already in Exchange Online, connect with the required endpoints before running the script; these parameters do not change the caller's existing connection.

For usage details, please see [Migrate your public folders to Microsoft 365 Groups](https://learn.microsoft.com/exchange/collaboration/public-folders/migrate-to-microsoft-365-groups).
