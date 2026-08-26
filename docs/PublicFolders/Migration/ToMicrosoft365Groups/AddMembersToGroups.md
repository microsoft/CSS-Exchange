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
  [-WhatIf]
  [-ScriptUpdateOnly]
  [-SkipVersionCheck]
  [<CommonParameters>]
```

## Parameters

- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.

## Usage

For usage details, please see [Migrate your public folders to Microsoft 365 Groups](https://learn.microsoft.com/exchange/collaboration/public-folders/migrate-to-microsoft-365-groups).
