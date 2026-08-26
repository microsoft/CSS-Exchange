# Move-PublicFolderBranch

Download the latest release: [Move-PublicFolderBranch.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Move-PublicFolderBranch.ps1)

## Syntax

```powershell
Move-PublicFolderBranch.ps1
  [-FolderRoot] <String>
  [-TargetPublicFolderMailbox] <String>
  [-OrganizationName <String>]
  [-WhatIf]
  [-SkipVersionCheck]
  [<CommonParameters>]

Move-PublicFolderBranch.ps1
  -ScriptUpdateOnly
  [<CommonParameters>]
```

## Parameters

- `-FolderRoot` (required): The public folder branch to move.
- `-TargetPublicFolderMailbox` (required): The target public folder mailbox where the contents need to go to.
- `-OrganizationName` (optional): Name of the organization.
- `-WhatIf` (optional): Shows what the script would do without making changes.
- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.

## Usage

For usage details, please see [Move a public folder to a different public folder mailbox](https://learn.microsoft.com/exchange/move-a-public-folder-to-a-different-public-folder-mailbox-exchange-2013-help).
