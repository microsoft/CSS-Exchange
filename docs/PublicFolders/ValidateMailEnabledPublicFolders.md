# ValidateMailEnabledPublicFolders

Download the latest release: [ValidateMailEnabledPublicFolders.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ValidateMailEnabledPublicFolders.ps1)

This script performs pre-migration checks on mail-enabled folders on Exchange 2010 and up. Note that these checks are also included in the new SourceSideValidations.ps1 for 2013 and up.

## Syntax

```powershell
ValidateMailEnabledPublicFolders.ps1
  [-SkipVersionCheck]
  [<CommonParameters>]

ValidateMailEnabledPublicFolders.ps1
  -ScriptUpdateOnly
  [<CommonParameters>]
```

## Parameters

- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.
