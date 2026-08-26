# ModernPublicFolderToMailboxMapGenerator

Download the latest release: [ModernPublicFolderToMailboxMapGenerator.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ModernPublicFolderToMailboxMapGenerator.ps1)

## Syntax

```powershell
ModernPublicFolderToMailboxMapGenerator.ps1
  [-MailboxSize] <Int64>
  [-MailboxRecoverableItemSize] <Int64>
  [-ImportFile] <String>
  [-ExportFile] <String>
  [-ScriptUpdateOnly]
  [-SkipVersionCheck]
  [<CommonParameters>]
```

## Parameters

- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.

## Usage

For usage details, please see [Batch migrate Exchange Server public folders to Microsoft 365 or Office 365 | Microsoft Learn](https://learn.microsoft.com/en-us/exchange/collaboration/public-folders/migrate-to-exchange-online?view=exchserver-2019).
