# ManagePublicFolderPermissions

Download the latest release: [ManagePublicFolderPermissions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ManagePublicFolderPermissions.ps1)

This script exports or imports public folder client permissions to/from a CSV file.

- Use `-Export` to write permissions from public folders to CSV.
- Use `-Import` to apply permissions from CSV back to public folders.

The script is designed to be resilient for long-running operations:

- Export writes in batches and can resume by appending to an existing CSV.
- Import records progress to a sidecar progress file so reruns skip already-processed rows.

Environment|Support
-|-
Exchange Online|Supported
Exchange SE|Not Supported

## Syntax

```powershell
ManagePublicFolderPermissions.ps1
    -Export
    [-Folder <Object[]>]
    [-Mailbox <String>]
    [-File <String>]
    [-BatchSize <Int32>]
    [-WhatIf]
    [-Confirm]
    [<CommonParameters>]

ManagePublicFolderPermissions.ps1
    -Import
    -File <String>
    [-ReplaceExisting]
    [-OnlyModifyEmptyACLs]
    [-BatchSize <Int32>]
    [-WhatIf]
    [-Confirm]
    [<CommonParameters>]
```

## Prerequisites

- PowerShell 5.1
- `ExchangeOnlineManagement` module
- Connected Exchange Online session with rights to read/write public folder permissions

## Usage

Export all public folder permissions to a CSV:

```powershell
.\ManagePublicFolderPermissions.ps1 -Export -File PFPerms.csv
```

Export a specific subtree:

```powershell
Get-PublicFolder -Identity "\Finance" -Recurse -ResultSize Unlimited |
    .\ManagePublicFolderPermissions.ps1 -Export -File PFPerms.csv
```

Import permissions from CSV (do not overwrite existing matching entries):

```powershell
.\ManagePublicFolderPermissions.ps1 -Import -File PFPerms.csv
```

Import and replace existing differing permissions:

```powershell
.\ManagePublicFolderPermissions.ps1 -Import -File PFPerms.csv -ReplaceExisting
```

Import only into folders whose ACL currently contains only `Default` and `Anonymous`:

```powershell
.\ManagePublicFolderPermissions.ps1 -Import -File PFPerms.csv -OnlyModifyEmptyACLs
```

## Parameters

- `-Export` (required in Export set): Exports permissions to CSV.
- `-Folder` (optional, Export): Folder objects/identities from pipeline for targeted export.
- `-Mailbox` (optional, Export): Public folder mailbox identity. If omitted, script uses root public folder mailbox.
- `-Import` (required in Import set): Imports permissions from CSV.
- `-ReplaceExisting` (optional, Import): Removes and re-adds permissions when an existing entry differs from the CSV.
- `-OnlyModifyEmptyACLs` (optional, Import): Skips a folder if it already contains any ACL entries other than `Default` and `Anonymous`.
- `-File` (required for Import, optional for Export): CSV input/output path.
- `-BatchSize` (optional): Batch size used for writing progress in export/import. Default is `100`.
- `-WhatIf` (optional): Shows what actions the script would take (export/import operations) without making any changes.
- `-Confirm` (optional): Prompts for confirmation before performing each change when importing or modifying permissions.

## CSV format

### Export output columns

- `EntryId`
- `FolderPath`
- `ContentMailboxName`
- `ExportedFrom`
- `DisplayName`
- `PrimarySmtpAddress`
- `Guid`
- `UserType`
- `AccessRights`

### Import input expectations

The import process expects rows with folder identity and permission identity information from a prior export.

Folder identity selection during import:

- If `EntryId` exists and has a value, the script uses `EntryId` for Exchange cmdlet operations.
- Otherwise, it falls back to `FolderPath`.
- User-facing messages continue to show `FolderPath`.

## Resume behavior

### Export resume

If the output CSV already exists, export reads existing `FolderPath` values and skips folders that have already been exported. New results are appended in batches.

### Import resume

Import writes successful row checkpoints to:

```text
<File>.import.progress.csv
```

On rerun, any row whose progress key already exists in that file is skipped.

## AccessRights behavior

During import, `AccessRights` values are interpreted using delimiter-aware tokenization:

- Supported delimiters: semicolon (`;`), comma (`,`), or whitespace.
- Existing and imported rights are normalized and compared as sets.

This avoids false differences caused only by delimiter or ordering changes.

## Notes

- Root marker folders (`\` and `\NON_IPM_SUBTREE`) are skipped during export.
- The script uses `Write-Progress` for activity reporting.
- Long runs can be safely resumed by rerunning with the same `-File`.
