# Export-PublicFolderStatistics

Download the latest release: [Export-PublicFolderStatistics.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Export-PublicFolderStatistics.ps1)

This script exports statistics for a list of public folders to CSV by calling
`Get-PublicFolderStatistics` for each folder identity in an input CSV.

Get-PublicFolderStatistics may encounter transient exceptions for
many different reasons, such as database failover, connection timing out,
laptop going to sleep, etc. This makes exporting statistics for thousands
of public folders difficult.

This script attempts to solve the problem by using an input file that lists
the folders it needs to export, and then exporting those results in batches
as it goes. If it skips folders, fails entirely, or is interrupted
for whatever reason, the user can simply run it again. It will read the
input file, skip everything that is already in the export file, and then
continue adding to the same export file until it fails or completes.

In this way, the user can rerun the script repeatedly and keep building
the results file until all folders have been exported, or at least until
the remaining folders are ones that are experiencing permanent failures.

## Prerequisites

- Run where Exchange cmdlets are available (ExchangeOnlineManagement module
  or EMS is loaded).
- Input CSV must contain a column named `Identity` with public folder paths.

## Usage

First, generate your input file to tell the script which folders to export.
This can be the entire hierarchy or a subset:

Get-PublicFolder "\Some\Folder" -Recurse -ResultSize Unlimited | Export-Csv PublicFoldersToExport.csv

Provide that file to the script. This is how it will determine the difference
between what it needs to export and what is already exported.

Example (basic):

```
.\Export-PublicFolderStatistics.ps1 -InputFile PublicFoldersToExport.csv
```

Example (custom output file):

```
.\Export-PublicFolderStatistics.ps1 -InputFile PublicFoldersToExport.csv -OutputFile PFStats.csv
```

Example (custom batch size):

```
.\Export-PublicFolderStatistics.ps1 -InputFile PublicFoldersToExport.csv -BatchSize 20
```

## Parameters

- `-InputFile` (required): Path to CSV file containing public folder identities.
- `-OutputFile` (optional): Path to the CSV to write results to. Defaults to
  `PublicFolderStatistics.csv`.
- `-BatchSize` (optional): Number of results buffered before appending to the
  output CSV. Must be 1 or greater. Defaults to `5`.

## Input CSV format

The CSV must include an `Identity` column. Each row should contain a single
public folder identity (for example `\Contoso\Departments\HR`). The script
automatically ignores the Exchange root markers `\` and `\NON_IPM_SUBTREE`.

## Output CSV

The output CSV contains the selected properties returned by
`Get-PublicFolderStatistics` including:

- `Name`
- `FolderPath` (joined folder path with leading `\`)
- `ItemCount`
- `TotalItemSize`
- `AssociatedItemCount`
- `TotalAssociatedItemSize`
- `DeletedItemCount`
- `TotalDeletedItemSize`
- `CreationTime`
- `LastModificationTime`

If the output file already exists, the script reads it and skips folders that
already have a `FolderPath` entry so the script can be safely re-run.

## Behavior & Notes

- Progress is reported via `Write-Progress` with an estimated remaining time.
- Errors for individual folders are written to host and processing continues.
- The script appends to the output CSV in batches (configured by `-BatchSize`);
  ensure sufficient disk space and permissions for the target path.

## Troubleshooting

- If `Get-PublicFolderStatistics` fails for a folder, the script logs the
  exception message and continues. Re-run the script to retry failed folders.
- Validate the `Identity` values in the input CSV if many queries fail.
  Long runs of the script may encounter expected failures due to folders being
  renamed or deleted after the input file was generated.
