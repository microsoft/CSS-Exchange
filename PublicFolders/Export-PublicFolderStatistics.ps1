# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Export statistics for a list of public folders to CSV.
.DESCRIPTION
    Reads a CSV of public folder identities, calls `Get-PublicFolderStatistics`
    for each identity, and appends the returned properties to an output CSV.

.PARAMETER InputFile
    Path to a CSV file that contains a list of public folder identities.
    The CSV must include a column named `Identity` containing the folder path.

.PARAMETER OutputFile
    Path to the CSV file to write statistics to. If the file exists, it will
    be read to avoid re-processing folders already exported. Defaults to
    `PublicFolderStatistics.csv` in the current working directory.

.PARAMETER BatchSize
    Number of folder statistics results to buffer before writing to the output
    CSV. Must be 1 or greater. Defaults to 5.

.EXAMPLE
    .\Export-PublicFolderStatistics.ps1 -InputFile PublicFoldersToQuery.csv

.EXAMPLE
    .\Export-PublicFolderStatistics.ps1 -InputFile folders.csv -OutputFile PFStatistics.csv

.EXAMPLE
    .\Export-PublicFolderStatistics.ps1 -InputFile folders.csv -BatchSize 20

.NOTES
    - Requires Exchange cmdlets to be available (for example, run in an
      Exchange Management Shell or have the Exchange modules loaded).
    - The script skips root markers such as "\" and "\NON_IPM_SUBTREE".
    - Progress is reported with `Write-Progress` and errors are logged to host.
#>

[CmdletBinding()]
param (

    [Parameter(Mandatory = $true)]
    [string]
    $InputFile,

    [Parameter(Mandatory = $false)]
    [string]
    $OutputFile = "PublicFolderStatistics.csv",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]
    $BatchSize = 5
)

# Import the list of public folders from the specified CSV input file. The
# CSV is expected to contain a column named 'Identity' with each folder path.
$publicFolders = Import-Csv -Path $InputFile

# Filter out the Exchange root markers which are not real public folders.
$publicFolders = $publicFolders | Where-Object { $_.Identity -ne "\" -and $_.Identity -ne "\NON_IPM_SUBTREE" }
Write-Host "Total public folders to process: $($publicFolders.Count)"

# If the output CSV already exists, read it so we can skip folders already
# exported in previous runs. We expect the exported CSV to have a column
# named 'FolderPath' which we compare against Identity values from input.
$foldersAlreadyExported = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path -Path $OutputFile) {
    [string[]]$identitiesInOutput = Import-Csv -Path $OutputFile -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FolderPath
    $foldersAlreadyExported.UnionWith($identitiesInOutput)
}

Write-Host "Public folders already exported: $($foldersAlreadyExported.Count)"

# Exclude any folders that are already present in the output CSV to allow
# safe re-runs of this script without duplicating work.
$publicFolders = $publicFolders | Where-Object { $foldersAlreadyExported.Contains($_.Identity.ToString()) -eq $false }
Write-Host "Public folders remaining to process: $($publicFolders.Count)"

$startTime = [DateTime]::UtcNow
$successfullyExportedCount = 0
$failedExportCount = 0
$exportBatch = New-Object System.Collections.ArrayList

for ($i = 0; $i -lt $publicFolders.Count; $i++) {
    $elapsed = ([DateTime]::UtcNow - $startTime)
    $estimatedTimeRemaining = [TimeSpan]::FromTicks($publicFolders.Count / ($i + 1) * $elapsed.Ticks - $elapsed.Ticks).ToString("hh\:mm\:ss")
    Write-Progress -Activity $publicFolders[$i].Identity -Status "$i / $($publicFolders.Count) Estimated time remaining: $estimatedTimeRemaining" -PercentComplete (($i + 1) * 100 / $publicFolders.Count)
    try {
        # We make this an array since we could have a scenario where multiple folders have the same path
        $stats = @(Get-PublicFolderStatistics $publicFolders[$i].Identity | Select-Object Name, @{Label = "FolderPath"; Expression = { "\" + ($_.FolderPath -join "\") } }, ItemCount, TotalItemSize, AssociatedItemCount, TotalAssociatedItemSize, DeletedItemCount, TotalDeletedItemSize, CreationTime, LastModificationTime)
        $exportBatch.AddRange($stats)
        if ($exportBatch.Count -ge $BatchSize) {
            $exportBatch | Export-Csv -Path $OutputFile -Append -Encoding utf8 -NoTypeInformation
            $successfullyExportedCount += $exportBatch.Count
            $exportBatch.Clear()
        }
    } catch {
        Write-Host "Error processing folder $($publicFolders[$i].Identity): $($_.Exception.Message)"
        $failedExportCount++
    }
}

if ($exportBatch.Count -gt 0) {
    $exportBatch | Export-Csv -Path $OutputFile -Append -Encoding utf8 -NoTypeInformation
    $successfullyExportedCount += $exportBatch.Count
}

Write-Host "Export completed. Total folders exported: $successfullyExportedCount. Total folders failed: $failedExportCount"
