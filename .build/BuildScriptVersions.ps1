# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param (

)

#Requires -Version 7

$repoRoot = Get-Item "$PSScriptRoot\.."
$distFolder = "$repoRoot\dist"
$scriptVersionsCsv = "$distFolder\ScriptVersions.csv"

if (Test-Path -Path $scriptVersionsCsv) {
    $versionsFileCSV = ConvertFrom-Csv -InputObject (Get-Content -Path $scriptVersionsCsv)

    # Generate final ScriptVersions.txt file (with SHA256 hash) for release description
    $versionFile = "$distFolder\ScriptVersions.txt"
    New-Item -Path $versionFile -ItemType File -Force | Out-Null
    "Script | Version | SHA256 Hash" | Out-File $versionFile -Append
    "-------|---------|------------" | Out-File $versionFile -Append
    foreach ($script in $versionsFileCSV) {
        $sha256Hash = $((Get-FileHash -Path "$($distFolder)\$($script.File)").Hash)
        $script | Add-Member -MemberType NoteProperty -Name SHA256Hash -Value $sha256Hash
        "$($script.File) | $($script.Version) | $sha256Hash" | Out-File $versionFile -Append
        Write-Host ("File: '{0}' Version: '{1}' Hash: '{2}' added" -f $script.File, $script.Version, $sha256Hash)
    }

    $versionsFileCSV | Export-Csv -Path $scriptVersionsCsv -NoTypeInformation
} else {
    # Skip re-creation if ScriptVersions.csv doesn't exist
    Write-Host ("File: '{0}' not found. Skipping 'ScriptVersions.txt' re-creation" -f $scriptVersionsCsv)
}
