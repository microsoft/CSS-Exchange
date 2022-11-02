# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-TryCopyMissingPackages.ps1
function Invoke-MachineCopy {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$MachineName
    )

    $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
    [System.Collections.Generic.List[PSObject]]$missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    $currentMissingPackages = $missingPackages.Count

    if ($currentMissingPackages -eq 0) {
        Write-Host "No missing packages detected."
        return
    }

    Write-Host "Number of missing packages detected: $currentMissingPackages"

    $missingPackages |
        ForEach-Object { $_ | Select-Object DisplayName, DisplayVersion, RevisionNumber, FoundFileInCache } |
        Format-Table |
        Out-String |
        Write-Host

    # foreach machine, need to try to fix the cache till the fixed count reached original missing packages count
    $totalFixedCount = 0

    foreach ($machine in $MachineName) {

        $remoteInstallerCache = "\\$machine\c$\Windows\Installer"
        Write-Verbose "Getting cache information from $remoteInstallerCache"

        try {
            $remoteFiles = Get-ChildItem $remoteInstallerCache -ErrorAction Stop |
                Where-Object { $_.Name.ToLower().EndsWith(".msi") } |
                ForEach-Object {
                    return Get-FileInformation -File $_.FullName
                }
        } catch {
            Write-Host "Failed to get files from the following path: $remoteInstallerCache" -ForegroundColor "Red"
            continue
        }

        Invoke-TryCopyMissingPackages -MissingPackages $missingPackages -PossiblePackages $remoteFiles ([ref]$totalFixedCount)

        if ($totalFixedCount -ge $currentMissingPackages) {
            Write-Verbose "Found all missing packages, break out of loop."
            break
        }

        $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
        [System.Collections.Generic.List[PSObject]]$missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    }

    "Fixed $totalFixedCount out of $currentMissingPackages" | Write-Host
}
