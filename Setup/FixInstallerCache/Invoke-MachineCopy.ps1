# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-MachineCopy {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$MachineName
    )

    $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
    [System.Collections.Generic.List[PSObject]]$missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    $currentMissingPackages = $missingPackages.Count

    "Current Missing Files" | Write-Host
    #Fix later, figure out how to log this better.
    $missingPackages | ForEach-Object { $_ | Select-Object DisplayName, DisplayVersion, RevisionNumber, ValidMsi, FoundFileInCache } | Write-Host

    $runAgain = $false

    foreach ($machine in $MachineName) {

        $remoteInstallerCache = "\\$machine\c$\Windows\Installer"

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

        if ($runAgain) {
            $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
            [System.Collections.Generic.List[PSObject]]$missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
        }

        foreach ($missingMsi in $missingPackages) {

            $fileFound = $remoteFiles | Where-Object { $_.RevisionNumber -eq $missingMsi.RevisionNumber }

            if ($null -eq $fileFound) {
                "Failed to find MSI - $($missingMsi.DisplayName) - $($missingMsi.RevisionNumber)" | Write-Host
            } elseif ($fileFound.Count -gt 1) {
                Write-Host "Found more than 1 MSI file that matched our revision number." | Write-Host
            } else {
                "Copying file $($fileFound.FilePath) to $($missingMsi.CacheLocation)" | Write-Host
                Copy-Item $fileFound.FilePath $missingMsi.CacheLocation
                $fixedFiles++
            }
        }
        $runAgain = $true
    }

    "Fixed $fixedFiles out of $currentMissingPackages" | Write-Host
}
