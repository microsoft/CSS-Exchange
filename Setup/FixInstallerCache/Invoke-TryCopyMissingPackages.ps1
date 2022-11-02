# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Common code between ISO and Machine copy logic
function Invoke-TryCopyMissingPackages {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$MissingPackages,

        [Parameter(Mandatory = $true)]
        [object[]]$PossiblePackages,

        [Parameter(Mandatory = $true)]
        [ref]$FixedCount
    )

    function GetInstallerPackageInfoString {
        param(
            [Parameter(Mandatory = $true)]
            [object]$InstallerPackage
        )
        $InstallerPackage | Select-Object DisplayName, RevisionNumber, DisplayVersion |
            Format-Table |
            Out-String
    }

    function CopyAction {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $true)]
            [string]$Destination
        )

        try {
            "Copying file $Path to $Destination" | Write-Host
            Copy-Item $Path $Destination -ErrorAction Stop
            $FixedCount.Value++
        } catch {
            Invoke-CatchActions
        }
    }
    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    foreach ($missingMsi in $MissingPackages) {
        Write-Verbose "Trying to find MSI $(GetInstallerPackageInfoString $missingMsi)"
        $fileFound = $PossiblePackages | Where-Object { $_.RevisionNumber -eq $missingMsi.RevisionNumber }

        if ($null -eq $fileFound) {
            "Failed to find MSI - $(GetInstallerPackageInfoString $missingMsi)" | Write-Host
        } elseif ($fileFound.Count -gt 1) {
            "Found more than 1 MSI file that matched our revision number." | Write-Host
            $hashes = $fileFound |
                ForEach-Object { Get-FileHash $_.FilePath } |
                Group-Object Hash
            if ($hashes.Count -eq 1) {
                "All files have the same hash value. $(GetInstallerPackageInfoString $missingMsi)" | Write-Host
                $fileFound = $fileFound[0]
                CopyAction $fileFound.FilePath $missingMsi.CacheLocation
            } else {
                "Not all found files had the same hash" | Write-Host
                $fileFound | ForEach-Object { "$($fileFound.FilePath) - $($fileFound.RevisionNumber)" | Write-Host }
            }
        } else {
            CopyAction $fileFound.FilePath $missingMsi.CacheLocation
        }
    }
}
