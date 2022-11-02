# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-TryCopyMissingPackages.ps1
function Invoke-MachineCopy {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$MachineName,
        [Parameter(Mandatory = $false)]
        [bool]$RemoteDebug
    )

    $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
    [System.Collections.Generic.List[PSObject]]$missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    $currentMissingPackages = $missingPackages.Count

    if ($currentMissingPackages -eq 0) {
        Write-Host "No missing packages detected."
        return
    }

    # Don't need to export out the information if 0 missing files were found
    if ($RemoteDebug) {
        Write-Verbose "Save out the Get-InstallerPackages information"
        try {
            $msiInstallerPackages | Export-Clixml -Path "$((Get-Location).Path)\$env:ComputerName-InstallerPackages.xml" -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to export the Installer Packages Information"
            Invoke-CatchActions
        }
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

        if ($RemoteDebug) {
            Write-Verbose "Save out Installer Information from $machine"
            try {
                $remoteFiles | Export-Clixml -Path "$((Get-Location).Path)\$machine-InstallerPackages.xml" -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to export the ISO Packages Information"
                Invoke-CatchActions
            }
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
