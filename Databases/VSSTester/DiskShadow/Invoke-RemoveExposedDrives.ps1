# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-RemoveExposedDrives {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath,

        [Parameter(Mandatory = $true)]
        [string[]]
        $ExposedDrives
    )

    function Out-removeDHSFile {
        param ([string]$FileLine)
        $FileLine | Out-File -FilePath "$OutputPath\removeSnapshot.dsh" -Encoding ASCII -Append
    }

    Write-Host "$(Get-Date) DiskShadow Snapshots"
    Write-Host
    Write-Host "If the snapshot was successful, the snapshot should be exposed as drive(s) $ExposedDrives."
    Write-Host "You should be able to see and navigate the snapshot with File Explorer."
    Write-Host
    Write-Host "NOTE: It is recommended to wait a few minutes to allow truncation to possibly occur before moving past this point."
    Write-Host "      This allows time for the logs that are automatically collected to include the window for the truncation to occur."
    Write-Host

    New-Item -Path $OutputPath\removeSnapshot.dsh -type file -Force | Out-Null

    $ExposedDrives | ForEach-Object {
        Out-removeDHSFile "delete shadows exposed $($_):"
    }

    Out-removeDHSFile "exit"

    if ($PSCmdlet.ShouldProcess("$ExposedDrives", "Remove exposed drives now?")) {
        DiskShadow.exe /s "$OutputPath\removeSnapshot.dsh"
    } else {
        Write-Host "When you are ready to remove the snapshots, run the following command:"
        Write-Host
        Write-Host "DiskShadow.exe /s $OutputPath\removeSnapshot.dsh"
        Write-Host
    }
}
