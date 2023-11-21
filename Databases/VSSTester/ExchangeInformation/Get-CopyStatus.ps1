# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-CopyStatus {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ServerName,

        [Parameter(Mandatory = $true)]
        [object]
        $Database,

        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )

    Write-Host "$(Get-Date) Status of '$Database' and its replicas (if any)"
    [array]$copyStatus = (Get-MailboxDatabaseCopyStatus -identity ($Database).name)
    ($copyStatus | Format-List) | Out-File -FilePath "$OutputPath\copyStatus.txt"
    $copyStatus | Format-Table Name, Status | Out-Host
    $unhealthyCopies = $copyStatus | Where-Object { $_.Status -ne "Healthy" -and $_.Status -ne "Mounted" }
    if ($null -ne $unhealthyCopies) {
        Write-Warning "One of the copies of the selected database is not healthy. Please run backup after ensuring that the database copy is healthy"
        exit
    }
}
