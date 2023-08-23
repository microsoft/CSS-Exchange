# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    This script is used to review the Security Update Logs to determine why they are failing.
    The default location: V15\Logging\Update\msi
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [System.IO.FileInfo]$SecurityUpdateLog
)

$BuildVersion = ""

try {
    Write-Host "Security Log Reviewer Version: $BuildVersion"
} catch {
    Write-HostErrorInformation $_ "Write-Host"
    Write-Warning "Ran into an issue with the script. If possible please email the Security Log to 'ExToolsFeedback@microsoft.com', or at least notify them of the issue."
}
