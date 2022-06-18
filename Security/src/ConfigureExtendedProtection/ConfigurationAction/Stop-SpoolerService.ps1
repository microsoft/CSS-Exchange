# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This method stops the Spooler service and also set the start up of this process as disabled on the given server.
function Stop-SpoolerService {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Logic not yet implemented to consider PSShouldProcess - future work.')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter (Mandatory = $true)]
        [string]$Server
    )

    try {
        Get-Service -Name "Spooler" -ComputerName $Server | Stop-Service -Force
        Set-Service -Name "Spooler" -ComputerName $Server -StartupType "Disabled"
    } catch {
        Write-Host ("Error while stopping the spooler service on {0} due to error: {1}" -f $Server, $_.Exception.Message)
    }
}
