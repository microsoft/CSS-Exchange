# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-ScriptBlockHandler.ps1
function Get-ExSetupFileVersionInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exSetupDetails = [string]::Empty
    function Get-ExSetupDetailsScriptBlock {
        try {
            Get-Command ExSetup -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo }
        } catch {
            try {
                Write-Verbose "Failed to find ExSetup by environment path locations. Attempting manual lookup."
                $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction Stop).MsiInstallPath

                if ($null -ne $installDirectory) {
                    Get-Command ([System.IO.Path]::Combine($installDirectory, "bin\ExSetup.exe")) -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo }
                }
            } catch {
                Write-Verbose "Failed to find ExSetup, need to fallback."
            }
        }
    }

    $exSetupDetails = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock ${Function:Get-ExSetupDetailsScriptBlock} -ScriptBlockDescription "Getting ExSetup remotely" -CatchActionFunction $CatchActionFunction
    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $exSetupDetails
}
