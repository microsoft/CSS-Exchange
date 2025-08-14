# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    Get the ExSetup.exe file version information on the local server. If the ExSetup.exe isn't in the environment path, we will manually try to find it.
.NOTES
    You MUST execute this code on the server you want to collect information for. This can be done remotely via Invoke-Command/Invoke-ScriptBlockHandler.
#>
function Get-ExSetupFileVersionInfo {
    param(
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    # You must have Invoke-CatchActionError within Get-ExSetupFileVersionInfo if running this inside of Invoke-Command
    . $PSScriptRoot\Invoke-CatchActionError.ps1

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exSetupDetails = $null
    try {
        $exSetupDetails = Get-Command ExSetup -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo }
        $getItem = Get-Item -ErrorAction SilentlyContinue $exSetupDetails[0].FileName
        $exSetupDetails | Add-Member -MemberType NoteProperty -Name InstallTime -Value ($getItem.LastAccessTime)
    } catch {
        try {
            Write-Verbose "Failed to find ExSetup by environment path locations. Attempting manual lookup. Inner Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
            $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction Stop).MsiInstallPath

            if ($null -ne $installDirectory) {
                $exSetupDetails = Get-Command ([System.IO.Path]::Combine($installDirectory, "bin\ExSetup.exe")) -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo }
                $getItem = Get-Item -ErrorAction SilentlyContinue $exSetupDetails[0].FileName
                $exSetupDetails | Add-Member -MemberType NoteProperty -Name InstallTime -Value ($getItem.LastAccessTime)
            }
        } catch {
            Write-Verbose "Failed to find ExSetup, need to fallback. Inner Exception $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }

    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $exSetupDetails
}
