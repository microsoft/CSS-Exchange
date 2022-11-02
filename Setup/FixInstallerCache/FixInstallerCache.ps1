# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(DefaultParameterSetName = "CopyFromCu")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "CopyFromCu")]
    [ValidateNotNullOrEmpty()]
    [string]$CurrentCuRootDirectory,
    [Parameter(Mandatory = $true, ParameterSetName = "CopyFromServer")]
    [ValidateNotNullOrEmpty()]
    [string[]]$MachineName
)

. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Warning.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\Shared\Get-FileInformation.ps1
. $PSScriptRoot\..\Shared\Get-InstallerPackages.ps1
. $PSScriptRoot\WriteFunctions.ps1
. $PSScriptRoot\Invoke-IsoCopy.ps1
. $PSScriptRoot\Invoke-MachineCopy.ps1

try {
    Invoke-ErrorMonitoring
    $Script:HostLogger = Get-NewLoggerInstance -LogName "FixInstallerCache"
    $Script:DebugLogger = Get-NewLoggerInstance -LogName "FixInstallerCache-Debug"
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteWarningAction ${Function:Write-HostLog}

    if ($PsCmdlet.ParameterSetName -eq "CopyFromCu") {
        Write-Host "Starting Fix Installer Cache from CU ISO."
        Write-Verbose "Using CU Root: $CurrentCuRootDirectory"
        Invoke-IsoCopy $CurrentCuRootDirectory
        return
    } else {
        Write-Host "Starting Fix Installer Cache from machine."
        Write-Verbose "Using the following machine names: $([string]::Join(",", $MachineName))"
        Invoke-MachineCopy $MachineName
        return
    }
} catch {
    Invoke-CatchActions
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing with the log '$($Script:DebugLogger.FullPath)'")
}
