# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(DefaultParameterSetName = "CopyFromCu")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "CopyFromCu")]
    [ValidateNotNullOrEmpty()]
    [string]$CurrentCuRootDirectory,
    [Parameter(Mandatory = $true, ParameterSetName = "CopyFromServer")]
    [ValidateNotNullOrEmpty()]
    [string[]]$MachineName,
    [Parameter(Mandatory = $false)]
    [switch]$RemoteDebug
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

    if ($RemoteDebug) {
        Write-Verbose "Remote Debug detected, saving out the installer cache location."
        try {
            $installerCacheFiles = Get-ChildItem "$env:SystemPath\Windows\Installer" -ErrorAction Stop |
                Where-Object { $_.Name.ToLower().EndsWith(".msi") } |
                ForEach-Object {
                    return Get-FileInformation -File $_.FullName
                }
        } catch {
            Write-Verbose "Failed to get the installer cache information."
            Invoke-CatchActions
        }

        try {
            Write-Verbose "Exporting out the Installer Cache Information"
            $installerCacheFiles | Export-Clixml -Path "$((Get-Location).Path)\$env:ComputerName-InstallerCache.xml" -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to export the Installer Cache Information"
            Invoke-CatchActions
        }

        try {
            Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer" -Recurse |
                Where-Object { $_.Property -eq "LocalPackage" } |
                Export-Clixml -Path "$((Get-Location).Path)\$env:ComputerName-InstallerRegistry.xml" -ErrorAction Stop
            Get-ChildItem -Path "Registry::HKEY_CLASSES_ROOT\Installer\Products\" -Recurse |
                Export-Clixml -Path "$((Get-Location).Path)\$env:ComputerName-InstallerRegistryProducts.xml" -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to export out the registry information."
            Invoke-CatchActions
        }
    }

    if ($PsCmdlet.ParameterSetName -eq "CopyFromCu") {
        Write-Host "Starting Fix Installer Cache from CU ISO."
        Write-Verbose "Using CU Root: $CurrentCuRootDirectory"
        Invoke-IsoCopy $CurrentCuRootDirectory $RemoteDebug
        return
    } else {
        Write-Host "Starting Fix Installer Cache from machine."
        Write-Verbose "Using the following machine names: $([string]::Join(",", $MachineName))"
        Invoke-MachineCopy $MachineName $RemoteDebug
        return
    }
} catch {
    Invoke-CatchActions
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing with the log '$($Script:DebugLogger.FullPath)'")
    $Script:MainCatchOccurred = $true
} finally {
    if ($PSBoundParameters["Verbose"] -or
    (Test-UnhandledErrorsOccurred) -or
        $Script:MainCatchOccurred -or
        $RemoteDebug) {
        $Script:DebugLogger.PreventLogCleanup = $true
    }
    Invoke-WriteDebugErrorsThatOccurred
    $Script:DebugLogger | Invoke-LoggerInstanceCleanup

    if ((Test-UnhandledErrorsOccurred) -and
    (-not($Script:MainCatchOccurred))) {
        Write-Warning "Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing with the log '$($Script:DebugLogger.FullPath)'"
    }
}
