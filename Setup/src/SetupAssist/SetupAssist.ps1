# SetupAssist.ps1 is used for running on the Exchange Server that we are wanting to install or upgrade.
# We validate common prerequisites that or overlooked and look at AD to make sure it is able to upgrade
#
# TODO: Add AD Object Permissions check
#
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Need to do nothing about it')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Use is the best verb and do not need to confirm')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter is used')]
[CmdletBinding()]
param(
    [switch]$OtherWellKnownObjects
)

. .\Checks\Confirm-VirtualDirectoryConfiguration.ps1
. .\Checks\Test-CriticalService.ps1
. .\Checks\Test-ExchangeAdLevel.ps1
. .\Checks\Test-MissingDirectory.ps1
. .\Checks\Test-MissingMsiFiles.ps1
. .\Checks\Test-OtherWellKnownObjects.ps1
. .\Checks\Test-PendingReboot.ps1
. .\Checks\Test-UserGroupMemberOf.ps1
. .\Checks\Test-ValidHomeMdb.ps1
. .\Utils\ConvertFrom-Ldif.ps1

function IsAdministrator {
    $ident = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object System.Security.Principal.WindowsPrincipal($ident)
    return $prin.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function MainUse {

    if (IsAdministrator) {
        Write-Host "User is an administrator."
    } else {
        Write-Warning "User is not an administrator."
    }

    Test-UserGroupMemberOf
    Test-MissingMsiFiles

    $powershellProcesses = @(Get-Process -IncludeUserName powershell)

    if ($powershellProcesses.Count -gt 1) {
        Write-Warning "More than one PowerShell process was found. Please close other instances of PowerShell."
        Write-Host ($powershellProcesses | Format-Table -AutoSize | Out-String)
    } else {
        Write-Host "No other PowerShell instances were detected."
    }

    if (Test-PendingReboot) {
        Write-Warning "Reboot pending."
    } else {
        Write-Host "No reboot pending."
    }

    Test-CriticalService
    Test-ValidHomeMDB
    Test-MissingDirectory
    Test-ExchangeAdSetupObjects
    Confirm-VirtualDirectoryConfiguration
}

Function Main {

    if ($OtherWellKnownObjects) {
        Test-OtherWellKnownObjects
    } else {
        MainUse
    }
}

Main
