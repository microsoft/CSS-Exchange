# SetupAssist.ps1 is used for running on the Exchange Server that we are wanting to install or upgrade.
# We validate common prerequisites that or overlooked and look at AD to make sure it is able to upgrade
#
# TODO: Add AD Object Permissions check
#
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

$Script:ScriptLogging = "$PSScriptRoot\SetupAssist_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).log"

Function Write-LogInformation {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [bool]$VerboseEnabled = $VerbosePreference
    )

    process {

        if ($VerboseEnabled) {
            $Object | Write-Verbose -Verbose
        }

        $Object | Out-File -FilePath $Script:ScriptLogging -Append
    }
}

Function Receive-Output {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [switch]$Diagnostic,
        [switch]$IsWarning,
        [switch]$IsError
    )

    process {

        if (($Diagnostic -and
                $VerbosePreference) -or
            (-not $Diagnostic -and
                -not $IsWarning -and
                -not $IsError)) {
            $Object | Write-Output
        } elseif ($IsWarning) {
            $Object | Write-Warning
        } elseif ($IsError) {
            $Object | Write-Error
        } else {
            $Object | Write-Verbose
        }

        Write-LogInformation $Object -VerboseEnabled $false
    }
}

function IsAdministrator {
    $ident = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object System.Security.Principal.WindowsPrincipal($ident)
    return $prin.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function MainUse {

    if (IsAdministrator) {
        "User is an administrator." | Receive-Output
    } else {
        "User is not an administrator." | Receive-Output -IsWarning
    }

    Test-UserGroupMemberOf
    Test-MissingMsiFiles

    $powershellProcesses = @(Get-Process -IncludeUserName powershell)

    if ($powershellProcesses.Count -gt 1) {
        "More than one PowerShell process was found. Please close other instances of PowerShell." | Receive-Output -IsWarning
        $powershellProcesses | Format-Table -AutoSize | Out-String | Receive-Output
    } else {
        "No other PowerShell instances were detected." | Receive-Output
    }

    if (Test-PendingReboot) {
        "Reboot pending." | Receive-Output -IsWarning
    } else {
        "No reboot pending." | Receive-Output
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

try {
    Out-File -FilePath $Script:ScriptLogging -Force | Out-Null
    Receive-Output "Starting Script At: $([DateTime]::Now)" -Diagnostic
    Main
    Receive-Output "Finished Script At: $([DateTime]::Now)" -Diagnostic
    Write-Output "File Written at: $Script:ScriptLogging"
} catch {
    Receive-Output "$($_.Exception)"
    Receive-Output "$($_.ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}
