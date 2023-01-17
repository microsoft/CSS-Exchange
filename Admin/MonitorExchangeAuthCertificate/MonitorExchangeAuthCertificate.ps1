# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: MonitorExchangeAuthCertificate.ps1
	Requires: Exchange Management Shell and Organization Management permissions.
    Major Release History:
        01/10/2023  - Initial Public Release on CSS-Exchange

.SYNOPSIS
    Validates the Auth Certificate configuration of the Exchange organization where the script runs.
    It can be run in mode to automatically replace an invalid Auth Certificate or prepare a new next Auth Certificate
    to ensure a smooth Auth Certificate rollover.
.DESCRIPTION
    This script checks the status of the Auth Certificate which is set to the Auth Configuration of the Exchange organization.
    If the script is executed without any parameter, it will only perform tests if any Auth Certificate renewal action is required.
    The script can be executed in action mode which will then perform the appropriate Auth Certificate renewal actions (if required).
    The script can also be configured to run via Scheduled Task on a daily base. It will then perform the required renewal actions
    without admin interaction needed (except in Exchange Hybrid scenarios where a run of the Hybrid Configuration Wizard or HCW is required
    after a new Auth Certificate becomes active).
.PARAMETER ValidateAndRenewAuthCertificate
    You can use this parameter to let the script perform the required Auth Certificate renewal actions.
    If the script runs with this parameter set to $false, no action will be made to the current Auth Configuration.
.PARAMETER IgnoreUnreachableServers
    This optional parameter can be used to ignore if some of the Exchange servers within the organization cannot be reached.
    If this parameter is used, the script only validates the servers that can be reached and will perform Auth Certificate
    renewal actions based on the result.
.PARAMETER IgnoreHybridConfig
    This optional parameter allows you to explicitly perform Auth Certificate renewal actions (if required) even if an
    Exchange hybrid configuration was detected. You need to run the Hybrid Configuration Wizard (HCW) after the renewed
    Auth Certificate becomes the one in use.
.PARAMETER PrepareADForAutomationOnly
    This optional parameter can be used in AD Split Permission scenarios. It allows you to create the AD account which can then be
    used to run the Exchange Auth Certificate Monitoring script automatically via Scheduled Task.
.PARAMETER ADAccountDomain
    This optional parameter allows you to specify the domain which is then used by the script to generate the AD account used for automation.
.PARAMETER ConfigureScriptToRunViaScheduledTask
    This optional parameter can be used to automatically prepare the requirements in AD (user account), Exchange (email enable the account,
    hide the account from address book, create a new role group with limited permissions) and finally it creates the scheduled task on the computer
    on which the script was executed (it has to be an Exchange server running the mailbox role).
.PARAMETER AutomationAccountCredential
    This optional parameter can be used to provide a different user under whose context the script is then executed via scheduled task.
.PARAMETER Password
    Parameter to provide a password to the script which is required in some scenarios.
    This parameter is required if you use one of the following parameters:
        - If you use the PrepareADForAutomationOnly parameter
        - If you use the ExportAuthCertificatesAsPfx parameter
    It is an optional parameter if you use the ConfigureScriptToRunViaScheduledTask parameter.
.PARAMETER ExportAuthCertificatesAsPfx
    This optional parameter can be used to export all on the system available Auth Certificates as password protected .pfx file.
.PARAMETER ScriptUpdateOnly
    This optional parameter allows you to only update the script without performing any other actions.
.PARAMETER SkipVersionCheck
    This optional parameter allows you to skip the automatic version check and script update.
.EXAMPLE
	.\MonitorExchangeAuthCertificate.ps1
	Runs the script in validation mode and will show you the Auth Certificate renewal action which will be performed when executed in renew mode.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ValidateAndRenewAuthCertificate $true -Confirm:$false
    Runs the script in renewal mode without user interaction. The Auth Certificate renewal action will be performed (if required).
    In unattended mode the internal SMTP certificate will be replaced with the new Auth Certificate and is then set back to the previous one.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ValidateAndRenewAuthCertificate $true -IgnoreUnreachableServers $true -Confirm:$false
    Runs the script in renewal mode without user interaction. We only take the Exchange server into account which are reachable and will perform
    the renewal action if required.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ValidateAndRenewAuthCertificate $true -IgnoreHybridConfig $true -Confirm:$false
    Runs the script in renewal mode without user interaction. The renewal action will be performed even if a Exchange hybrid configuration was detected.
    Please note that you have to run the Hybrid Configuration Wizard (HCW) after the active Auth Certificate was replaced.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ConfigureScriptToRunViaScheduledTask -Password (Get-Credential).Password
    If you run the script using this parameter, the script will then create a new AD user which is then assigned to a newly created Exchange Role Group.
    The script will also create a scheduled task that runs on a hourly base. The '-ConfigureScriptToRunViaScheduledTask' parameter can be combined with the
    '-IgnoreHybridConfig $true' and '-IgnoreUnreachableServers $true' parameter.
#>

[CmdletBinding(DefaultParameterSetName = "MonitorExchangeAuthCertificateManually", SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [bool]$ValidateAndRenewAuthCertificate = $false,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [bool]$IgnoreUnreachableServers = $false,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [bool]$IgnoreHybridConfig = $false,

    [Parameter(Mandatory = $false, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [switch]$PrepareADForAutomationOnly,

    [Parameter(Mandatory = $false, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [string]$ADAccountDomain = $env:USERDNSDOMAIN,

    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [switch]$ConfigureScriptToRunViaScheduledTask,

    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [PSCredential]$AutomationAccountCredential,

    [Parameter(Mandatory = $true, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $true, ParameterSetName = "ExportExchangeAuthCertificatesAsPfx")]
    [SecureString]$Password,

    [Parameter(Mandatory = $false, ParameterSetName = "ExportExchangeAuthCertificatesAsPfx")]
    [switch]$ExportAuthCertificatesAsPfx,

    [Parameter(Mandatory = $false, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $false, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [switch]$SkipVersionCheck
)

$BuildVersion = ""

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-GlobalCatalogServer.ps1
. $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-InternalTransportCertificateFromServer.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

. $PSScriptRoot\ConfigurationAction\Build-ExchangeAuthCertificateManagementAccount.ps1
. $PSScriptRoot\ConfigurationAction\Copy-ScriptToExchangeDirectory.ps1
. $PSScriptRoot\ConfigurationAction\Export-ExchangeAuthCertificate.ps1
. $PSScriptRoot\ConfigurationAction\New-AuthCertificateManagementAccount.ps1
. $PSScriptRoot\ConfigurationAction\New-AuthCertificateMonitoringLogFolder.ps1
. $PSScriptRoot\ConfigurationAction\New-ExchangeAuthCertificate.ps1
. $PSScriptRoot\ConfigurationAction\Register-AuthCertificateRenewalTask.ps1
. $PSScriptRoot\DataCollection\Get-ExchangeAuthCertificateStatus.ps1
. $PSScriptRoot\DataCollection\Test-IsServerValidForAuthCertificateGeneration.ps1

function Write-DebugLog($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Main {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param()

    if (-not(Confirm-Administrator)) {
        Write-Warning ("The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator.")
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
    }

    Invoke-ErrorMonitoring

    $versionsUrl = "https://aka.ms/MEAC-VersionsUrl"
    Write-Host ("Monitor Exchange Auth Certificate script version $($BuildVersion)") -ForegroundColor Green

    $currentErrors = $Error.Count

    if ($ScriptUpdateOnly) {
        switch (Test-ScriptVersion -AutoUpdate -VersionsUrl $versionsUrl -Confirm:$false) {
            ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
            ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
            default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
        }
        return
    }

    if ((-not($SkipVersionCheck)) -and
        (Test-ScriptVersion -AutoUpdate -VersionsUrl $versionsUrl -Confirm:$false)) {
        Write-Host ("Script was updated. Please rerun the command") -ForegroundColor Yellow
        return
    }

    Invoke-ErrorCatchActionLoopFromIndex $currentErrors

    if ($PrepareADForAutomationOnly) {
        Write-Host ("Mode: Prepare AD account to run the script as scheduled task")
        $newAuthCertificateParamsAccountOnly = @{
            Password            = $Password
            DomainToUse         = $ADAccountDomain
            CatchActionFunction = ${Function:Invoke-CatchActions}
        }
        $adAccountSuccessfullyCreated = New-AuthCertificateManagementAccount @newAuthCertificateParamsAccountOnly

        if ($adAccountSuccessfullyCreated) {
            Write-Host ("Account: 'SM_ad0b1fe3a1a3' successfully created - please run the script as follows:") -ForegroundColor Green
            Write-Host ""
            Write-Host (".\MonitorExchangeAuthCertificate.ps1 -ConfigureScriptToRunViaScheduledTask -AutomationAccountCredential (Get-Credential)") -ForegroundColor Green
        } else {
            Write-Host ("Unable to prepare the Auth Certificate automation account - please check the verbose script log for more details") -ForegroundColor Yellow
        }
        return
    }

    $exchangeShell = Confirm-ExchangeShell -CatchActionFunction ${Function:Invoke-CatchActions}
    $exitScriptDueToShellRequirementsNotFullFilled = $false
    if (-not($exchangeShell.ShellLoaded)) {
        Write-Warning ("Unable to load Exchange Management Shell")
        $exitScriptDueToShellRequirementsNotFullFilled = $true
    } else {
        if ($exchangeShell.ToolsOnly) {
            Write-Warning ("The script must be run on an Exchange server")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }

        if ($exchangeShell.EdgeServer) {
            Write-Warning ("The script cannot be run on an Edge Transport server")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }

        if ($exchangeShell.RemoteShell) {
            Write-Warning ("Running the script via Remote Shell is not supported")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }

        if ($exchangeShell.Major -lt 15) {
            Write-Warning ("The script must be run on Exchange 2013 or higher")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }
    }

    if ($exitScriptDueToShellRequirementsNotFullFilled) {
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
    }

    Set-ADServerSettings -ViewEntireForest $true

    if ($ExportAuthCertificatesAsPfx) {
        Write-Host ("Mode: Export all Exchange Auth Certificates available on this system")

        if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
            Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
            return
        }

        $authCertificateExportParams = @{
            Password            = $Password
            CatchActionFunction = ${Function:Invoke-CatchActions}
        }

        $authCertificateExportStatusObject = Export-ExchangeAuthCertificate @authCertificateExportParams

        if ($authCertificateExportStatusObject.CertificatesAvailableToExport) {
            Write-Host ("There are $($authCertificateExportStatusObject.NumberOfCertificatesToExport) certificates that could be exported")
            if ($authCertificateExportStatusObject.ExportSuccessful) {
                Write-Host ("All of them were successfully exported to the following directory: $($PSScriptRoot)") -ForegroundColor Green
            } else {
                Write-Host ("Some of the certificates couldn't be exported - please check the verbose log") -ForegroundColor Yellow
                Write-Host ("Thumbprints of the certificates that couldn't be exported:") -ForegroundColor Yellow
                Write-Host ("$([string]::Join(", ", $authCertificateExportStatusObject.UnableToExportCertificatesList))") -ForegroundColor Yellow
            }
        } else {
            Write-Host ("There are no Auth Certificates on the system that are available to export")
        }

        return
    }

    if ($ConfigureScriptToRunViaScheduledTask) {
        Write-Host ("Mode: Configure monitoring script to run via scheduled task")

        if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
            Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
            return
        }

        try {
            try {
                $dcToUseAsConfigDC = (Get-ExchangeServer -Identity $env:COMPUTERNAME -Status -ErrorAction Stop).CurrentConfigDomainController
            } catch {
                $dcToUseAsConfigDC = Get-GlobalCatalogServer -CatchActionFunction ${Function:Invoke-CatchActions}
            }
            Write-Host ("We use the following Domain Controller: $($dcToUseAsConfigDC)")

            $buildExchangeAuthManagementAccountParams = @{
                DomainController    = $dcToUseAsConfigDC
                CatchActionFunction = ${Function:Invoke-CatchActions}
            }

            if ($null -ne $AutomationAccountCredential) {
                $buildExchangeAuthManagementAccountParams.Add("UseExistingAccount", $true)
                $buildExchangeAuthManagementAccountParams.Add("AccountCredentialObject", $AutomationAccountCredential)
            } elseif ($null -ne $Password) {
                $buildExchangeAuthManagementAccountParams.Add("PasswordToSet", $Password)
            } else {
                Write-Host ("Please provide a password for the automation account") -ForegroundColor Yellow
                Write-Host ("You can do so by using the '-Password' parameter or by using the '-AutomationAccountCredential' parameter") -ForegroundColor Yellow
                return
            }

            $adAccountInfo = Build-ExchangeAuthCertificateManagementAccount @buildExchangeAuthManagementAccountParams

            if ($null -ne $adAccountInfo) {
                Write-Host ("Account for automation was successfully created: $($adAccountInfo.UserPrincipalName)")
                $Username = $adAccountInfo.UserPrincipalName
                $Password = $adAccountInfo.Password

                $scriptInfo = Copy-ScriptToExchangeDirectory -CatchActionFunction ${Function:Invoke-CatchActions}
                if ($null -ne $scriptInfo) {
                    Write-Host ("Script: $($scriptInfo.ScriptName) was successfully copied over to: $($scriptInfo.WorkingDirectory)")
                    $registerSchTaskParams = @{
                        Username             = $Username
                        Password             = $Password
                        WorkingDirectory     = $scriptInfo.WorkingDirectory
                        ScriptName           = $scriptInfo.ScriptName
                        IgnoreOfflineServers = $IgnoreUnreachableServers
                        IgnoreHybridConfig   = $IgnoreHybridConfig
                        CatchActionFunction  = ${Function:Invoke-CatchActions}
                    }
                    $schTaskResults = Register-AuthCertificateRenewalTask @registerSchTaskParams
                } else {
                    Write-Host ("We couldn't copy the script: $($scriptInfo.ScriptName) to: $($scriptInfo.WorkingDirectory)") -ForegroundColor Red
                }
            } else {
                Write-Host ("Something went wrong while preparing the automation account") -ForegroundColor Red
            }

            if ($schTaskResults) {
                Write-Host ("The scheduled task was created successfully") -ForegroundColor Green
            } else {
                Write-Host ("The scheduled task wasn't created - please check the verbose script log for more details") -ForegroundColor Red
            }
        } catch {
            Write-Verbose ("Exception: $($Error[0].Exception.Message)")
        }
        return
    }

    if ($ValidateAndRenewAuthCertificate) {
        Write-Host ("Mode: Testing and replacing Auth Certificate (if required)")
    } else {
        Write-Host ("The script was run without parameter therefore, only a check of the Auth Certificate configuration is performed and no change will be made")
    }

    if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
        Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
        return
    }

    $authCertificateStatusParams = @{
        IgnoreUnreachableServers = $IgnoreUnreachableServers
        IgnoreHybridSetup        = $IgnoreHybridConfig
        CatchActionFunction      = ${Function:Invoke-CatchActions}
    }
    $authCertStatus = Get-ExchangeAuthCertificateStatus @authCertificateStatusParams

    $noRenewalDueToUnreachableServers = (($authCertStatus.NumberOfUnreachableServers -gt 0) -and ($IgnoreUnreachableServers -eq $false))
    $stopProcessingDueToHybrid = $authCertStatus.StopProcessingDueToHybrid
    $renewalActionRequired = (($authCertStatus.ReplaceRequired) -or ($authCertStatus.ConfigureNextAuthRequired))

    if ($authCertStatus.ReplaceRequired) { $renewalActionWording = "The Auth Certificate in use must be replaced by a new one." }
    elseif ($authCertStatus.ConfigureNextAuthRequired) { $renewalActionWording = "The Auth Certificate configured as next Auth Certificate must be configured or replaced by a new one." }
    else { $renewalActionWording = "No renewal action is required" }

    if ($noRenewalDueToUnreachableServers) {
        Write-Host ("We couldn't validate if the Auth Certificate is properly configured because $($authCertStatus.NumberOfUnreachableServers) servers were unreachable.") -ForegroundColor Yellow
        Write-Host ("The unreachable servers are: $([string]::Join(", ", $authCertStatus.UnreachableServersList))") -ForegroundColor Yellow
    } elseif ($stopProcessingDueToHybrid) {
        Write-Host ("We have not made any configuration change because because Exchange Hybrid has been detected in your environment.") -ForegroundColor Yellow
        Write-Host ("Please rerun the script using the '-IgnoreHybridConfig `$true' parameter to perform the renewal action.") -ForegroundColor Yellow
        Write-Host ("It's also required to run the Hybrid Configuration Wizard (HCW) after the primary Auth Certificate was replaced.") -ForegroundColor Yellow
    } else {
        if (($ValidateAndRenewAuthCertificate) -and
            ($renewalActionRequired)) {
            Write-Host ("Renewal scenario: $($renewalActionWording)")
            if ($PSCmdlet.ShouldProcess("Ask if the script should run unattended", "Do you want to run the script in unattended mode?", "Run Unattended") -or
                $WhatIfPreference) {
                $UnattendedMode = $true
                $recycleAppPoolsAfterRenewal = $true
            } else {
                $UnattendedMode = $false
                $recycleAppPoolsMessage = ("It's recommended to restart the 'MSExchangeOWAAppPool' and 'MSExchangeECPAppPool' WebApp Pools in case the Auth Certificate was replaced. " +
                    "This is to speed up the adoption of the new configuration." +
                    "`r`nDo you want to restart the WebApp Pools after the Auth Certificate was replaced?"
                )
                if ($PSCmdlet.ShouldProcess("Ask if the script should recycling the WebApp pools", $recycleAppPoolsMessage, "Recycle WebApp Pools") -or
                    $WhatIfPreference) {
                    $recycleAppPoolsAfterRenewal = $true
                } else {
                    $recycleAppPoolsAfterRenewal = $false
                }
            }

            if ($authCertStatus.ReplaceRequired) {
                $replaceExpiredAuthCertificateParams = @{
                    ReplaceExpiredAuthCertificate = $true
                    UnattendedMode                = $UnattendedMode
                    CatchActionFunction           = ${Function:Invoke-CatchActions}
                }

                if ($recycleAppPoolsAfterRenewal) {
                    $replaceExpiredAuthCertificateParams.Add("RecycleAppPoolsAfterRenewal", $recycleAppPoolsAfterRenewal)
                }
                $renewalActionResult = New-ExchangeAuthCertificate @replaceExpiredAuthCertificateParams
            } elseif ($authCertStatus.ConfigureNextAuthRequired) {
                $configureNextAuthCertificateParams = @{
                    ConfigureNextAuthCertificate         = $true
                    CurrentAuthCertificateLifetimeInDays = $authCertStatus.CurrentAuthCertificateLifetimeInDays
                    UnattendedMode                       = $UnattendedMode
                    CatchActionFunction                  = ${Function:Invoke-CatchActions}
                }
                $renewalActionResult = New-ExchangeAuthCertificate @configureNextAuthCertificateParams
            }

            if (($renewalActionResult.RenewalActionPerformed) -and
            ($authCertStatus.HybridSetupDetected -eq $false)) {
                Write-Host ("")
                Write-Host ("The renewal action was successfully performed") -ForegroundColor Green
            } elseif (($renewalActionResult.RenewalActionPerformed) -and
            ($authCertStatus.HybridSetupDetected)) {
                Write-Host ("")
                Write-Host ("The renewal action was successfully performed - the new Auth Certificate will become active on: $($renewalActionResult.AuthCertificateActivationDate)") -ForegroundColor Green
                Write-Host ("Please ensure to run the Hybrid Configuration Wizard (HCW) as soon as the new Auth Certificate becomes active.") -ForegroundColor Green
            } else {
                Write-Host ("")
                Write-Host ("There was an issue while performing the renewal action - please check the verbose script log for more details.") -ForegroundColor Red
            }
        } else {
            Write-Host ("")
            Write-Host ("Test result: $($renewalActionWording)") -ForegroundColor Cyan
        }

        if (($renewalActionRequired) -and
            ($renewalActionResult.RenewalActionPerformed) -and
            ($authCertStatus.MultipleExchangeADSites)) {
            $multipleExchangeADSitesWording = (
                "We've successfully created a new certificate which was then configured as Auth Certificate." +
                "`r`nThe new certificate has the following thumbprint: $($renewalActionResult.NewCertificateThumbprint)" +
                "`r`n`nWe've also detected that Exchange is installed in multiple Active Directory sites. In rare cases the Exchange certificate servicelet " +
                "will fail to deploy the certificate to the other AD sites. `r`nYou can validate that the certificate was deployed by running the following command " +
                "on an Exchange server located in a different site than this server:" +
                "`r`n`nGet-ExchangeCertificate -Thumbprint $($renewalActionResult.NewCertificateThumbprint)" +
                "`r`n`nPlease export the Auth Certificate manually if it is missing in the other site and import it to an Exchange server." +
                "`r`nIt will then be automatically deployed to all Exchange servers within that particular AD site."
            )

            Write-Host ""
            Write-Host ($multipleExchangeADSitesWording) -ForegroundColor Yellow
        }
    }
}

try {
    $loggerParams = @{
        LogName        = "AuthCertificateMonitoringLog"
        LogDirectory   = (New-AuthCertificateMonitoringLogFolder)
        AppendDateTime = $true
        ErrorAction    = "SilentlyContinue"
    }

    $Script:Logger = Get-NewLoggerInstance @loggerParams
    SetProperForegroundColor
    SetWriteHostAction ${Function:Write-DebugLog}
    SetWriteVerboseAction ${Function:Write-DebugLog}

    Main
} finally {
    Write-Host ""
    Write-Host ("Log file written to: $($Script:Logger.FullPath)")
    Write-Host ""
    Write-Host ("Do you have feedback regarding the script? Please email ExToolsFeedback@microsoft.com.") -ForegroundColor Green
    Write-Host ""

    if ($Error.Count -ne 0) {
        foreach ($e in (Get-UnhandledErrors)) {
            Write-Host ("Unhandled error hit:") -ForegroundColor Red
            Write-Host ($e.ErrorInformation) -ForegroundColor Red
        }
    } else {
        Write-Verbose ("No errors occurred within the script")
    }
    RevertProperForegroundColor
}
