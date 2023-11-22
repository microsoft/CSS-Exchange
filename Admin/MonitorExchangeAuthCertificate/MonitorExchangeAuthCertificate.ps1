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
.PARAMETER SendEmailNotificationTo
    This optional parameter can be used to specify recipients which will then be notified in case that an Exchange Auth Certificate renewal action
    was performed.
.PARAMETER TrustAllCertificates
    This optional parameter can be used to trust all certificates when connecting to the EWS service to send out email notifications.
.PARAMETER TestEmailNotification
    This optional parameter can be used to test the email notification feature of the script.
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

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $true, ParameterSetName = "TestEmailNotification")]
    [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
    [string[]]$SendEmailNotificationTo,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $false, ParameterSetName = "TestEmailNotification")]
    [switch]$TrustAllCertificates,

    [Parameter(Mandatory = $false, ParameterSetName = "TestEmailNotification")]
    [switch]$TestEmailNotification,

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
. $PSScriptRoot\..\..\Shared\EMailFunctions\Send-EwsMailMessage.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

. $PSScriptRoot\ConfigurationAction\Build-ExchangeAuthCertificateManagementAccount.ps1
. $PSScriptRoot\ConfigurationAction\Copy-ScriptToExchangeDirectory.ps1
. $PSScriptRoot\ConfigurationAction\Export-ExchangeAuthCertificate.ps1
. $PSScriptRoot\ConfigurationAction\Import-ExchangeAuthCertificateToServers.ps1
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
            WhatIf              = $WhatIfPreference
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
    $localServerFqdn = (([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName).ToLower()

    if ($ExportAuthCertificatesAsPfx) {
        Write-Host ("Mode: Export all Exchange Auth Certificates available on this system")

        if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
            Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
            return
        }

        $authCertificateExportParams = @{
            Password            = $Password
            CatchActionFunction = ${Function:Invoke-CatchActions}
            WhatIf              = $WhatIfPreference
        }

        $authCertificateExportStatusObject = Export-ExchangeAuthCertificate @authCertificateExportParams

        if ($authCertificateExportStatusObject.CertificatesAvailableToExport) {
            Write-Host ("There is/are $($authCertificateExportStatusObject.NumberOfCertificatesToExport) certificate(s) that could be exported")
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

    if ($TestEmailNotification) {
        Write-Host ("Mode: Test email notification feature")

        $sendEmailNotificationTestParams = @{
            To                  = $SendEmailNotificationTo
            Subject             = "[Test] An Exchange Auth Certificate maintenance action was performed"
            Importance          = "Low"
            Body                = "This is a test message sent by the MonitorExchangeAuthCertificate.ps1 script.<BR><B>No action is required!</B>"
            EwsServiceUrl       = (Get-WebServicesVirtualDirectory -Server $env:COMPUTERNAME -ADPropertiesOnly).InternalUrl.AbsoluteUri
            BodyAsHtml          = $true
            CatchActionFunction = ${Function:Invoke-CatchActions}
        }

        if ($TrustAllCertificates) {
            $sendEmailNotificationTestParams.Add("IgnoreCertificateMismatch", $true)
        }

        # Check for the last value as Send-EwsMailMessage returns the SendAndSaveCopy() result too (not sure how to suppress this yet)
        if (Send-EwsMailMessage @sendEmailNotificationTestParams) {
            Write-Host ("Please check if the test message was received by the following recipient(s): $($SendEmailNotificationTo)")
        } else {
            Write-Host ("We hit an exception while processing your test email message. Please check the log file") -ForegroundColor Yellow
            Write-Host ("`n$($Error[0].Exception.Message)") -ForegroundColor Red
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
                WhatIf              = $WhatIfPreference
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

                $scriptInfo = Copy-ScriptToExchangeDirectory -CatchActionFunction ${Function:Invoke-CatchActions} -WhatIf:$WhatIfPreference
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
                        WhatIf               = $WhatIfPreference
                    }

                    if ($null -ne $SendEmailNotificationTo) {
                        Write-Host ("We're trying to notify the following recipient(s): $($SendEmailNotificationTo)")
                        $registerSchTaskParams.Add("SendEmailNotificationTo", $SendEmailNotificationTo)

                        if ($TrustAllCertificates) {
                            Write-Host ("We trust all certificates when connecting to EWS service")
                            $registerSchTaskParams.Add("TrustAllCertificates", $true)
                        }
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
        Write-Host ("Mode: Testing and replacing or importing the Auth Certificate (if required)")
    } else {
        Write-Host ("The script was run without parameter therefore, only a check of the Auth Certificate configuration is performed and no change will be made")
    }

    if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
        Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
        return
    }

    if ($null -ne $SendEmailNotificationTo) {
        $sendEmailNotificationParams = @{
            To                  = $SendEmailNotificationTo
            Subject             = "[Action required] An Exchange Auth Certificate maintenance action was performed"
            Importance          = "High"
            EwsServiceUrl       = (Get-WebServicesVirtualDirectory -Server $env:COMPUTERNAME -ADPropertiesOnly).InternalUrl.AbsoluteUri
            BodyAsHtml          = $true
            CatchActionFunction = ${Function:Invoke-CatchActions}
        }

        $emailBodyBase = "On $(Get-Date) we performed an Exchange Auth Certificate maintenance action.<BR>" +
        "Due to your Exchange Server or organization configuration, manual actions may be required.<BR><BR>"
    }

    $authCertificateStatusParams = @{
        IgnoreUnreachableServers = $IgnoreUnreachableServers
        IgnoreHybridSetup        = $IgnoreHybridConfig
        CatchActionFunction      = ${Function:Invoke-CatchActions}
    }
    $authCertStatus = Get-ExchangeAuthCertificateStatus @authCertificateStatusParams

    $noRenewalDueToUnreachableServers = (($authCertStatus.NumberOfUnreachableServers -gt 0) -and ($IgnoreUnreachableServers -eq $false))
    $stopProcessingDueToHybrid = $authCertStatus.StopProcessingDueToHybrid
    $renewalActionRequired = (($authCertStatus.ReplaceRequired) -or
        ($authCertStatus.ConfigureNextAuthRequired) -or
        ($authCertStatus.CurrentAuthCertificateImportRequired) -or
        ($authCertStatus.NextAuthCertificateImportRequired))

    if ($authCertStatus.ReplaceRequired) {
        $renewalActionWording = "The Auth Certificate in use must be replaced by a new one."
    } elseif ($authCertStatus.ConfigureNextAuthRequired) {
        $renewalActionWording = "The Auth Certificate configured as next Auth Certificate must be configured or replaced by a new one."
    } elseif (($authCertStatus.CurrentAuthCertificateImportRequired) -or
        ($authCertStatus.NextAuthCertificateImportRequired)) {
        $renewalActionWording = "The current or next Auth Certificate is missing on some servers and must be imported."
    } else {
        $renewalActionWording = "No renewal action is required"
    }

    if ($noRenewalDueToUnreachableServers) {
        Write-Host ("We couldn't validate if the Auth Certificate is properly configured because $($authCertStatus.NumberOfUnreachableServers) servers were unreachable.") -ForegroundColor Yellow
        Write-Host ("The unreachable servers are: $([string]::Join(", ", $authCertStatus.UnreachableServersList))") -ForegroundColor Yellow
    } elseif ($stopProcessingDueToHybrid) {
        Write-Host ("We have not made any configuration change because Exchange Hybrid has been detected in your environment.") -ForegroundColor Yellow
        Write-Host ("Please rerun the script using the '-IgnoreHybridConfig `$true' parameter to perform the renewal action.") -ForegroundColor Yellow
        Write-Host ("It's also required to run the Hybrid Configuration Wizard (HCW) after the primary Auth Certificate was replaced.") -ForegroundColor Yellow
    } else {
        if (($ValidateAndRenewAuthCertificate) -and
            ($renewalActionRequired)) {
            Write-Host ("Renewal scenario: $($renewalActionWording)")
            if ($authCertStatus.ReplaceRequired) {
                $replaceExpiredAuthCertificateParams = @{
                    ReplaceExpiredAuthCertificate = $true
                    CatchActionFunction           = ${Function:Invoke-CatchActions}
                    WhatIf                        = $WhatIfPreference
                }
                $renewalActionResult = New-ExchangeAuthCertificate @replaceExpiredAuthCertificateParams

                $emailBodyRenewalScenario = "The Auth Certificate in use was invalid (expired) or not available on all Exchange Servers within your organization.<BR>" +
                "It was immediately replaced by a new one which is already active.<BR><BR>"
            } elseif ($authCertStatus.ConfigureNextAuthRequired) {
                $configureNextAuthCertificateParams = @{
                    ConfigureNextAuthCertificate         = $true
                    CurrentAuthCertificateLifetimeInDays = $authCertStatus.CurrentAuthCertificateLifetimeInDays
                    CatchActionFunction                  = ${Function:Invoke-CatchActions}
                    WhatIf                               = $WhatIfPreference
                }
                $renewalActionResult = New-ExchangeAuthCertificate @configureNextAuthCertificateParams

                $emailBodyRenewalScenario = "The new Auth Certificate will replace the current one on: <B>$($renewalActionResult.AuthCertificateActivationDate)</B>, " +
                "as soon as the AuthAdmin servicelet runs the next time (from the mentioned date within 12 hours).<BR><BR>"
            } elseif (($authCertStatus.CurrentAuthCertificateImportRequired) -or
                ($authCertStatus.NextAuthCertificateImportRequired)) {

                if ($authCertStatus.CurrentAuthCertificateImportRequired) {
                    $importCurrentAuthCertificateParams = @{
                        Thumbprint          = $authCertStatus.CurrentAuthCertificateThumbprint
                        ServersToImportList = $authCertStatus.AuthCertificateMissingOnServers
                        CatchActionFunction = ${Function:Invoke-CatchActions}
                        WhatIf              = $WhatIfPreference
                    }

                    if ($authCertStatus.AuthCertificateMissingOnServers.ToLower().Contains($localServerFqdn)) {
                        Write-Verbose ("Current Auth Certificate can't be exported from the local system - must be exported from another server")
                        $importCurrentAuthCertificateParams.Add("ExportFromServer", $authCertStatus.AuthCertificateFoundOnServers[0])
                    }
                    $importCurrentAuthCertificateResults = Import-ExchangeAuthCertificateToServers @importCurrentAuthCertificateParams

                    $emailBodyImportCurrentAuthCertificateResult = "The current Auth Certificate is valid but was missing on some servers.<BR>" +
                    "It was imported to the following server(s): <B>$([string]::Join(", ", $importCurrentAuthCertificateResults.ImportedToServersList))</B><BR><BR>"

                    if ($importCurrentAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                        $emailBodyImportCurrentAuthCertificateResult += "We failed to import it to the following servers: <B>$([string]::Join(", ", $importCurrentAuthCertificateResults.ImportToServersFailedList))</B><BR>" +
                        "Please export the Auth Certificate manually and import it on these Exchange server(s).<BR><BR>"
                    }
                }

                if ($authCertStatus.NextAuthCertificateImportRequired) {
                    $importNextAuthCertificateParams = @{
                        Thumbprint          = $authCertStatus.NextAuthCertificateThumbprint
                        ServersToImportList = $authCertStatus.NextAuthCertificateMissingOnServers
                        CatchActionFunction = ${Function:Invoke-CatchActions}
                        WhatIf              = $WhatIfPreference
                    }

                    if ($authCertStatus.NextAuthCertificateMissingOnServers.ToLower().Contains($localServerFqdn)) {
                        Write-Verbose ("Next Auth Certificate can't be exported from the local system - must be exported from another server")
                        $importNextAuthCertificateParams.Add("ExportFromServer", $authCertStatus.NextAuthCertificateFoundOnServers[0])
                    }
                    $importNextAuthCertificateResults = Import-ExchangeAuthCertificateToServers @importNextAuthCertificateParams

                    $emailBodyImportNextAuthCertificateResult = "The next Auth Certificate is valid but was missing on some servers.<BR>" +
                    "It was imported to the following server(s): <B>$([string]::Join(", ", $importNextAuthCertificateResults.ImportedToServersList))</B><BR><BR>"

                    if ($importNextAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                        $emailBodyImportNextAuthCertificateResult += "We failed to import it to the following servers: <B>$([string]::Join(", ", $importNextAuthCertificateResults.ImportToServersFailedList))</B><BR>" +
                        "Please export the next Auth Certificate manually and import it on these Exchange server(s).<BR><BR>"
                    }
                }
            }

            if ($authCertStatus.HybridSetupDetected) {
                $emailBodyHybrid = "Please ensure to run the Hybrid Configuration Wizard (HCW) as soon as the new Auth Certificate replaces the active one."
            }

            if ($renewalActionResult.RenewalActionPerformed) {
                $emailBodyRenewalAction = "New Exchange Auth Certificate thumbprint: <B>$($renewalActionResult.NewCertificateThumbprint)</B><BR>" +
                $emailBodyRenewalScenario
            }

            if ($authCertStatus.MultipleExchangeADSites) {
                $emailBodyMultiADSites = "Please validate that the newly created Auth Certificate was successfully replicated to all Exchange Servers (except Edge Transport) " +
                "which are located in another Active-Directory site.<BR>" +
                "You can do so by running the following command against one Exchange Server per AD site:<BR><BR>" +
                "Get-ExchangeCertificate -Server 'ServerName' -Thumbprint $($renewalActionResult.NewCertificateThumbprint)<BR><BR>" +
                "If you run the script again, it will try to import the newly created certificate to all servers where it's missing.<BR><BR>" +
                "However, if you still find that the Auth Certificate is missing on a server in a different AD site, please follow these steps:<BR><BR>" +
                "1. Export the Auth Certificate: .\MonitorExchangeAuthCertificate.ps1 -ExportAuthCertificatesAsPfx<BR>" +
                "2. Import it to the Computer Accounts 'Personal' certificate store on an Exchange Server per other AD site<BR><BR>" +
                "The Auth Certificate will then be automatically replicated to all Exchange Servers within this AD site.<BR><BR>"
            }

            $emailBodyFailure = "We ran into an issue while trying to renew the Exchange Auth Certificate. Please check the verbose script log for more details.<BR>" +
            "You can find it under: '$($Script:Logger.FullPath)' on computer: $($env:COMPUTERNAME)"

            if (($renewalActionResult.RenewalActionPerformed) -and
            ($authCertStatus.HybridSetupDetected -eq $false)) {
                if ($null -ne $emailBodyBase) {
                    if ($authCertStatus.MultipleExchangeADSites) {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + $emailBodyMultiADSites
                    } else {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + "No further action is required on your part."
                    }
                }
                Write-Host ("")
                Write-Host ("The renewal action was successfully performed") -ForegroundColor Green
            } elseif (($renewalActionResult.RenewalActionPerformed) -and
            ($authCertStatus.HybridSetupDetected)) {
                if ($null -ne $emailBodyBase) {
                    if ($authCertStatus.MultipleExchangeADSites) {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + $emailBodyMultiADSites + $emailBodyHybrid
                    } else {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + $emailBodyHybrid
                    }
                }
                Write-Host ("")
                Write-Host ("The renewal action was successfully performed - the new Auth Certificate will become active on: $($renewalActionResult.AuthCertificateActivationDate)") -ForegroundColor Green
                Write-Host ("Please ensure to run the Hybrid Configuration Wizard (HCW) as soon as the new Auth Certificate becomes active.") -ForegroundColor Green
            } elseif (($null -ne $importCurrentAuthCertificateResults) -or
                ($null -ne $importNextAuthCertificateResults)) {
                $importFailedAppendixWording = (
                    "Our approach to automatically import the certificate failed." +
                    "`r`nPlease export the Auth Certificate manually and import it to the Exchange servers where it's missing." +
                    "`r`nIt's sufficient to import it to at least one Exchange server per AD site." +
                    "`r`nIt will then be automatically deployed to all Exchange servers within that particular AD site."
                )
                $importTriedWording = "`r`nWe've tried to import it to those Exchange servers and this is the result:"
                $importFailedWording = "Import failed: {0}"
                $importSuccessfulWording = "Import successful: {0}"

                if ($null -ne $importCurrentAuthCertificateResults) {
                    Write-Host ("")
                    if ($null -ne $emailBodyBase) {
                        $finalEmailBody = $emailBodyBase + $emailBodyImportCurrentAuthCertificateResult
                    }

                    Write-Host ("The current Auth Certificate: $($authCertStatus.CurrentAuthCertificateThumbprint) is valid but missing on the following server(s):") -ForegroundColor Yellow
                    Write-Host ([string]::Join(", ", $authCertStatus.AuthCertificateMissingOnServers)) -ForegroundColor Yellow
                    if ($importCurrentAuthCertificateResults.ExportSuccessful) {
                        Write-Host ($importTriedWording)
                        if ($importCurrentAuthCertificateResults.ImportedToServersList.Count -gt 0) {
                            Write-Host ($importSuccessfulWording -f [string]::Join(", ", $importCurrentAuthCertificateResults.ImportedToServersList)) -ForegroundColor Green
                        }

                        if ($importCurrentAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                            Write-Host ($importFailedWording -f [string]::Join(", ", $importCurrentAuthCertificateResults.ImportToServersFailedList)) -ForegroundColor Yellow
                            Write-Host ($importFailedAppendixWording) -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host $importFailedAppendixWording -ForegroundColor Yellow
                    }
                }

                if ($null -ne $importNextAuthCertificateResults) {
                    Write-Host ("")
                    if (($null -ne $emailBodyBase) -and
                        ($null -eq $finalEmailBody)) {
                        # No email content available as the current Auth Certificate wasn't imported before
                        $finalEmailBody = $emailBodyBase + $emailBodyImportNextAuthCertificateResult
                    } elseif (($null -ne $emailBodyBase) -and
                        ($null -ne $finalEmailBody)) {
                        # Email content available as the current Auth Certificate was imported too
                        $finalEmailBody = $finalEmailBody + $emailBodyImportNextAuthCertificateResult
                    }

                    Write-Host ("The next Auth Certificate: $($authCertStatus.NextAuthCertificateThumbprint) is valid but missing on the following server(s):") -ForegroundColor Yellow
                    Write-Host ([string]::Join(", ", $authCertStatus.NextAuthCertificateMissingOnServers)) -ForegroundColor Yellow
                    if ($importNextAuthCertificateResults.ExportSuccessful) {
                        Write-Host ($importTriedWording)
                        if ($importNextAuthCertificateResults.ImportedToServersList.Count -gt 0) {
                            Write-Host ($importSuccessfulWording -f [string]::Join(", ", $importNextAuthCertificateResults.ImportedToServersList)) -ForegroundColor Green
                        }

                        if ($importNextAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                            Write-Host ($importFailedWording -f [string]::Join(", ", $importNextAuthCertificateResults.ImportToServersFailedList)) -ForegroundColor Yellow
                            Write-Host ($importFailedAppendixWording) -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host $exportFailedWording -ForegroundColor Yellow
                    }
                }
            } else {
                if ($null -ne $emailBodyBase) {
                    $finalEmailBody = $emailBodyBase + $emailBodyFailure
                }
                Write-Host ("")
                Write-Host ("There was an issue while performing the appropriate action - please check the verbose script log for more details.") -ForegroundColor Red
            }
        } else {
            Write-Host ""
            Write-Host ("Current Auth Certificate thumbprint: $($authCertStatus.CurrentAuthCertificateThumbprint)") -ForegroundColor Cyan
            Write-Host ("Current Auth Certificate is valid for $($authCertStatus.CurrentAuthCertificateLifetimeInDays) day(s)") -ForegroundColor Cyan
            if (-not([string]::IsNullOrEmpty($authCertStatus.NextAuthCertificateThumbprint))) {
                Write-Host ("Next Auth Certificate thumbprint: $($authCertStatus.NextAuthCertificateThumbprint)") -ForegroundColor Cyan
                Write-Host ("Next Auth Certificate is valid for $($authCertStatus.NextAuthCertificateLifetimeInDays) day(s)") -ForegroundColor Cyan
            }
            if ($authCertStatus.MultipleExchangeADSites) {
                Write-Host ("We've detected Exchange servers in multiple AD sites") -ForegroundColor Cyan
            }
            if ($authCertStatus.HybridSetupDetected) {
                Write-Host ("Exchange Hybrid was detected in this environment") -ForegroundColor Cyan
            }
            if ($authCertStatus.NumberOfUnreachableServers -gt 0) {
                Write-Host ("Number of unreachable Exchange servers: $($authCertStatus.NumberOfUnreachableServers)") -ForegroundColor Cyan
            }
            if ($authCertStatus.AuthCertificateMissingOnServers.Count -gt 0) {
                Write-Host ("`r`nThe actively used Auth Certificate is missing on the following servers:") -ForegroundColor Cyan
                Write-Host ("$([string]::Join(", ", $authCertStatus.AuthCertificateMissingOnServers))") -ForegroundColor Cyan
            }
            if ($authCertStatus.NextAuthCertificateMissingOnServers.Count -gt 0) {
                Write-Host ("`r`nThe certificate which is configured as next Auth Certificate is missing on the following servers:") -ForegroundColor Cyan
                Write-Host ("$([string]::Join(", ", $authCertStatus.NextAuthCertificateMissingOnServers))") -ForegroundColor Cyan
            }
            Write-Host ("")
            Write-Host ("Test result: $($renewalActionWording)") -ForegroundColor Cyan
            if ((($authCertStatus.AuthCertificateMissingOnServers.Count -gt 0) -and
                ($authCertStatus.CurrentAuthCertificateImportRequired)) -or
                (($authCertStatus.NextAuthCertificateMissingOnServers.Count -gt 0) -and
                ($authCertStatus.NextAuthCertificateImportRequired))) {
                Write-Host ("`rThe script will try to import the certificate to the missing servers automatically (as long as it's valid).") -ForegroundColor Cyan
            }
        }

        if (($renewalActionRequired) -and
            ($renewalActionResult.RenewalActionPerformed) -and
            ($authCertStatus.MultipleExchangeADSites)) {
            $multipleExchangeADSitesWording = (
                "We've successfully created a new certificate which was then configured as Auth Certificate." +
                "`r`nThe new certificate has the following thumbprint: $($renewalActionResult.NewCertificateThumbprint)" +
                "`r`n`nWe've also detected that Exchange is installed in multiple Active Directory sites. In rare cases the Exchange certificate servicelet " +
                "will fail to deploy the certificate to the other AD sites. `r`nYou can validate that the certificate was deployed by running the following command " +
                "on an Exchange server located in a different AD site than this server:" +
                "`r`n`nGet-ExchangeCertificate -Server <ServerFqdn> -Thumbprint $($renewalActionResult.NewCertificateThumbprint)" +
                "`r`n`nIf you run the script again, it will try to import the certificate to the server(s) where it's missing." +
                "`r`nHowever, we recommend to wait for at least 24 hours to let Exchange Server perform the certificate replication task."
            )

            Write-Host ""
            Write-Host ($multipleExchangeADSitesWording) -ForegroundColor Yellow
        }

        if ((-not($WhatIfPreference)) -and
            (($renewalActionResult.RenewalActionPerformed) -or
                ($null -ne $importCurrentAuthCertificateResults) -or
                ($null -ne $importNextAuthCertificateResults)) -and
            (-not([System.String]::IsNullOrEmpty($SendEmailNotificationTo)))) {
            Write-Host ("`r`nTrying to send out email notification to the following recipients: $($SendEmailNotificationTo)")
            $sendEmailNotificationParams.Add("Body", $finalEmailBody)

            if ($TrustAllCertificates) {
                $sendEmailNotificationParams.Add("IgnoreCertificateMismatch", $true)
            }

            if (Send-EwsMailMessage @sendEmailNotificationParams) {
                Write-Host ("An email message was successfully sent")
            } else {
                Write-Host ("We ran into an issue while trying to notify you via email - please check the log of the script") -ForegroundColor Yellow
            }
        }
    }
}

try {
    $loggerParams = @{
        LogName        = "AuthCertificateMonitoringLog"
        LogDirectory   = (New-AuthCertificateMonitoringLogFolder -WhatIf:$WhatIfPreference)
        AppendDateTime = $true
        ErrorAction    = "SilentlyContinue"
    }

    if (-not($WhatIfPreference)) {
        $Script:Logger = Get-NewLoggerInstance @loggerParams
        SetProperForegroundColor
        SetWriteHostAction ${Function:Write-DebugLog}
        SetWriteVerboseAction ${Function:Write-DebugLog}
    }

    Main
} finally {
    Write-Host ""
    if (-not($WhatIfPreference)) {
        Write-Host ("Log file written to: $($Script:Logger.FullPath)")
    } else {
        Write-Host ("Script was executed by using '-WhatIf' parameter - no action was performed and no log file was generated")
    }
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
    if (-not($WhatIfPreference)) {
        RevertProperForegroundColor
    }
}
