# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 23.01.13.1832

#Requires -Version 5.1
#Requires -Modules AzureAD, ExchangeOnlineManagement

<#
.SYNOPSIS
    This script offers the ability to validate users and org settings related to the Cross-tenant mailbox migration before creating a migration batch and have a better experience.

.DESCRIPTION
    This script is intended to be used for:
    - Making sure the source mailbox object is a member of the Mail-Enabled Security Group defined on the MailboxMovePublishedScopes of the source organization relationship
    - Making sure the source mailbox object ExchangeGuid attribute value matches the one from the target MailUser object, and give you the option to set it
    - Making sure the source mailbox object ArchiveGuid attribute (if there's an Archive enabled) value matches the one from the target MailUser object, and give you the option to set it
    - Making sure the source mailbox object has no more than 12 auxArchives
    - Making sure the source mailbox object has no hold applied
    - Making sure the source mailbox object TotalDeletedItemsSize is not bigger than Target MailUser recoverable items size
    - Making sure the source mailbox object LegacyExchangeDN attribute value is present on the target MailUser object as an X500 proxyAddress, and give you the option to set it, as long as the Target MailUser is not DirSynced
    - Making sure the target MailUser object PrimarySMTPAddress attribute value is part of the target tenant accepted domains and give you the option to set it to be like the UPN if not true, as long as the Target MailUser is not DirSynced
    - Making sure the target MailUser object EmailAddresses are all part of the target tenant accepted domains and give you the option to remove them if any doesn't belong to are found, as long as the Target MailUser is not DirSynced
    - Making sure the target MailUser object ExternalEmailAddress attribute value points to the source Mailbox object PrimarySMTPAddress and give you the option to set it if not true, as long as the Target MailUser is not DirSynced
    - Checking if there's an AAD app as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-destination-tenant-by-creating-the-migration-application-and-secret
    - Checking if the target tenant has an Organization Relationship as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-tenant-by-creating-the-exchange-online-migration-endpoint-and-organization-relationship
    - Checking if the target tenant has a Migration Endpoint as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-tenant-by-creating-the-exchange-online-migration-endpoint-and-organization-relationship
    - Checking if the source tenant has an Organization Relationship as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-source-current-mailbox-location-tenant-by-accepting-the-migration-application-and-configuring-the-organization-relationship including a Mail-Enabled security group defined on the MailboxMovePublishedScopes property.
    - Gather all the necessary information for troubleshooting and send it to Microsoft Support if needed
    - Because not all scenarios allow access to both tenants by the same person, this will also allow you to collect the source tenant and mailbox information and wrap it into a zip file so the target tenant admin can use it as a source to validate against.

    The script will prompt you to connect to your source and target tenants for EXO and AAD as needed
    You can decide to run the checks for the source mailbox and target MailUser (individually or by providing a CSV file), for the organization settings described above, collect the source information and compress it to a zip file that can be used by the target tenant admins, or use the collected zip file as a source to validate the target objects and configurations against it.

    PRE-REQUISITES:
    -Please make sure you have at least the Exchange Online V2 Powershell module (https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-and-maintain-the-exo-v2-module)
    -You would need the Azure AD Module (https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0#installing-the-azure-ad-module)
    -Also, depending on the parameters you specify, you will be prompted for the SourceTenantId and TargetTenantId (i.e.: if you choose to run the script with the "CheckOrgs" parameter). To obtain the tenant ID of a subscription, sign in to the Microsoft 365 admin center and go to https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties. Click the copy icon for the Tenant ID property to copy it to the clipboard.


.PARAMETER CheckObjects
        This will allow you to perform the checks for the Source Mailbox and Target MailUser objects you provide. If used without the "-CSV" parameter, you will be prompted to type the identities.. If used with the '-SourceIsOffline' you also need to specify the '-PathForCollectedData' parameter

.PARAMETER CSV
        This will allow you to specify a path for a CSV file you have with a list of users that contain the "SourceUser, TargetUser" columns.
        An example of the CSV file content would be:
        SourceUser, TargetUser
        Jdoe@contoso.com, Jdoe@fabrikam.com
        BSmith@contoso.com, BSmith@fabrikam.com

        If Used along with the 'CollectSourceOnly' parameter, you only need the 'SourceUser' column.

.PARAMETER CheckOrgs
        This will allow you to perform the checks for the source and target organizations. More specifically the organization relationship on both tenants, the migration endpoint on target tenant and the existence of the AAD application needed.

.PARAMETER SDP
        This will collect all the relevant information for troubleshooting from both tenants and be able to send it to Microsoft Support in case of needed.

.PARAMETER LogPath
        This will allow you to specify a log path to transcript all the script execution and it's results. This parameter is mandatory.

.PARAMETER CollectSourceOnly
        This will allow you to specify a CSV file so we can export all necessary data of the source tenant and mailboxes to migrate, compress the files as a zip file to be used by the target tenant admin as a source for validation against the target. This parameter is mandatory and also requires the '-CSV' parameter to be specified containing the SourceUser column.

.PARAMETER PathForCollectedData
        This will allow you to specify a path to store the exported data from the source tenant when used along with the 'CollectSourceOnly' and 'SDP' parameters transcript all the script execution and it's results. This parameter is mandatory.

.PARAMETER SourceIsOffline
        With this parameter, the script will only connect to target tenant and not source, instead it will rely on the zip file gathered when running this script along with the 'CollectSourceOnly' parameter. When used, you also need to specify the 'PathForCollectedData' parameter pointing to the collected zip file.

.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -CheckObjects -LogPath C:\Temp\LogFile.txt
        This will prompt you to type the source mailbox identity and the target identity, will establish 2 EXO remote powershell sessions (one to the source tenant and another one to the target tenant), and will check the objects.

.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -CheckObjects -CSV C:\Temp\UsersToMigrateValidationList.CSV -LogPath C:\Temp\LogFile.txt
        This will establish 2 EXO remote powershell sessions (one to the source tenant and another one to the target tenant), will import the CSV file contents and will check the objects one by one.

.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -CheckOrgs -LogPath C:\Temp\LogFile.txt
        This will prompt you for the sourceTenantId and TargetTenantId, establish 3 remote powershell sessions (one to the source EXO tenant, one to the target EXO tenant and another one to AAD target tenant), and will validate the migration endpoint on the target tenant, AAD applicationId on target tenant and the Organization relationship on both tenants.

.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -SDP -LogPath C:\Temp\LogFile.txt
        This will prompt you for the sourceTenantId and TargetTenantId, establish 3 remote powershell sessions (one to the source EXO tenant, one to the target EXO tenant and another one to AAD target tenant), and will collect all the relevant information (config-wise) so it can be used for troubleshooting and send it to Microsoft Support if needed.

.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -SourceIsOffline -PathForCollectedData C:\temp\CTMMCollectedSourceData.zip -CheckObjects -LogPath C:\temp\CTMMTarget.log
        This will expand the CTMMCollectedSourceData.zip file contents into a folder with the same name within the zip location, will establish the EXO remote powershell session and also with AAD against the Target tenant and will check the objects contained on the UsersToProcess.CSV file.

.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -SourceIsOffline -PathForCollectedData C:\temp\CTMMCollectedSourceData.zip -CheckOrgs -LogPath C:\temp\CTMMTarget.log
        This will expand the CTMMCollectedSourceData.zip file contents into a folder with the same name within the zip location, will establish the EXO remote powershell session and also with AAD against the Target tenant, and will validate the migration endpoint on the target tenant, AAD applicationId on target tenant and the Organization relationship on both tenants.

.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -CollectSourceOnly -PathForCollectedData c:\temp -LogPath C:\temp\CTMMCollectSource.log -CSV C:\temp\UsersToMigrate.csv
        This will connect to the Source tenant against AAD and EXO, and will collect all the relevant information (config and user wise) so it can be used passed to the Target tenant admin for the Target validation to be done without the need to connect to the source tenant at the same time.
.#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomRules\AvoidUsingReadHost', '', Justification = 'Do not want to change logic of script as of now')]
param (
    [Parameter(Mandatory = $True, ParameterSetName = "ObjectsValidation", HelpMessage = "Validate source Mailbox and Target MailUser objects. If used alone you will be prompted to introduce the identities you want to validate")]
    [Parameter(Mandatory = $False, ParameterSetName = "OfflineMode", HelpMessage = "Validate source Mailbox and Target MailUser objects. If used alone you will be prompted to introduce the identities you want to validate")]
    [System.Management.Automation.SwitchParameter]$CheckObjects,
    [Parameter(Mandatory = $False, ParameterSetName = "ObjectsValidation", HelpMessage = "Path pointing to the CSV containing the identities to validate. CheckObjects parameter needs also to be specified")]
    [Parameter(Mandatory = $True, ParameterSetName = "CollectMode", HelpMessage = "Path pointing to the CSV containing the identities to validate. CheckObjects parameter needs also to be specified")]
    [System.String]$CSV,
    [Parameter(Mandatory = $True, HelpMessage = "Path pointing to the log file")]
    [System.String]$LogPath,
    [Parameter(Mandatory = $True, ParameterSetName = "OrgsValidation", HelpMessage = "Validate the organizations settings like organization relationships, migration endpoint and AADApplication")]
    [Parameter(Mandatory = $False, ParameterSetName = "OfflineMode", HelpMessage = "Validate the organizations settings like organization relationships, migration endpoint and AADApplication")]
    [System.Management.Automation.SwitchParameter]$CheckOrgs,
    [Parameter(Mandatory = $True, ParameterSetName = "SDP", HelpMessage = "Collect relevant data for troubleshooting purposes and send it to Microsoft Support if needed")]
    [System.Management.Automation.SwitchParameter]$SDP,
    [Parameter(Mandatory = $False, ParameterSetName = "CollectMode", HelpMessage = "Collect source only mode, to generate the necessary files and provide them to the target tenant admin. You need to specify the CSV parameter as well")]
    [System.Management.Automation.SwitchParameter]$CollectSourceOnly,
    [Parameter(Mandatory = $True, ParameterSetName = "SDP", HelpMessage = "Path that will be used to store the collected data")]
    [Parameter(Mandatory = $True, ParameterSetName = "CollectMode", HelpMessage = "Path that will be used to store the collected data")]
    [Parameter(Mandatory = $True, ParameterSetName = "OfflineMode", HelpMessage = "Path that will be used to store the collected data, you should specify the path and the zip file name")]
    [System.String]$PathForCollectedData,
    [Parameter(Mandatory = $false, ParameterSetName = "OfflineMode", HelpMessage = "Do not connect to source EXO tenant, but specify a zip file gathered when running the script with the 'CollectSourceOnly' parameter.")]
    [System.Management.Automation.SwitchParameter]$SourceIsOffline
)

function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Proper handling of write host with colors')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$Object,
        [switch]$NoNewLine,
        [string]$ForegroundColor
    )
    process {
        $consoleHost = $host.Name -eq "ConsoleHost"

        if ($null -ne $Script:WriteHostManipulateObjectAction) {
            $Object = & $Script:WriteHostManipulateObjectAction $Object
        }

        $params = @{
            Object    = $Object
            NoNewLine = $NoNewLine
        }

        if ([string]::IsNullOrEmpty($ForegroundColor)) {
            if ($null -ne $host.UI.RawUI.ForegroundColor -and
                $consoleHost) {
                $params.Add("ForegroundColor", $host.UI.RawUI.ForegroundColor)
            }
        } elseif ($ForegroundColor -eq "Yellow" -and
            $consoleHost -and
            $null -ne $host.PrivateData.WarningForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.WarningForegroundColor)
        } elseif ($ForegroundColor -eq "Red" -and
            $consoleHost -and
            $null -ne $host.PrivateData.ErrorForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.ErrorForegroundColor)
        } else {
            $params.Add("ForegroundColor", $ForegroundColor)
        }

        Microsoft.PowerShell.Utility\Write-Host @params

        if ($null -ne $Script:WriteHostDebugAction -and
            $null -ne $Object) {
            &$Script:WriteHostDebugAction $Object
        }
    }
}

function SetProperForegroundColor {
    $Script:OriginalConsoleForegroundColor = $host.UI.RawUI.ForegroundColor

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.WarningForegroundColor) {
        Write-Verbose "Foreground Color matches warning's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.ErrorForegroundColor) {
        Write-Verbose "Foreground Color matches error's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }
}

function RevertProperForegroundColor {
    $Host.UI.RawUI.ForegroundColor = $Script:OriginalConsoleForegroundColor
}

function SetWriteHostAction ($DebugAction) {
    $Script:WriteHostDebugAction = $DebugAction
}

function SetWriteHostManipulateObjectAction ($ManipulateObject) {
    $Script:WriteHostManipulateObjectAction = $ManipulateObject
}
$wsh = New-Object -ComObject WScript.Shell

function ConnectToEXOTenants {
    #Connect to SourceTenant (EXO)
    Write-Verbose -Message "Informational: Connecting to SOURCE EXO tenant"
    $wsh.Popup("You're about to connect to source tenant (EXO), please provide the SOURCE tenant admin credentials", 0, "SOURCE tenant") | Out-Null
    Connect-ExchangeOnline -Prefix Source -ShowBanner:$false

    #Connect to TargetTenant (EXO)
    Write-Verbose -Message "Informational: Connecting to TARGET EXO tenant"
    $wsh.Popup("You're about to connect to target tenant (EXO), please provide the TARGET tenant admin credentials", 0, "TARGET tenant") | Out-Null
    Connect-ExchangeOnline -Prefix Target -ShowBanner:$false
}
function ConnectToSourceEXOTenant {
    #Connect to SourceTenant (EXO)
    Write-Verbose -Message "Informational: Connecting to SOURCE EXO tenant"
    $wsh.Popup("You're about to connect to source tenant (EXO), please provide the SOURCE tenant admin credentials", 0, "SOURCE tenant") | Out-Null
    Connect-ExchangeOnline -Prefix Source -ShowBanner:$false
}
function ConnectToTargetEXOTenant {
    #Connect to SourceTenant (EXO)
    Write-Verbose -Message "Informational: Connecting to TARGET EXO tenant"
    $wsh.Popup("You're about to connect to target tenant (EXO), please provide the TARGET tenant admin credentials", 0, "TARGET tenant") | Out-Null
    Connect-ExchangeOnline -Prefix Target -ShowBanner:$false
}
function CheckObjects {

    Write-Host "Informational: Loading SOURCE object"$SourceIdentity
    $SourceObject = Get-SourceMailbox $SourceIdentity -ErrorAction SilentlyContinue
    Write-Host "Informational: Loading TARGET object"$TargetIdentity
    $TargetObject = Get-TargetMailUser $TargetIdentity -ErrorAction SilentlyContinue

    #Validate if SourceObject is present
    if ($SourceObject) {
        #Since SourceObject is valid, validate if TargetObject is present
        if ($TargetObject) {
            #Check if source mailbox has aux archives and if so throw error, otherwise continue with the rest of validations
            Write-Verbose -Message "Checking if SOURCE mailbox has any aux-archives present, and if so, no more than 12"
            $auxArchiveCount = 0
            $MailboxLocations = $SourceObject.MailboxLocations | Where-Object { ($_ -like '*auxArchive*') }
            $auxArchiveCount = $MailboxLocations.count
            Write-Verbose -Message $auxArchiveCount" aux archives are present on SOURCE mailbox"
            if ($auxArchiveCount -gt 12) {
                Write-Host ">> Error: The SOURCE mailbox has more than 12 auxArchive present and we can't migrate that much." -ForegroundColor Red
                exit
            } else {
                Write-Verbose -Message "No aux archives are present on SOURCE mailbox"

                #Check for the T2T license on any of the objects (either source or target) as long as the source mailbox is a regular mailbox
                Write-Verbose -Message "Informational: Source mailbox is regular, checking if either SOURCE mailbox or TARGET MailUser has the T2T license assigned"
                if ($SourceObject.RecipienTypeDetails -eq 'UserMailbox') {
                    if ($SourceObject.PersistedCapabilities -notmatch 'EXCHANGET2TMBXMOVE') {
                        if ($TargetObject.PersistedCapabilities -notmatch 'EXCHANGET2TMBXMOVE') {
                            Write-Host ">> Error: Neither SOURCE mailbox or TARGET MailUser have a valid T2T migration license. This is a pre-requisite, and if the license is not assigned by the time the migration is injected, it will fail to complete" -ForegroundColor Red
                        } else {
                            Write-Verbose -Message "TARGET MailUser has a valid T2T migration license"
                        }
                    } else {
                        Write-Verbose -Message "SOURCE mailbox has a valid T2T migration license"
                    }
                } else {
                    Write-Verbose -Message "Mailbox is not regular, skiping T2T migration license validation check"
                }

                #Verify if SOURCE mailbox is under any type of hold as we won't support this and will throw an error if this is the case
                Write-Verbose -Message "Informational: Checking if the SOURCE mailbox is under a litigation hold"
                if ($SourceObject.litigationHoldEnabled) {
                    Write-Host ">> Error: SOURCE mailbox is under Litigation Hold and this is not a supported scenario" -ForegroundColor Red
                } else {
                    Write-Verbose -Message "Mailbox is not under LitigationHold"
                }
                Write-Verbose -Message "Informational: Checking if the SOURCE mailbox is under any delay hold"
                if ($SourceObject.DelayHoldApplied) {
                    Write-Host ">> Error: SOURCE mailbox is under a Delay Hold Applied and this is not a supported scenario" -ForegroundColor Red
                } else {
                    Write-Verbose -Message "Mailbox is not under Delay Hold Applied"
                }
                if ($SourceObject.DelayReleaseHoldApplied) {
                    Write-Host ">> Error: SOURCE mailbox is under a Delay Release Hold and this is not a supported scenario" -ForegroundColor Red
                } else {
                    Write-Verbose -Message "Mailbox is not under Delay Release Hold"
                }
                if ($SourceObject.ComplianceTagHoldApplied) {
                    Write-Host ">> Error: SOURCE mailbox has labeled items with a Retention Label and this is not a supported scenario" -ForegroundColor Red
                } else {
                    Write-Verbose -Message "Mailbox is not under ComplianceTagHold"
                }
                if ($SourceObject.InPlaceHolds) {
                    $SourceObject.InPlaceHolds | ForEach-Object {
                        #This will identify Purview retention policies that may apply to mailbox (mbx without an '-') or Skype content stored on the mailbox (skp), also compliance portal eDiscovery case (UniH), and legacy InPlaceHolds starting with cld.
                        if (($_ -like "mbx*") -or ($_ -like "cld*") -or ($_ -like "UniH*") -or ($_ -like "skp*")) {
                            Write-Host ">> Error: SOURCE mailbox is under an In-PlaceHold Hold and this is not a supported scenario" -ForegroundColor Red
                        } else {
                            Write-Verbose -Message "Mailbox is not under any In-PlaceHold"
                        }
                        #This will identify legacy InPlaceHolds (eDiscovery holds) since they are always 32 chars long, while the rest aren't.
                        if (($_).length -eq 32) {
                            Write-Host ">> Error: SOURCE mailbox is under a legacy In-PlaceHold and this is not a supported scenario" -ForegroundColor Red
                        } else {
                            Write-Verbose -Message "Mailbox is not under any legacy In-Place Hold"
                        }
                    }
                }
                #Check if the mailbox is under any organizational hold
                $MailboxDiagnosticLogs = Export-SourceMailboxDiagnosticLogs $SourceObject -ComponentName HoldTracking
                if ($MailboxDiagnosticLogs.MailboxLog -like '*"hid":"mbx*","ht":4*') {
                    Write-Host ">> Error: SOURCE mailbox is under an Organizational Hold and this is not a supported scenario" -ForegroundColor Red
                } else {
                    Write-Verbose -Message "Mailbox is not under any Organizational Hold"
                }
                #Verify if SOURCE mailbox has an Archive, and if it does, check if there's any item within recoverable items SubstrateHolds folder.
                if ($SourceObject.ArchiveGUID -notmatch "00000000-0000-0000-0000-000000000000") {
                    Write-Verbose -Message "Informational: SOURCE mailbox has an Archive enabled, checking if there's any SubstrateHold folder present"
                    if ((Get-SourceMailboxFolderStatistics $SourceObject.ArchiveGuid -FolderScope RecoverableItems | Where-Object { $_.Name -eq 'SubstrateHolds' })) {
                        Write-Verbose -Message "Informational: SubstrateHolds folder found in SOURCE Archive mailbox, checking if there's any content inside it"
                        if ((Get-SourceMailboxFolderStatistics $SourceObject.ArchiveGuid -FolderScope RecoverableItems | Where-Object { $_.Name -eq 'SubstrateHolds' }).ItemsInFolder -gt 0) {
                            Write-Host ">> Error: SOURCE Archive mailbox has items within the SubstrateHolds folder and this will cause the migration to fail. Please work on removing those items with MFCMapi manually before creating the move for this mailbox" -ForegroundColor Red
                        } else {
                            Write-Verbose -Message "Informational: No items found within the Archive mailbox SubstrateHolds folder"
                        }
                    } else {
                        Write-Verbose -Message "Informational: No SubstrateHolds folder found in SOURCE Archive mailbox"
                    }
                } else {
                    Write-Verbose -Message "Informational: SOURCE mailbox has no Archive enabled. Skiping Archive mailbox SubstrateHolds folder check"
                }
                #Verify if SOURCE mailbox is part of the Mail-Enabled Security Group defined on the SOURCE organization relationship
                Write-Verbose -Message "Informational: Checking if the SOURCE mailbox is a member of the SOURCE organization relationship Mail-Enabled Security Group defined on the MailboxMovePublishedScopes"
                $SourceTenantOrgRelationship = Get-SourceOrganizationRelationship | Where-Object { ($_.MailboxMoveCapability -eq "RemoteOutbound") -and ($null -ne $_.OauthApplicationId) }
                if ((Get-SourceDistributionGroupMember $SourceTenantOrgRelationship.MailboxMovePublishedScopes[0]).Name -contains $SourceObject.Name) {
                    Write-Host ">> SOURCE mailbox is within the MailboxMovePublishedScopes" -ForegroundColor Green
                } else {
                    Write-Host ">> Error: SOURCE mailbox is NOT within the MailboxMovePublishedScopes. The migration will fail if you don't correct this" -ForegroundColor Red
                }

                #Check the recoverableItems quota on TARGET MailUser and compare it with the SOURCE mailbox occupied quota
                Write-Verbose -Message "Checking if the current dumpster size on SOURCE mailbox is bigger than the TARGET MailUser recoverable items quota"
                if (((Get-SourceMailboxStatistics $SourceIdentity).TotalDeletedItemSize -replace '^.+\((.+\))', '$1' -replace '\D' -as [uint64]) -gt ([uint64]($TargetObject.RecoverableItemsQuota -replace '^.+\((.+\))', '$1' -replace '\D'))) {
                    Write-Host ">> Error: Dumpster size on SOURCE mailbox is bigger than TARGET MailUser RecoverableItemsQuota. This might cause the migration to fail" -ForegroundColor Red
                }

                #Verify ExchangeGuid on target object matches with source object and provide the option to set it in case it doesn't
                if (($null -eq $SourceObject.ExchangeGuid) -or ($null -eq $TargetObject.ExchangeGuid)) {
                    exit
                }
                Write-Verbose -Message "Informational: Checking ExchangeGUID"
                if ($SourceObject.ExchangeGuid -eq $TargetObject.ExchangeGuid) {
                    Write-Host ">> ExchangeGuid match ok" -ForegroundColor Green
                } else {
                    Write-Host ">> Error: ExchangeGuid mismatch. Expected value: $($SourceObject.ExchangeGuid) ,Current value: $($TargetObject.ExchangeGuid)" -ForegroundColor Red
                    $ExchangeGuidSetOption = Read-Host "Would you like to set it? (Y/N)"
                    Write-Host " Your input: "$ExchangeGuidSetOption
                    if ($ExchangeGuidSetOption.ToLower() -eq "y") {
                        Write-Verbose -Message "Informational: Setting correct ExchangeGUID on TARGET object"
                        Set-TargetMailUser $TargetIdentity -ExchangeGuid $SourceObject.ExchangeGuid
                        #Reload TARGET object into variable as it has been changed
                        $TargetObject = Get-TargetMailUser $TargetIdentity
                    }
                }

                #Verify if Archive is present on source and if it is, verify ArchiveGuid on target object matches with source object and provide the option to set it in case it doesn't
                Write-Verbose -Message "Informational: Checking if there's an Archive enabled on SOURCE object"
                if ($null -eq $SourceObject.ArchiveGUID) {
                    if ($null -ne $TargetObject.ArchiveGUID) {
                        Write-Host ">> Error: The TARGET MailUser $($TargetObject.Name) has an archive present while source doesn't"
                    }
                    exit
                }
                if ($SourceObject.ArchiveGuid -ne "00000000-0000-0000-0000-000000000000") {
                    Write-Verbose -Message "Informational: Archive is enabled on SOURCE object"
                    Write-Verbose -Message "Informational: Checking ArchiveGUID"
                    if ($SourceObject.ArchiveGuid -eq $TargetObject.ArchiveGuid) {
                        Write-Host ">> ArchiveGuid match ok" -ForegroundColor Green
                    } else {
                        Write-Host ">> Error: ArchiveGuid mismatch. Expected Value: $($SourceObject.ArchiveGuid) , Current value: $($TargetObject.ArchiveGuid)" -ForegroundColor Red
                        $ArchiveGuidSetOption = Read-Host "Would you like to set it? (Y/N)"
                        Write-Host " Your input: "$ArchiveGuidSetOption
                        if ($ArchiveGuidSetOption.ToLower() -eq "y") {
                            Write-Verbose -Message "Informational: Setting correct ArchiveGUID on TARGET object"
                            Set-TargetMailUser $TargetIdentity -ArchiveGuid $SourceObject.ArchiveGuid
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    }
                }

                else {
                    Write-Verbose -Message "Informational: Source object has no Archive enabled"
                }

                #Verify LegacyExchangeDN is present on target object as an X500 proxy address and provide the option to add it in case it isn't
                Write-Verbose -Message "Informational: Checking if LegacyExchangeDN from SOURCE object is part of EmailAddresses on TARGET object"
                if ($null -eq $TargetObject.EmailAddresses) {
                    exit
                }
                if ($TargetObject.EmailAddresses -contains "X500:" + $SourceObject.LegacyExchangeDN) {
                    Write-Host ">> LegacyExchangeDN found as an X500 ProxyAddress on Target Object." -ForegroundColor Green
                } else {
                    Write-Host ">> Error: LegacyExchangeDN not found as an X500 ProxyAddress on Target Object. LegacyExchangeDN expected on target object:" $SourceObject.LegacyExchangeDN -ForegroundColor Red
                    if (!$TargetObject.IsDirSynced) {
                        $LegDNAddOption = Read-Host "Would you like to add it? (Y/N)"
                        Write-Host " Your input: "$LegDNAddOption
                        if ($LegDNAddOption.ToLower() -eq "y") {
                            Write-Verbose -Message "Informational: Adding LegacyExchangeDN as a proxyAddress on TARGET object"
                            Set-TargetMailUser $TargetIdentity -EmailAddresses @{Add = "X500:" + $SourceObject.LegacyExchangeDN }
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    } else {
                        Write-Host ">> Error: The object is DirSynced and this is not a change that can be done directly on EXO. Please do the change on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                    }
                }

                #Check if the primarySMTPAddress of the target MailUser is part of the accepted domains on the target tenant and if any of the email addresses of the target MailUser doesn't belong to the target accepted domains
                Write-Verbose -Message "Informational: Loading TARGET accepted domains"
                $TargetTenantAcceptedDomains = Get-TargetAcceptedDomain

                #PrimarySMTP
                Write-Verbose -Message "Informational: Checking if the PrimarySTMPAddress of TARGET belongs to a TARGET accepted domain"
                if ($TargetTenantAcceptedDomains.DomainName -notcontains $TargetObject.PrimarySmtpAddress.Split('@')[1]) {
                    if (!$TargetObject.IsDirSynced) {
                        Write-Host ">> Error: The Primary SMTP address $($TargetObject.PrimarySmtpAddress) of the MailUser does not belong to an accepted domain on the target tenant, would you like to set it to $($TargetObject.UserPrincipalName) (Y/N): " -ForegroundColor Red -NoNewline
                        $PrimarySMTPAddressSetOption = Read-Host
                        Write-Host " Your input: "$PrimarySMTPAddressSetOption
                        if ($PrimarySMTPAddressSetOption.ToLower() -eq "y") {
                            Write-Verbose -Message "Informational: Setting the UserPrincipalName of TARGET object as the PrimarySMTPAddress"
                            Set-TargetMailUser $TargetIdentity -PrimarySmtpAddress $TargetObject.UserPrincipalName
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    } else {
                        Write-Host ">> Error: The Primary SMTP address $($TargetObject.PrimarySmtpAddress) of the MailUser does not belong to an accepted domain on the target tenant. The object is DirSynced and this is not a change that can be done directly on EXO. Please do the change on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                    }
                } else {
                    Write-Host ">> Target MailUser PrimarySMTPAddress is part of target accepted domains" -ForegroundColor Green
                }

                #EMailAddresses
                Write-Verbose -Message "Informational: Checking for EmailAddresses on TARGET object that are not on the TARGET accepted domains list"
                foreach ($Address in $TargetObject.EmailAddresses) {
                    if ($Address.StartsWith("SMTP:") -or $Address.StartsWith("smtp:")) {
                        if ($TargetTenantAcceptedDomains.DomainName -notcontains $Address.Split("@")[1]) {
                            if (!$TargetObject.IsDirSynced) {
                                Write-Host ">> Error:"$Address" is not part of your organization, would you like to remove it? (Y/N): " -ForegroundColor Red -NoNewline
                                $RemoveAddressOption = Read-Host
                                Write-Host " Your input: "$RemoveAddressOption
                                if ($RemoveAddressOption.ToLower() -eq "y") {
                                    Write-Host "Informational: Removing the EmailAddress"$Address" from the TARGET object"
                                    Set-TargetMailUser $TargetIdentity -EmailAddresses @{Remove = $Address }
                                    #Reload TARGET object into variable as it has been changed
                                    $TargetObject = Get-TargetMailUser $TargetIdentity
                                }
                            } else {
                                Write-Host ">> Error:"$Address" is not part of your organization. The object is DirSynced and this is not a change that can be done directly on EXO. Please do remove the address from on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                            }
                        }
                    } else {
                        Write-Host ">> Target MailUser ProxyAddresses are all part of the target organization" -ForegroundColor Green
                    }
                }

                #Sync X500 addresses from source mailbox to target mailUser
                Write-Verbose -Message "Informational: Checking for missing X500 addresses on TARGET that are present on SOURCE mailbox"
                if ($SourceObject.EmailAddresses -like '*500:*') {
                    Write-Verbose -Message "SOURCE mailbox contains X500 addresses, checking if they're present on the TARGET MailUser"
                    foreach ($Address in ($SourceObject.EmailAddresses | Where-Object { $_ -like '*500:*' })) {
                        if ($TargetObject.EmailAddresses -notcontains $Address) {
                            if (!$TargetObject.IsDirSynced) {
                                Write-Host ">> Error:"$Address" is not present on the TARGET MailUser, would you like to add it? (Y/N): " -ForegroundColor Red -NoNewline
                                $AddX500 = Read-Host
                                Write-Host " Your input: "$AddX500
                                if ($AddX500.ToLower() -eq "y") {
                                    Write-Host "Informational: Adding the X500 Address"$Address" on the TARGET object"
                                    Set-TargetMailUser $TargetIdentity -EmailAddresses @{Add = $Address }
                                    #Reload TARGET object into variable as it has been changed
                                    $TargetObject = Get-TargetMailUser $TargetIdentity
                                }
                            } else {
                                Write-Host ">> Error:"$Address" is not present on the TARGET MailUser and the object is DirSynced. This is not a change that can be done directly on EXO, please add the X500 address from on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                            }
                        } else {
                            Write-Host ">> Informational: The X500 address from SOURCE object is present on TARGET object" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Verbose -Message "Informational: SOURCE mailbox doesn't contain any X500 address"
                }

                #Check ExternalEmailAddress on TargetMailUser with primarySMTPAddress from SourceMailbox:
                Write-Verbose -Message "Informational: Checking if the ExternalEmailAddress on TARGET object points to the PrimarySMTPAddress of the SOURCE object"
                if ($TargetObject.ExternalEmailAddress.Split(":")[1] -eq $SourceObject.PrimarySmtpAddress) {
                    Write-Host ">> ExternalEmailAddress of Target MailUser is pointing to PrimarySMTPAddress of Source Mailbox" -ForegroundColor Green
                } else {
                    if (!$TargetObject.IsDirSynced) {
                        Write-Host ">> Error: TargetMailUser ExternalEmailAddress value $($TargetObject.ExternalEmailAddress) does not match the PrimarySMTPAddress of the SourceMailbox $($SourceObject.PrimarySmtpAddress) , would you like to set it? (Y/N): " -ForegroundColor Red -NoNewline
                        $RemoveAddressOption = Read-Host
                        Write-Host " Your input: "$RemoveAddressOption
                        if ($RemoveAddressOption.ToLower() -eq "y") {
                            Write-Host "Informational: Setting the ExternalEmailAddress of SOURCE object to"$SourceObject.PrimarySmtpAddress
                            Set-TargetMailUser $TargetIdentity -ExternalEmailAddress $SourceObject.PrimarySmtpAddress
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    } else {
                        Write-Host ">> Error: TargetMailUser ExternalEmailAddress value $($TargetObject.ExternalEmailAddress) does not match the PrimarySMTPAddress of the SourceMailbox $($SourceObject.PrimarySmtpAddress). The object is DirSynced and this is not a change that can be done directly on EXO. Please do the change on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                    }
                }
            }
        }

        else {
            Write-Host ">> Error: $($TargetIdentity) wasn't found on TARGET tenant" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: $($SourceIdentity) wasn't found on SOURCE tenant" -ForegroundColor Red
    }
}
function CheckObjectsSourceOffline {

    Write-Host "Informational: Loading SOURCE object"$SourceIdentity
    $SourceObject = Import-Clixml $OutputPath\SourceMailbox_$SourceIdentity.xml
    Write-Host "Informational: Loading TARGET object"$TargetIdentity
    $TargetObject = Get-TargetMailUser $TargetIdentity -ErrorAction SilentlyContinue

    #Validate if SourceObject is present
    if ($SourceObject) {
        #Since SourceObject is valid, validate if TargetObject is present
        if ($TargetObject) {
            #Check if source mailbox has aux archives and if so throw error, otherwise continue with the rest of validations
            Write-Verbose -Message "Checking if SOURCE mailbox has any aux-archives present, and if so, no more than 12"
            $auxArchiveCount = 0
            $MailboxLocations = $SourceObject.MailboxLocations | Where-Object { ($_ -like '*auxArchive*') }
            $auxArchiveCount = $MailboxLocations.count
            Write-Verbose -Message $auxArchiveCount" aux archives are present on SOURCE mailbox"
            if ($auxArchiveCount -gt 12) {
                Write-Host ">> Error: The SOURCE mailbox has more than 12 auxArchive present and we can't migrate that much." -ForegroundColor Red
                exit
            } else {
                Write-Verbose -Message "No aux archives are present on SOURCE mailbox"

                #Check for the T2T license on any of the objects (either source or target) as long as the source mailbox is a regular mailbox
                Write-Verbose -Message "Informational: Source mailbox is regular, checking if either SOURCE mailbox or TARGET MailUser has the T2T license assigned"
                if ($SourceObject.RecipienTypeDetails -eq 'UserMailbox') {
                    if ($SourceObject.PersistedCapabilities -notmatch 'EXCHANGET2TMBXMOVE') {
                        if ($TargetObject.PersistedCapabilities -notmatch 'EXCHANGET2TMBXMOVE') {
                            Write-Host ">> Error: Neither SOURCE mailbox or TARGET MailUser have a valid T2T migration license. This is a pre-requisite, and if the license is not assigned by the time the migration is injected, it will fail to complete" -ForegroundColor Red
                        } else {
                            Write-Verbose -Message "TARGET MailUser has a valid T2T migration license"
                        }
                    } else {
                        Write-Verbose -Message "SOURCE mailbox has a valid T2T migration license"
                    }
                } else {
                    Write-Verbose -Message "Mailbox is not regular, skiping T2T migration license validation check"
                }

                #Verify if SOURCE mailbox is under any type of hold as we won't support this and will throw an error if this is the case
                Write-Verbose -Message "Informational: Checking if the SOURCE mailbox is under a litigation hold"
                if ($SourceObject.litigationHoldEnabled) {
                    Write-Host ">> Error: SOURCE mailbox is under Litigation Hold. This move is not supported as it would lead into data loss" -ForegroundColor Red
                }
                Write-Verbose -Message "Informational: Checking if the SOURCE mailbox is under any delay hold"
                if ($SourceObject.DelayHoldApplied) {
                    Write-Host ">> Error: SOURCE mailbox is under a Delay Hold. This move is not supported as it would lead into data loss" -ForegroundColor Red
                }
                if ($SourceObject.DelayReleaseHoldApplied) {
                    Write-Host ">> Error: SOURCE mailbox is under a Delay Release Hold. This move is not supported as it would lead into data loss" -ForegroundColor Red
                }
                if ($SourceObject.ComplianceTagHoldApplied) {
                    Write-Host ">> Error: SOURCE mailbox has labeled items with a Retention Label. This move is not supported as it would lead into data loss" -ForegroundColor Red
                }
                if ($SourceObject.InPlaceHolds) {
                    $SourceObject.InPlaceHolds | ForEach-Object {
                        #This will identify Purview retention policies that may apply to mailbox (mbx without an '-') or Skype content stored on the mailbox (skp), also compliance portal eDiscovery case (UniH), and legacy InPlaceHolds starting with cld.
                        if (($_ -like "mbx*") -or ($_ -like "cld*") -or ($_ -like "UniH*") -or ($_ -like "skp*")) {
                            Write-Host ">> Error: SOURCE mailbox is under an In-PlaceHold Hold. This move is not supported as it would lead into data loss" -ForegroundColor Red
                        }
                        #This will identify legacy InPlaceHolds (eDiscovery holds) since they are always 32 chars long, while the rest aren't.
                        if (($_).length -eq 32) {
                            Write-Host ">> Error: SOURCE mailbox is under an In-PlaceHold Hold. This move is not supported as it would lead into data loss" -ForegroundColor Red
                        }
                    }
                }
                #Check if the mailbox is under any organizational hold
                $MailboxDiagnosticLogs = Import-Clixml $OutputPath\MailboxDiagnosticLogs_$SourceIdentity.xml
                if ($MailboxDiagnosticLogs.MailboxLog -like '*"hid":"mbx*","ht":4*') {
                    Write-Host ">> Error: SOURCE mailbox is under an Organizational Hold. This move is not supported as it would lead into data loss" -ForegroundColor Red
                }

                #Verify if SOURCE mailbox has an Archive, and if it does, check if there's any item within recoverable items SubstrateHolds folder.
                if ($SourceObject.ArchiveGUID -notmatch "00000000-0000-0000-0000-000000000000") {
                    Write-Verbose -Message "Informational: SOURCE mailbox has an Archive enabled, checking if there's any SubstrateHold folder present"
                    $ArchiveMailboxFolderStatistics = Import-Clixml $OutputPath\ArchiveMailboxStatistics_$SourceIdentity.xml
                    if ($ArchiveMailboxFolderStatistics.Name -eq 'SubstrateHolds') {
                        if ($ArchiveMailboxFolderStatistics.ItemsInFolder -gt 0) {
                            Write-Host ">> Error: SOURCE Archive mailbox has items within the SubstrateHolds folder and this will cause the migration to fail. Please work on removing those items with MFCMapi manually before creating the move for this mailbox" -ForegroundColor Red
                        } else {
                            Write-Verbose -Message "Informational: No items found within the Archive mailbox SubstrateHolds folder"
                        }
                    } else {
                        Write-Verbose -Message "Informational: No SubstrateHolds folder found in SOURCE Archive mailbox"
                    }
                } else {
                    Write-Verbose -Message "Informational: SOURCE mailbox has no Archive enabled. Skiping Archive mailbox SubstrateHolds folder check"
                }

                #Verify if SOURCE mailbox is part of the Mail-Enabled Security Group defined on the SOURCE organization relationship
                Write-Verbose -Message "Informational: Checking if the SOURCE mailbox is a member of the SOURCE organization relationship Mail-Enabled Security Group defined on the MailboxMovePublishedScopes"
                $SourceTenantOrgRelationship = (Import-Clixml $OutputPath\SourceOrgRelationship.xml)
                $SourceTenantOrgRelationship = $SourceTenantOrgRelationship | Where-Object { ($_.MailboxMoveCapability -eq "RemoteOutbound") -and ($null -ne $_.OauthApplicationId) }
                $SourceTenantMailboxMovePublishedScopesSGMembers = Import-Clixml $OutputPath\MailboxMovePublishedScopesSGMembers.xml
                if ($SourceTenantMailboxMovePublishedScopesSGMembers.Name -contains $SourceObject.Name) {
                    Write-Host ">> SOURCE mailbox is within the MailboxMovePublishedScopes" -ForegroundColor Green
                } else {
                    Write-Host ">> Error: SOURCE mailbox is NOT within the MailboxMovePublishedScopes. The migration will fail if you don't correct this" -ForegroundColor Red
                }

                #Check the recoverableItems quota on TARGET MailUser and compare it with the SOURCE mailbox occupied quota
                Write-Verbose -Message "Checking if the current dumpster size on SOURCE mailbox is bigger than the TARGET MailUser recoverable items quota"
                $SourceMailboxStatistics = Import-Clixml $OutputPath\MailboxStatistics_$SourceIdentity.xml
                if (($SourceMailboxStatistics.TotalDeletedItemSize -replace '^.+\((.+\))', '$1' -replace '\D' -as [uint64]) -gt ([uint64]($TargetObject.RecoverableItemsQuota -replace '^.+\((.+\))', '$1' -replace '\D'))) {
                    Write-Host ">> Error: Dumpster size on SOURCE mailbox is bigger than TARGET MailUser RecoverableItemsQuota. This might cause the migration to fail" -ForegroundColor Red
                }

                #Verify ExchangeGuid on target object matches with source object and provide the option to set it in case it doesn't
                if (($null -eq $SourceObject.ExchangeGuid) -or ($null -eq $TargetObject.ExchangeGuid)) {
                    exit
                }
                Write-Verbose -Message "Informational: Checking ExchangeGUID"
                if ($SourceObject.ExchangeGuid -eq $TargetObject.ExchangeGuid) {
                    Write-Host ">> ExchangeGuid match ok" -ForegroundColor Green
                } else {
                    Write-Host ">> Error: ExchangeGuid mismatch. Expected value: $($SourceObject.ExchangeGuid) ,Current value: $($TargetObject.ExchangeGuid)" -ForegroundColor Red
                    $ExchangeGuidSetOption = Read-Host "Would you like to set it? (Y/N)"
                    Write-Host " Your input: "$ExchangeGuidSetOption
                    if ($ExchangeGuidSetOption.ToLower() -eq "y") {
                        Write-Verbose -Message "Informational: Setting correct ExchangeGUID on TARGET object"
                        Set-TargetMailUser $TargetIdentity -ExchangeGuid $SourceObject.ExchangeGuid
                        #Reload TARGET object into variable as it has been changed
                        $TargetObject = Get-TargetMailUser $TargetIdentity
                    }
                }

                #Verify if Archive is present on source and if it is, verify ArchiveGuid on target object matches with source object and provide the option to set it in case it doesn't
                Write-Verbose -Message "Informational: Checking if there's an Archive enabled on SOURCE object"
                if ($null -eq $SourceObject.ArchiveGUID) {
                    if ($null -ne $TargetObject.ArchiveGUID) {
                        Write-Host ">> Error: The TARGET MailUser $($TargetObject.Name) has an archive present while source doesn't"
                    }
                    exit
                }
                if ($SourceObject.ArchiveGuid -ne "00000000-0000-0000-0000-000000000000") {
                    Write-Verbose -Message "Informational: Archive is enabled on SOURCE object"
                    Write-Verbose -Message "Informational: Checking ArchiveGUID"
                    if ($SourceObject.ArchiveGuid -eq $TargetObject.ArchiveGuid) {
                        Write-Host ">> ArchiveGuid match ok" -ForegroundColor Green
                    } else {
                        Write-Host ">> Error: ArchiveGuid mismatch. Expected Value: $($SourceObject.ArchiveGuid) , Current value: $($TargetObject.ArchiveGuid)" -ForegroundColor Red
                        $ArchiveGuidSetOption = Read-Host "Would you like to set it? (Y/N)"
                        Write-Host " Your input: "$ArchiveGuidSetOption
                        if ($ArchiveGuidSetOption.ToLower() -eq "y") {
                            Write-Verbose -Message "Informational: Setting correct ArchiveGUID on TARGET object"
                            Set-TargetMailUser $TargetIdentity -ArchiveGuid $SourceObject.ArchiveGuid
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    }
                }

                else {
                    Write-Verbose -Message "Informational: Source object has no Archive enabled"
                }

                #Verify LegacyExchangeDN is present on target object as an X500 proxy address and provide the option to add it in case it isn't
                Write-Verbose -Message "Informational: Checking if LegacyExchangeDN from SOURCE object is part of EmailAddresses on TARGET object"
                if ($null -eq $TargetObject.EmailAddresses) {
                    exit
                }
                if ($TargetObject.EmailAddresses -contains "X500:" + $SourceObject.LegacyExchangeDN) {
                    Write-Host ">> LegacyExchangeDN found as an X500 ProxyAddress on Target Object." -ForegroundColor Green
                } else {
                    Write-Host ">> Error: LegacyExchangeDN not found as an X500 ProxyAddress on Target Object. LegacyExchangeDN expected on target object:" $SourceObject.LegacyExchangeDN -ForegroundColor Red
                    if (!$TargetObject.IsDirSynced) {
                        $LegDNAddOption = Read-Host "Would you like to add it? (Y/N)"
                        Write-Host " Your input: "$LegDNAddOption
                        if ($LegDNAddOption.ToLower() -eq "y") {
                            Write-Verbose -Message "Informational: Adding LegacyExchangeDN as a proxyAddress on TARGET object"
                            Set-TargetMailUser $TargetIdentity -EmailAddresses @{Add = "X500:" + $SourceObject.LegacyExchangeDN }
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    } else {
                        Write-Host ">> Error: The object is DirSynced and this is not a change that can be done directly on EXO. Please do the change on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                    }
                }

                #Check if the primarySMTPAddress of the target MailUser is part of the accepted domains on the target tenant and if any of the email addresses of the target MailUser doesn't belong to the target accepted domains
                Write-Verbose -Message "Informational: Loading TARGET accepted domains"
                $TargetTenantAcceptedDomains = Get-TargetAcceptedDomain

                #PrimarySMTP
                Write-Verbose -Message "Informational: Checking if the PrimarySTMPAddress of TARGET belongs to a TARGET accepted domain"
                if ($TargetTenantAcceptedDomains.DomainName -notcontains $TargetObject.PrimarySmtpAddress.Split('@')[1]) {
                    if (!$TargetObject.IsDirSynced) {
                        Write-Host ">> Error: The Primary SMTP address $($TargetObject.PrimarySmtpAddress) of the MailUser does not belong to an accepted domain on the target tenant, would you like to set it to $($TargetObject.UserPrincipalName) (Y/N): " -ForegroundColor Red -NoNewline
                        $PrimarySMTPAddressSetOption = Read-Host
                        Write-Host " Your input: "$PrimarySMTPAddressSetOption
                        if ($PrimarySMTPAddressSetOption.ToLower() -eq "y") {
                            Write-Verbose -Message "Informational: Setting the UserPrincipalName of TARGET object as the PrimarySMTPAddress"
                            Set-TargetMailUser $TargetIdentity -PrimarySmtpAddress $TargetObject.UserPrincipalName
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    } else {
                        Write-Host ">> Error: The Primary SMTP address $($TargetObject.PrimarySmtpAddress) of the MailUser does not belong to an accepted domain on the target tenant. The object is DirSynced and this is not a change that can be done directly on EXO, please do the change on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                    }
                } else {
                    Write-Host ">> Target MailUser PrimarySMTPAddress is part of target accepted domains" -ForegroundColor Green
                }

                #EMailAddresses
                Write-Verbose -Message "Informational: Checking for EmailAddresses on TARGET object that are not on the TARGET accepted domains list"
                foreach ($Address in $TargetObject.EmailAddresses) {
                    if ($Address.StartsWith("SMTP:") -or $Address.StartsWith("smtp:")) {
                        if ($TargetTenantAcceptedDomains.DomainName -notcontains $Address.Split("@")[1]) {
                            if (!$TargetObject.IsDirSynced) {
                                Write-Host ">> Error:"$Address" is not part of your organization, would you like to remove it? (Y/N): " -ForegroundColor Red -NoNewline
                                $RemoveAddressOption = Read-Host
                                Write-Host " Your input: "$RemoveAddressOption
                                if ($RemoveAddressOption.ToLower() -eq "y") {
                                    Write-Host "Informational: Removing the EmailAddress"$Address" from the TARGET object"
                                    Set-TargetMailUser $TargetIdentity -EmailAddresses @{Remove = $Address }
                                    #Reload TARGET object into variable as it has been changed
                                    $TargetObject = Get-TargetMailUser $TargetIdentity
                                }
                            } else {
                                Write-Host ">> Error:"$Address" is not part of your organization. The object is DirSynced and this is not a change that can be done directly on EXO, please remove the address from on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                            }
                        }
                    } else {
                        Write-Host ">> Target MailUser ProxyAddresses are all part of the target organization" -ForegroundColor Green
                    }
                }

                #Sync X500 addresses from source mailbox to target mailUser
                Write-Verbose -Message "Informational: Checking for missing X500 addresses on TARGET that are present on SOURCE mailbox"
                if ($SourceObject.EmailAddresses -like '*500:*') {
                    Write-Verbose -Message "SOURCE mailbox contains X500 addresses, checking if they're present on the TARGET MailUser"
                    foreach ($Address in ($SourceObject.EmailAddresses | Where-Object { $_ -like '*500:*' })) {
                        if ($TargetObject.EmailAddresses -notcontains $Address) {
                            if (!$TargetObject.IsDirSynced) {
                                Write-Host ">> Error:"$Address" is not present on the TARGET MailUser, would you like to add it? (Y/N): " -ForegroundColor Red -NoNewline
                                $AddX500 = Read-Host
                                Write-Host " Your input: "$AddX500
                                if ($AddX500.ToLower() -eq "y") {
                                    Write-Host "Informational: Adding the X500 Address"$Address" on the TARGET object"
                                    Set-TargetMailUser $TargetIdentity -EmailAddresses @{Add = $Address }
                                    #Reload TARGET object into variable as it has been changed
                                    $TargetObject = Get-TargetMailUser $TargetIdentity
                                }
                            } else {
                                Write-Host ">> Error:"$Address" is not present on the TARGET MailUser. The object is DirSynced and this is not a change that can be done directly on EXO, please add the address on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                            }
                        } else {
                            Write-Host ">> Informational: The X500 address from SOURCE object is present on TARGET object" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Verbose -Message "Informational: SOURCE mailbox doesn't contain any X500 address"
                }

                #Check ExternalEmailAddress on TargetMailUser with primarySMTPAddress from SourceMailbox:
                Write-Verbose -Message "Informational: Checking if the ExternalEmailAddress on TARGET object points to the PrimarySMTPAddress of the SOURCE object"
                if ($TargetObject.ExternalEmailAddress.Split(":")[1] -eq $SourceObject.PrimarySmtpAddress) {
                    Write-Host ">> ExternalEmailAddress of Target MailUser is pointing to PrimarySMTPAddress of Source Mailbox" -ForegroundColor Green
                } else {
                    if (!$TargetObject.IsDirSynced) {
                        Write-Host ">> Error: TargetMailUser ExternalEmailAddress value $($TargetObject.ExternalEmailAddress) does not match the PrimarySMTPAddress of the SourceMailbox $($SourceObject.PrimarySmtpAddress) , would you like to set it? (Y/N): " -ForegroundColor Red -NoNewline
                        $RemoveAddressOption = Read-Host
                        Write-Host " Your input: "$RemoveAddressOption
                        if ($RemoveAddressOption.ToLower() -eq "y") {
                            Write-Host "Informational: Setting the ExternalEmailAddress of SOURCE object to"$SourceObject.PrimarySmtpAddress
                            Set-TargetMailUser $TargetIdentity -ExternalEmailAddress $SourceObject.PrimarySmtpAddress
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    } else {
                        Write-Host ">> Error: TargetMailUser ExternalEmailAddress value $($TargetObject.ExternalEmailAddress) does not match the PrimarySMTPAddress of the SourceMailbox $($SourceObject.PrimarySmtpAddress). The object is DirSynced and this is not a change that can be done directly on EXO. Please do the change on-premises and perform an AADConnect delta sync" -ForegroundColor Red
                    }
                }
            }
        }

        else {
            Write-Host ">> Error: $($TargetIdentity) wasn't found on TARGET tenant" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: $($SourceIdentity) wasn't found on SOURCE tenant" -ForegroundColor Red
    }
}
function ConnectToSourceTenantAAD {
    #Connect to TargetTenant (AzureAD)
    Write-Verbose -Message "Informational: Connecting to AAD on SOURCE tenant"
    $wsh.Popup("You're about to connect to source tenant (AAD), please provide the SOURCE tenant admin credentials", 0, "SOURCE tenant") | Out-Null
    Connect-AzureAD | Out-Null
}
function ConnectToTargetTenantAAD {
    #Connect to TargetTenant (AzureAD)
    Write-Verbose -Message "Informational: Connecting to AAD on TARGET tenant"
    $wsh.Popup("You're about to connect to target tenant (AAD), please provide the TARGET tenant admin credentials", 0, "TARGET tenant") | Out-Null
    Connect-AzureAD | Out-Null
}
function CheckOrgs {

    #Check if there's an AAD EXO app as expected and load it onto a variable
    Write-Verbose -Message "Informational: Checking if there's already an AAD Application on TARGET tenant that meets the criteria"
    $AadExoApp = Get-AzureADApplication | Where-Object { ($_.ReplyUrls -eq "https://office.com") -and ($_.RequiredResourceAccess -like "*ResourceAppId: 00000002-0000-0ff1-ce00-000000000000*") }
    if ($AadExoApp) {
        Write-Host "AAD application for EXO has been found" -ForegroundColor Green
        Write-Verbose -Message "Informational: Loading migration endpoints on TARGET tenant that meets the criteria"
        if (Get-TargetMigrationEndpoint | Where-Object { ($_.RemoteServer -eq "outlook.office.com") -and ($_.EndpointType -eq "ExchangeRemoteMove") -and ($_.ApplicationId -eq $AadExoApp.AppId) }) {
            Write-Host "Migration endpoint found and correctly set" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Expected Migration endpoint not found" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No AAD application for EXO has been found" -ForegroundColor Red
    }

    #Check orgRelationship flags on source and target orgs
    Write-Verbose -Message "Informational: Loading Organization Relationship on SOURCE tenant that meets the criteria"
    $SourceTenantOrgRelationship = Get-SourceOrganizationRelationship | Where-Object { $_.OauthApplicationId -eq $AadExoApp.AppId }
    Write-Verbose -Message "Informational: Loading Organization Relationship on TARGET tenant that meets the criteria"
    $TargetTenantOrgRelationship = Get-TargetOrganizationRelationship | Where-Object { $_.DomainNames -contains $SourceTenantId }

    Write-Verbose -Message "Informational: Checking TARGET tenant organization relationship"
    if ($TargetTenantOrgRelationship) {
        Write-Host "Organization relationship on TARGET tenant DomainNames is correctly pointing to SourceTenantId" -ForegroundColor Green
        if ($TargetTenantOrgRelationship.MailboxMoveEnabled) {
            Write-Host "Organization relationship on TARGET tenant is enabled for moves" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Organization relationship on TARGET tenant mailbox is not enabled for moves" -ForegroundColor Red
        }
        if ($TargetTenantOrgRelationship.MailboxMoveCapability -eq "Inbound") {
            Write-Host "Organization relationship on TARGET tenant MailboxMove is correctly set" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Organization relationship on TARGET tenant MailboxMove is not correctly set. The expected value is 'Inbound' and the current value is"$TargetTenantOrgRelationship.MailboxMoveCapability -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No Organization relationship on TARGET tenant pointing to SourceTenantId has been found" -ForegroundColor Red
    }

    Write-Verbose -Message "Informational: Checking SOURCE tenant organization relationship"
    if ($SourceTenantOrgRelationship.MailboxMoveEnabled) {
        Write-Host "Organization relationship on SOURCE tenant is enabled for moves" -ForegroundColor Green
        if ($SourceTenantOrgRelationship.MailboxMoveCapability -eq "RemoteOutbound") {
            Write-Host "Organization relationship on SOURCE tenant MailboxMove is correctly set" -ForegroundColor Green
            if ($SourceTenantOrgRelationship.DomainNames -contains $TargetTenantId) {
                Write-Host "Organization relationship on SOURCE tenant DomainNames is correctly pointing to TargetTenantId" -ForegroundColor Green
            } else {
                Write-Host ">> Error: Organization relationship on SOURCE tenant DomainNames is not pointing to TargetTenantId" -ForegroundColor Red
            }
            if ($null -eq $SourceTenantOrgRelationship.MailboxMovePublishedScopes) {
                Write-Host ">> Error: Organization relationship on SOURCE tenant does not have a Mail-Enabled security group defined under the MailboxMovePublishedScopes property" -ForegroundColor Red
            }
        }

        else {
            Write-Host ">> Error: Organization relationship on SOURCE tenant MailboxMove is not correctly set. The expected value is 'RemoteOutbound' and the current value is"$TargetTenantOrgRelationship.MailboxMoveCapability -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: Organization relationship on TARGET tenant mailbox is not enabled for moves" -ForegroundColor Red
    }
}
function CheckOrgsSourceOffline {

    #Check if there's an AAD EXO app as expected and load it onto a variable
    Write-Verbose -Message "Informational: Checking if there's already an AAD Application on TARGET tenant that meets the criteria"
    $AadExoApp = Get-AzureADApplication | Where-Object { ($_.ReplyUrls -eq "https://office.com") -and ($_.RequiredResourceAccess -like "*ResourceAppId: 00000002-0000-0ff1-ce00-000000000000*") }
    if ($AadExoApp) {
        Write-Host "AAD application for EXO has been found" -ForegroundColor Green
        Write-Verbose -Message "Informational: Loading migration endpoints on TARGET tenant that meets the criteria"
        if (Get-TargetMigrationEndpoint | Where-Object { ($_.RemoteServer -eq "outlook.office.com") -and ($_.EndpointType -eq "ExchangeRemoteMove") -and ($_.ApplicationId -eq $AadExoApp.AppId) }) {
            Write-Host "Migration endpoint found and correctly set" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Expected Migration endpoint not found" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No AAD application for EXO has been found" -ForegroundColor Red
    }

    #Check orgRelationship flags on source and target orgs
    Write-Verbose -Message "Informational: Loading Organization Relationship on SOURCE tenant that meets the criteria"
    $SourceTenantOrgRelationship = (Import-Clixml $OutputPath\SourceOrgRelationship.xml)
    $SourceTenantOrgRelationship | Where-Object { $_.OauthApplicationId -eq $AadExoApp.AppId }
    Write-Verbose -Message "Informational: Loading Organization Relationship on TARGET tenant that meets the criteria"
    $TargetTenantOrgRelationship = Get-TargetOrganizationRelationship | Where-Object { $_.DomainNames -contains $SourceTenantId }

    Write-Verbose -Message "Informational: Checking TARGET tenant organization relationship"
    if ($TargetTenantOrgRelationship) {
        Write-Host "Organization relationship on TARGET tenant DomainNames is correctly pointing to SourceTenantId" -ForegroundColor Green
        if ($TargetTenantOrgRelationship.MailboxMoveEnabled) {
            Write-Host "Organization relationship on TARGET tenant is enabled for moves" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Organization relationship on TARGET tenant mailbox is not enabled for moves" -ForegroundColor Red
        }
        if ($TargetTenantOrgRelationship.MailboxMoveCapability -eq "Inbound") {
            Write-Host "Organization relationship on TARGET tenant MailboxMove is correctly set" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Organization relationship on TARGET tenant MailboxMove is not correctly set. The expected value is 'Inbound' and the current value is"$TargetTenantOrgRelationship.MailboxMoveCapability -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No Organization relationship on TARGET tenant pointing to SourceTenantId has been found" -ForegroundColor Red
    }

    Write-Verbose -Message "Informational: Checking SOURCE tenant organization relationship"
    if ($SourceTenantOrgRelationship.MailboxMoveEnabled) {
        Write-Host "Organization relationship on SOURCE tenant is enabled for moves" -ForegroundColor Green
        if ($SourceTenantOrgRelationship.MailboxMoveCapability -eq "RemoteOutbound") {
            Write-Host "Organization relationship on SOURCE tenant MailboxMove is correctly set" -ForegroundColor Green
            if ($SourceTenantOrgRelationship.DomainNames -contains $TargetTenantId) {
                Write-Host "Organization relationship on SOURCE tenant DomainNames is correctly pointing to TargetTenantId" -ForegroundColor Green
            } else {
                Write-Host ">> Error: Organization relationship on SOURCE tenant DomainNames is not pointing to TargetTenantId" -ForegroundColor Red
            }
            if ($null -eq $SourceTenantOrgRelationship.MailboxMovePublishedScopes) {
                Write-Host ">> Error: Organization relationship on SOURCE tenant does not have a Mail-Enabled security group defined under the MailboxMovePublishedScopes property" -ForegroundColor Red
            }
        }

        else {
            Write-Host ">> Error: Organization relationship on SOURCE tenant MailboxMove is not correctly set. The expected value is 'RemoteOutbound' and the current value is"$TargetTenantOrgRelationship.MailboxMoveCapability -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: Organization relationship on TARGET tenant mailbox is not enabled for moves" -ForegroundColor Red
    }
}
function KillSessions {
    #Check if there's any existing session opened for EXO and remove it so it doesn't remains open
    Get-PSSession | Where-Object { $_.ComputerName -eq 'outlook.office365.com' } | Remove-PSSession
}
function CollectDataForSDP {
    $currentDate = (Get-Date).ToString('ddMMyyHHMM')
    if (Test-Path $PathForCollectedData -PathType Container) {
        $OutputPath = New-Item -ItemType Directory -Path $PathForCollectedData -Name $currentDate | Out-Null
        $OutputPath = $PathForCollectedData + '\' + $currentDate
    } else {
        Write-Host ">> Error: The specified folder doesn't exist, please specify an existent one" -ForegroundColor Red
        exit
    }

    #Collect the Exchange Online data and export it to an XML file
    Write-Host "Informational: Saving SOURCE tenant id to text file"  -ForegroundColor Yellow
    "SourceTenantId: " + $SourceTenantId | Out-File $OutputPath\TenantIds.txt
    Write-Host "Informational: Saving TARGET tenant id to text file"  -ForegroundColor Yellow
    "TargetTenantId: " + $TargetTenantId | Out-File $OutputPath\TenantIds.txt -Append
    Write-Host "Informational: Exporting the SOURCE tenant organization relationship"  -ForegroundColor Yellow
    Get-SourceOrganizationRelationship | Export-Clixml $OutputPath\SourceOrgRelationship.xml
    Write-Host "Informational: Exporting the TARGET tenant migration endpoint"  -ForegroundColor Yellow
    Get-TargetMigrationEndpoint | Export-Clixml $OutputPath\TargetMigrationEndpoint.xml
    Write-Host "Informational: Exporting the TARGET tenant organization relationship"  -ForegroundColor Yellow
    Get-TargetOrganizationRelationship | Export-Clixml $OutputPath\TargetOrgRelationship.xml
    Write-Host "Informational: Exporting the TARGET tenant accepted domains"  -ForegroundColor Yellow
    Get-TargetAcceptedDomain | Export-Clixml $OutputPath\TargetAcceptedDomains.xml
    Write-Host "Informational: Exporting the TARGET tenant Azure AD applications" -ForegroundColor Yellow
    Get-AzureADApplication | Export-Clixml $OutputPath\TargetAADApps.xml

    #Compress folder contents into a zip file
    Write-Host "Informational: Data has been exported. Compressing it into a ZIP file"  -ForegroundColor Yellow
    if ((Get-ChildItem $OutputPath).count -gt 0) {
        try {
            Compress-Archive -Path $OutputPath\*.XML -DestinationPath $PathForCollectedData\CTMMCollectedData$currentDate.zip -Force
            Compress-Archive -Path $OutputPath\TenantIds.txt -DestinationPath $PathForCollectedData\CTMMCollectedData$currentDate.zip -Update
            Write-Host "Informational: ZIP file has been generated with a total of $((Get-ChildItem $OutputPath).count) files, and can be found at"$PathForCollectedData\CTMMCollectedData$currentDate.zip" so it can be sent to Microsoft Support if needed, however you can still access the raw data at $($OutputPath)"  -ForegroundColor Yellow
        } catch {
            Write-Host ">> Error: There was an issue trying to compress the exported data" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No data has been detected at"$OutputPath", so there's nothing to compress" -ForegroundColor Red
    }
}
function CollectSourceData {
    #Collect the source Exchange Online data of the provided mailboxes via CSV file and export it to an XML file including mailbox diagnostic logs and mailbox statistics
    Write-Host "Informational: Exporting the SOURCE mailbox properties for" $SourceIdentity -ForegroundColor Yellow
    Get-SourceMailbox $SourceIdentity | Export-Clixml $OutputPath\SourceMailbox_$SourceIdentity.xml

    Write-Host "Informational: Exporting the SOURCE mailbox diagnostic logs for" $SourceIdentity -ForegroundColor Yellow
    Export-SourceMailboxDiagnosticLogs $SourceIdentity -ComponentName HoldTracking | Export-Clixml $OutputPath\MailboxDiagnosticLogs_$SourceIdentity.xml

    Write-Host "Informational: Exporting the SOURCE mailbox statistics for" $SourceIdentity -ForegroundColor Yellow
    Get-SourceMailboxStatistics $SourceIdentity | Export-Clixml $OutputPath\MailboxStatistics_$SourceIdentity.xml
    if (Get-SourceMailbox $SourceIdentity.ArchiveGuid -notmatch "00000000-0000-0000-0000-000000000000") {
        Get-SourceMailboxFolderStatistics $SourceIdentity.ArchiveGuid -FolderScope RecoverableItems | Where-Object { $_.Name -eq 'SubstrateHolds' } | Export-Clixml $OutputPath\ArchiveMailboxStatistics_$SourceIdentity.xml
    }
}
function ExpandCollectedData {
    #Expand zip file gathered from the CollectSourceData process provided on the 'PathForCollectedData' parameter
    Write-Host "Informational: Trying to expand exported data from the source tenant specified on the 'PathForCollectedData' parameter"
    if ($PathForCollectedData -like '*\CTMMCollectedSourceData.zip') {
        try {
            $OutputPath = $PathForCollectedData.TrimEnd('CTMMCollectedSourceData.zip') + 'CTMMCollectedSourceData'
            Expand-Archive -Path $PathForCollectedData -DestinationPath $OutputPath -Force
            Write-Host "Informational: ZIP file has been expanded with a total of $((Get-ChildItem $OutputPath).count) files"
        } catch {
            Write-Host ">> Error: There was an issue trying to expand the compressed data" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No CTMMCollectedData.zip file has been specified, you must provide the 'PathForCollectedData' parameter with a valid path including the 'CTMMCollectedSourceData.zip' filename. i.e.: C:\temp\CTMMCollectedSourceData.zip" -ForegroundColor Red
    }
}
function LoggingOn {
    Write-Host ""
    Write-Host ""
    if (Test-Path $LogPath -PathType Leaf) {
        Write-Host ">> Error: The log file already exists, please specify a different name and run again" -ForegroundColor Red
        exit
    } else {
        Start-Transcript -Path $LogPath -NoClobber
    }
}
function LoggingOff {
    Stop-Transcript
}

if ($CheckObjects -and !$NoConn -and !$SourceIsOffline) {
    LoggingOn
    if ($CSV) {
        $Objects = Import-Csv $CSV
        if (($Objects.SourceUser) -and ($Objects.TargetUser)) {
            ConnectToEXOTenants
            foreach ($object in $Objects) {
                $SourceIdentity = $object.SourceUser
                $TargetIdentity = $object.TargetUser
                Write-Host ""
                Write-Host "----------------------------------------" -ForegroundColor Cyan
                Write-Host "----------------------------------------" -ForegroundColor Cyan
                Write-Host ""
                Write-Host $SourceIdentity" is being used as SOURCE object"
                Write-Host $TargetIdentity" is being used as TARGET object"
                CheckObjects
            }
        } else {
            Write-Host ">> Error: Invalid CSV file, please make sure you specify a correct one with the 'SourceUser' and 'TargetUser' columns" -ForegroundColor Red
            LoggingOff
            exit
        }
    } else {
        $SourceIdentity = Read-Host "Please type the SOURCE object to check at"
        $TargetIdentity = Read-Host "Please type the TARGET object to compare with"
        ConnectToEXOTenants
        Write-Host ""
        Write-Host "----------------------------------------" -ForegroundColor Cyan
        Write-Host "----------------------------------------" -ForegroundColor Cyan
        Write-Host ""
        CheckObjects
    }
    LoggingOff
    KillSessions
}

if ($CheckOrgs -and !$SourceIsOffline) {
    LoggingOn
    ConnectToSourceTenantAAD
    $SourceTenantId = (Get-AzureADTenantDetail).ObjectId
    Write-Verbose -Message "Informational: SourceTenantId gathered from AzureADTenantDetail.ObjectId: $SourceTenantId"
    ConnectToTargetTenantAAD
    $TargetTenantId = (Get-AzureADTenantDetail).ObjectId
    Write-Verbose -Message "Informational: TargetTenantId gathered from AzureADTenantDetail.ObjectId: $TargetTenantId"
    ConnectToEXOTenants
    CheckOrgs
    LoggingOff
    KillSessions
}

if ($SDP) {
    LoggingOn
    ConnectToEXOTenants
    ConnectToTargetTenantAAD
    $SourceTenantId = Read-Host "Please specify the SOURCE TenantId"
    $TargetTenantId = (Get-AzureADTenantDetail).ObjectId
    CollectDataForSDP
    LoggingOff
    KillSessions
}

if ($CollectSourceOnly -and $CSV) {
    LoggingOn
    ConnectToSourceTenantAAD
    $SourceTenantId = (Get-AzureADTenantDetail).ObjectId
    Write-Verbose -Message "SourceTenantId gathered from AzureADTenantDetail.ObjectId: $SourceTenantId"
    $Objects = Import-Csv $CSV
    if ($Objects.SourceUser) {
        Write-Verbose -Message "Informational: CSV file contains the SourceUser column, now we need to connect to the source EXO tenant"
        ConnectToSourceEXOTenant

        #Create the folders based on date and time to store the files
        $currentDate = (Get-Date).ToString('ddMMyyHHMM')
        if (Test-Path $PathForCollectedData -PathType Container) {
            $OutputPath = New-Item -ItemType Directory -Path $PathForCollectedData -Name $currentDate | Out-Null
            $OutputPath = $PathForCollectedData + '\' + $currentDate
        } else {
            Write-Host ">> Error: The specified folder doesn't exist, please specify an existent one" -ForegroundColor Red
            exit
        }

        #Collect the TenantId and OrganizationConfig only once and leave the foreach only to mailboxes we need to collect data from
        Write-Host "Informational: Saving SOURCE tenant id to text file"  -ForegroundColor Yellow
        $SourceTenantId | Out-File $OutputPath\SourceTenantId.txt

        Write-Host "Informational: Exporting the SOURCE tenant organization relationships"  -ForegroundColor Yellow
        $SourceTenantOrganizationRelationship = Get-SourceOrganizationRelationship
        $SourceTenantOrganizationRelationship | Export-Clixml $OutputPath\SourceOrgRelationship.xml

        Write-Host "Informational: Checking if there's a published scope defined on the organization relationships to extract the members"  -ForegroundColor Yellow
        $SourceTenantOrganizationRelationship | ForEach-Object {
            if (($_.MailboxMoveEnabled) -and ($_.MailboxMoveCapability -eq "RemoteOutbound") -and ($_.MailboxMovePublishedScopes)) {
                Write-Host "Informational: $($_.Identity) organization relationship meets the conditions for a cross tenant mailbox migration scenario, exporting members of the security group defined on the MailboxMovePublishedScopes" -ForegroundColor Yellow
                Get-SourceDistributionGroupMember $_.MailboxMovePublishedScopes[0] | Export-Clixml $OutputPath\MailboxMovePublishedScopesSGMembers.xml
            } else {
                Write-Host "Informational: $($_.Identity) organization relationship doesn't match for a cross tenant mailbox migration scenario" -ForegroundColor Yellow
            }
        }

        foreach ($object in $Objects) {
            $SourceIdentity = $object.SourceUser
            Write-Host ""
            Write-Host "----------------------------------------" -ForegroundColor Cyan
            Write-Host "----------------------------------------" -ForegroundColor Cyan
            Write-Host ""
            Write-Host $SourceIdentity" is being used as SOURCE object"
            CollectSourceData
        }

        #Compress folder contents into a zip file
        Write-Host "Informational: Source data has been exported. Compressing it into a ZIP file"  -ForegroundColor Yellow
        if ((Get-ChildItem $OutputPath).count -gt 0) {
            try {
                Copy-Item $CSV -Destination $OutputPath\UsersToProcess.csv
                Compress-Archive -Path $OutputPath\*.* -DestinationPath $PathForCollectedData\CTMMCollectedSourceData.zip -Force
                Write-Host "Informational: ZIP file has been generated with a total of $((Get-ChildItem $OutputPath).count) files, and can be found at"$PathForCollectedData\CTMMCollectedSourceData.zip" so it can be sent to the target tenant administrator, however you can still access the raw data at $($OutputPath)"  -ForegroundColor Yellow
            } catch {
                Write-Host ">> Error: There was an issue trying to compress the exported data" -ForegroundColor Red
            }
        } else {
            Write-Host ">> Error: No data has been detected at"$OutputPath", so there's nothing to compress" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: Invalid CSV file, please make sure you specify a correct one with the 'SourceUser' column" -ForegroundColor Red
        exit
    }
    LoggingOff
    KillSessions
}

if ($SourceIsOffline -and $PathForCollectedData -and $CheckObjects) {
    LoggingOn
    ConnectToTargetEXOTenant
    ExpandCollectedData
    $OutputPath = $PathForCollectedData.TrimEnd('CTMMCollectedSourceData.zip') + 'CTMMCollectedSourceData'
    Write-Verbose -Message "OutputPath: $OutputPath"
    $CSV2 = Import-Csv $OutputPath\UsersToProcess.csv
    if ($CSV2.SourceUser) {
        Write-Verbose -Message "Informational: CSV file contains the SourceUser column"
    } else {
        Write-Host ">> Error: Invalid CSV file, please make sure the file contains the 'SourceUser' column" -ForegroundColor Red
        exit
    }

    foreach ($c in $CSV2) {
        $SourceIdentity = $c.SourceUser
        $TargetIdentity = $c.SourceUser.Split('@')[0]
        CheckObjectsSourceOffline
    }
    LoggingOff
    KillSessions
}

if ($SourceIsOffline -and $PathForCollectedData -and $CheckOrgs) {
    LoggingOn
    ExpandCollectedData
    $OutputPath = $PathForCollectedData.TrimEnd('CTMMCollectedSourceData.zip') + 'CTMMCollectedSourceData'
    Write-Verbose -Message "OutputPath: $OutputPath"
    ConnectToTargetTenantAAD
    $SourceTenantId = Get-Content $OutputPath\SourceTenantId.txt
    Write-Verbose -Message "SourceTenantId gathered from SourceTenantId.txt: $SourceTenantId"
    $TargetTenantId = (Get-AzureADTenantDetail).ObjectId
    Write-Verbose -Message "TargetTenantId gathered from AzureADTenantDetail.ObjectId: $TargetTenantId"
    ConnectToTargetEXOTenant
    CheckOrgsSourceOffline
    LoggingOff
    KillSessions
}

# SIG # Begin signature block
# MIInqwYJKoZIhvcNAQcCoIInnDCCJ5gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAs+yAgppM+c5rP
# gulpQZBp94uZv2z2UnivRKQ6yaYgC6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGYswghmHAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggcYwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMdY2yFhFRWY3me7HNyk65XK
# MNvzh6RGST42o0EiwzkXMFoGCisGAQQBgjcCAQwxTDBKoBqAGABDAFMAUwAgAEUA
# eABjAGgAYQBuAGcAZaEsgCpodHRwczovL2dpdGh1Yi5jb20vbWljcm9zb2Z0L0NT
# Uy1FeGNoYW5nZSAwDQYJKoZIhvcNAQEBBQAEggEAhs5ELDD4mu8Em5HyaGWNT8R+
# nF/Oy7itrcLBwgBALidpboftT6K0g5x8IqzpRajsUJveJQXR7/RogI0GYW8ePC1h
# xoQKabDfGrnndtXfPnJHun5q2mq9q1NZlQWQw6TLJrMsUONxYvSIeprQuGlqHrCP
# OMLMtA6N7qzggdywxbIbePOWcFjpckwN4pAAGwnJT8ennTjSRSFTNvCJ+un6mR95
# oFY17skcc93TVkXN182bNQMBrwEsZX9I75TESiLLgyyIlgsnnCMdbg/AjsSsLOIO
# jO4UiZYavgYR7A+HPNO8bwpv+BqAFt9mEu4t4dBSvfdL3kkBBRgl6pHrSH1XmaGC
# Fv0wghb5BgorBgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCC1scjgGbT24vz240zsXrLL
# xO+qPVlQEKzst2mfLDgQfwIGZF0DdBhXGBMyMDIzMDUxOTE3MTgwOS40MzFaMASA
# AgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjoxMkJDLUUzQUUtNzRFQjElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAAByk/C
# s+0DDRhsAAEAAAHKMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTIyMTEwNDE5MDE0MFoXDTI0MDIwMjE5MDE0MFowgcoxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jv
# c29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjEyQkMtRTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwwGcq9j50rWE
# kcLSlGZLweUVfxXRaUjiPsyaNVxPdMRs3CVe58siu/EkaVt7t7PNTPko/s8lNtus
# AeLEnzki44yxk2c9ekm8E1SQ2YV9b8/LOxfKapZ8tVlPyxw6DmFzNFQjifVm8EiZ
# 7lFRoY448vpcbBD18qjYNF/2Z3SQchcsdV1N9Y6V2WGl55VmLqFRX5+dptdjreBX
# zi3WW9TsoCEWcYCBK5wYgS9tT2SSSTzae3jmdw40g+LOIyrVPF2DozkStv6JBDPv
# wahXWpKGpO7rHrKF+o7ECN/ViQFMZyp/vxePiUABDNqzEUI8s7klYmeHXvjeQOq/
# CM3C/Y8bj3fJObnZH7eAXvRDnxT8R6W/uD1mGUJvv9M9BMu3nhKpKmSxzzO5LtcM
# Eh2tMXxhMGGNMUP3DOEK3X+2/LD1Z03usJTk5pHNoH/gDIvbp787Cw40tsApiAvt
# rHYwub0TqIv8Zy62l8n8s/Mv/P764CTqrxcXzalBHh+Xy4XPjmadnPkZJycp3Kcz
# bkg9QbvJp0H/0FswHS+efFofpDNJwLh1hs/aMi1K/ozEv7/WLIPsDgK16fU/axyb
# qMKk0NOxgelUjAYKl4wU0Y6Q4q9N/9PwAS0csifQhY1ooQfAI0iDCCSEATslD8bT
# O0tRtqdcIdavOReqzoPdvAv3Dr1XXQ8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBT6
# x/6lS4ESQ8KZhd0RgU7RYXM8fzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtT
# NRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAl
# MjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQDY0HkqCS3KuKefFX8/rm/dtD9066dK
# EleNqriwZqsM4Ym8Ew4QiqOqO7mWoYYY4K5y8eXSOHKNXOfpO6RbaYj8jCOcJAB5
# tqLl5hiMgaMbAVLrl1hlix9sloO45LON0JphKva3D6AVKA7P78mA9iRHZYUVrRiy
# fvQjWxmUnxhis8fom92+/RHcEZ1Dh5+p4gzeeL84Yl00Wyq9EcgBKKfgq0lCjWNS
# q1AUG1sELlgXOSvKZ4/lXXH+MfhcHe91WLIaZkS/Hu9wdTT6I14BC97yhDsZWXAl
# 0IJ801I6UtEFpCsTeOyZBJ7CF0rf5lxJ8tE9ojNsyqXJKuwVn0ewCMkZqz/cEwv9
# FEx8QmsZ0ZNodTtsl+V9dZm+eUrMKZk6PKsKArtQ+jHkfVsHgKODloelpOmHqgX7
# UbO0NVnIlpP55gQTqV76vU7wRXpUfz7KhE3BZXNgwG05dRnCXDwrhhYz+Itbzs1K
# 1R8I4YMDJjW90ASCg9Jf+xygRKZGKHjo2Bs2XyaKuN1P6FFCIVXN7KgHl/bZiakG
# q7k5TQ4OXK5xkhCHhjdgHuxj3hK5AaOy+GXxO/jbyqGRqeSxf+TTPuWhDWurIo33
# RMDGe5DbImjcbcj6dVhQevqHClR1OHSfr+8m1hWRJGlC1atcOWKajArwOURqJSVl
# ThwVgIyzGNmjzjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJ
# KoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0
# eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25
# PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsH
# FPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTa
# mDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc
# 6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF
# 50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpG
# dc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOm
# TTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi
# 0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU
# 2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSF
# F5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCC
# AdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6C
# kTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1Ud
# IARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUE
# DDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8E
# BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2U
# kFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
# b20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmww
# WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkq
# hkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaT
# lz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYu
# nKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f
# 8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVC
# s/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzs
# kYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzH
# VG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+k
# KNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+
# CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAo
# GokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEz
# fbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKh
# ggLLMIICNAIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTJCQy1FM0FFLTc0RUIxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# AKOO55cMT4syPP6nClg2IWfajMqkoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDoEgzbMCIYDzIwMjMwNTE5MjI1
# NzMxWhgPMjAyMzA1MjAyMjU3MzFaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgS
# DNsCAQAwBwIBAAICDg4wBwIBAAICETEwCgIFAOgTXlsCAQAwNgYKKwYBBAGEWQoE
# AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkq
# hkiG9w0BAQUFAAOBgQCvPd0HL+B4LScWRhN9giSdB2hycdm/I+GM7GgKxSVK9ZEz
# m31kjnAd6Ky/XoPfwndbPajpMTCBXySuAFBogqnMMPA/iaR1SbF5KCkKcHPIkwjr
# GSQ9mA/orKATWjwCLPoc1sKej00AMVibJ+HAYGtUlkcsqNddjMoD8uwftYCmLDGC
# BA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# yk/Cs+0DDRhsAAEAAAHKMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMx
# DQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEICXyWRjO+xBGF3fPzunmI/gQ
# Chr2LlNI5M+keRRmPsAqMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgEz0b
# 85vrVU2slZAk4jt1SDEk6IzZAwVCoWwF3KzcGuAwgZgwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcpPwrPtAw0YbAABAAAByjAiBCB1vpsN
# Jt7vqQn/K6C6b12A6igkJ+j4jJnr7WHKPXXPjjANBgkqhkiG9w0BAQsFAASCAgAJ
# gJxD4AtSpIq3M8iS/4ecK+QAzzrLcyFlGrf+s7AgJk0q0DyFW+NuL0apDozaKwiQ
# eIUnQYn0PfXCW+EjTtxpi+m+85kyJxCbp/aN1sMgUXcxSKBbm1D0Ti4Y8oCqiSyO
# 893QQVGVdRqw8djJ+KhSnM8GyW/UxOHypuHIuM/Nh6bPBP+SEW0G0ButepjZrZxU
# 92KKRj62oCRJ72GZcrFJMMuwb7yrNUe/mZ3sYO+WZQx+Wc/lFuWedokbVQbJGqbD
# 2zxmjTSeUx7uslPnoK9XrlOb2yIo32pDDRblj0EBsXz2S4cxWAeB1a3dFIV7Vr+c
# BRZgWyKtXThFdxSmQ2KGSvWcBKyztouqFDsR2fYjfbVLLU6/KVDcbCVoDNIYQffH
# P0daLZKxkNCZSGWI6DCzB6+hA1exphfflAFmwt3GzVn+Vb8QdYJ/j+MhBgKO31lT
# WGbS186iGn0f80tSnX3mlAX+iqWOO5kWy9YQAkuj/PJnZc6y+IDnwRJH8rYuP3Bv
# RsaW1dIROzjdBL7YxSS60Ye+zIELFNFlHbOaA3EfNRDvsfwykmJlwrrxgw9XYx0C
# 87xWQ0RRwXXpX6lCXRDvJPeoIBcdnuLJW71IBGlLoqieD39npah99t8oRzIfWAV6
# mL6QukjDJjntryCmQRaJWELjG/L508kSTeND2AHpiA==
# SIG # End signature block
