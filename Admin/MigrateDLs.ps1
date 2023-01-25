# Copyright (c) Microsoft Corporation.LogPath
# Licensed under the MIT License.
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    This script offers the ability to migrate Distribution Lists (aka Distribution Groups) that are sitting in Exchage On-premises and need to be moved to Exchange Online, providing in this way, the ability for end users to manage them once their mailboxes have been migrated to Exchange Online.

.DESCRIPTION
    This script offers the ability to migrate Distribution Lists (aka Distribution Groups) that are sitting in Exchage On-premises and need to be moved to Exchange Online, providing in this way, the ability for end users to manage them once their mailboxes have been migrated to Exchange Online.
    It will process every DL listed on the CSV file and will do the following:
    - Check if the DL is present on-premises (if it isn't, the entry will be bypassed and will move on to the next one)
    - Check if the DL is present in EXO (if it is, the entry will be bypassed and will move on to the next one)
    - Export all the properties of the on-premises DL and store them on a file matching the entry within the specified LogPath.
    - Create the DL on EXO and stamp the properties from the on-premises DL.
    - Validate every property of the DL, ensuring the on-premises ones match the one on EXO (including members). If a property is not matching, it will be shown on the screen and will be logged on the 'Failed-' log file that corresponds to the object being processed.
    - If validation is successful, we will remove the DL from on-premises (check if the object was removed) and create a mail-contact on-premises, having the ExternalEmailAddress pointing to the provisioned onmicrosoft.com email address of the DL on EXO.
    - Once the Mail-Contact has been validated, we will rename the log file to start with 'OK-'
    - If the process fails on any step, we will rename the log file to start with 'Failed-'

    PRE-REQUISITES:
    For the process to work correctly, we need to have the following things in consideration:
    - Make sure the DL's you include on the CSV file are present in Exchange On-premises AND NOT SYNCED to Exchange Online anymore (in other words, the DL should not be present in EXO)
    - Running this script, needs to be done from the Exchange Management Shell on-premises, with the Exchange Online management module installed (if you need to install the module, running EMS or Powershell as an admin, run 'Install-Module ExchangeOnlineManagement')
    - The account running this scripts needs to have at least the 'Recipient Management' Exchange management role assigned on both ends (on-premises and online).
    - The CSV file needs to have just one column named 'DL'
    - The specified log path should not end with '\'
    - To avoid any possible throttling applied to Powershell, I recommend running batches of no more than 100 entries per day.

.PARAMETER CSVfile
    CSV file of the DL's we will be migrating when running this script

.PARAMETER LogPath
	Temp path for storing DL props and logging of the process for each one of the entries listed on the CSV file

.EXAMPLE
    .\MigrateDLs.ps1 -CSV c:\Temp\myCSV.csv -LogPath C:\Temp
    This will import the specified CSV file and migrate the DL's listed there. For every one of them, their properties and the process details will be stores ont he specified path for logging.
#>


param(
    [Parameter(Mandatory = $True)]
    [System.String]$CSV,
    [Parameter(Mandatory = $True)]
    [System.String]$LogPath
)

. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1

if (!(Test-Path -Path $LogPath )) {
    Write-Host "  Creating Directory: $LogPath"
    New-Item -ItemType directory -Path $LogPath | Out-Null
}

if (($LogPath).EndsWith('\')) {
    Write-Host "ERROR: The specified LogPath is ending with a '\'. This should not be present and should be something like 'C:\temp' instead of 'C:\temp\'" -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "### Starting migrate DL's to EXO script ###"
Write-Host "-------------------------------------------"
Write-Host "  Importing the CSV that contains the DL's to migrate from $CSV"
$Objects = Import-Csv $CSV
if (!($Objects).DL) {
    Write-Host "  ERROR: The specified CSV file doesn't contain a column named 'DL'. Please specify a valid CSV file that contains the mentioned column. Exiting the process." -ForegroundColor Red
    exit
}

Write-Host "  Connecting to EXO"
Connect-ExchangeOnline -Prefix Online -ShowBanner:$false
Write-Host ""
$FormatEnumerationLimit = -1
$Total = $Objects.count
$Success = 0
$Warning = 0
$Failed = 0

foreach ($Group in $Objects) {
    #Initializing counter variable
    $i = 0

    Write-Host ""
    $Group = $Group.DL
    Start-Transcript -Path $LogPath\$group-log.txt -Force
    Write-Host "  Starting to process DL $Group"
    if (((Get-DistributionGroup $Group -ErrorAction 'SilentlyContinue').IsValid) -eq $true) {
        Write-Host "  $Group was found, getting properties"
        $OldDG = Get-DistributionGroup $Group

        Write-Host "  Exporting properties of $Group to $LogPath\$Group-SourceProperties.txt"
        $OldDG | Format-List | Out-File $LogPath\$Group-SourceProperties.txt -Force
        Add-Content $LogPath\$Group-SourceProperties.txt "###"
        Add-Content $LogPath\$Group-SourceProperties.txt "Distribution Group Members"
        Add-Content $LogPath\$Group-SourceProperties.txt "###"
        Add-Content $LogPath\$Group-SourceProperties.txt "`n"

        (Get-DistributionGroupMember $Group).Name | Out-File $LogPath\$Group-SourceProperties.txt -Append

        Write-Host "  Checking for invalid chars for: $Group"
        [System.IO.Path]::GetInvalidFileNameChars() | ForEach-Object { $Group = $Group.Replace($_, '_') }

        $OldName = [string]$OldDG.Name
        $OldDisplayName = [string]$OldDG.DisplayName
        $OldPrimarySmtpAddress = [string]$OldDG.PrimarySmtpAddress
        $OldAlias = [string]$OldDG.Alias
        $OldMembers = (Get-DistributionGroupMember $OldDG.Name).Name

        Write-Host "  Storing existing EmailAddresses on $LogPath\$Group.csv for: $Group"
        "EmailAddress" > "$LogPath\$Group.csv"
        $OldDG.EmailAddresses.ProxyAddressString >> "$LogPath\$Group.csv"
        "x500:" + $OldDG.LegacyExchangeDN >> "$LogPath\$Group.csv"

        Write-Host "  Importing the resultant file ($LogPath\$Group.csv) for $Group"
        $OldAddresses = @(Import-Csv "$LogPath\$Group.csv")
        $NewAddresses = $OldAddresses | ForEach-Object { $_.EmailAddress.Replace("X500", "x500") }

        Write-Host "  Checking if the group is already created in EXO"
        if (((Get-OnlineDistributionGroup $Group -ErrorAction 'SilentlyContinue').IsValid) -eq $true) {
            Write-Host "  $Group already exists. Jumping to the next group on the CSV file"
            Stop-Transcript
            Rename-Item $LogPath\$group-log.txt $LogPath\Failed-$group-log.txt -Force
            $Failed++
            Write-Host "  Process FAILED and details can be found at $LogPath\Failed-$group-log.txt" -ForegroundColor Red
            Write-Host ""
            continue
        }

        Write-Host "  Creating Group: $Group"
        New-OnlineDistributionGroup `
            -Name "$OldName" `
            -Alias "$OldAlias" `
            -DisplayName "$OldDisplayName" `
            -PrimarySmtpAddress "$OldPrimarySmtpAddress" | Out-Null

        if (((Get-OnlineDistributionGroup $Group -ErrorAction 'SilentlyContinue').IsValid) -eq $true) {
            Write-Host "  $Group was successfully created on EXO"

            Write-Host "  Setting EmailAddresses for: $Group from the imported CSV file ($LogPath\$Group.csv)"
            Set-OnlineDistributionGroup -Identity "$Group" -EmailAddresses @{Add = $NewAddresses }

            Write-Host "  Setting mail delivery restriction/allowance and members for: $Group"
            $ir = 0
            if (($OldDG.AcceptMessagesOnlyFromSendersOrMembers).count -gt 0) {
                foreach ($item in $OldDG.AcceptMessagesOnlyFromSendersOrMembers) {
                    Write-Host "  Adding $($item.Name) to the AcceptMessagesOnlyFromSendersOrMembers property"
                    Set-OnlineDistributionGroup -Identity "$OldName" -AcceptMessagesOnlyFromSendersOrMembers @{Add = $item.Name } -ErrorAction SilentlyContinue -ErrorVariable E1
                    if ($E1 -like "*ManagementObjectNotFoundException*") {
                        Write-Host "  WARNING: Can't add the entry to the property because it wasn't found in Exchange Online" -ForegroundColor Yellow
                        $ir++
                    }
                }
                if (($OldDG.RejectMessagesFromSendersOrMembers).count -gt 0) {
                    foreach ($item in $OldDG.RejectMessagesFromSendersOrMembers) {
                        Write-Host "  Adding $($item.Name) to the RejectMessagesFromSendersOrMembers property"
                        Set-OnlineDistributionGroup -Identity "$OldName" -RejectMessagesFromSendersOrMembers @{Add = $item.Name } -ErrorAction SilentlyContinue -ErrorVariable E1
                        if ($E1 -like "*ManagementObjectNotFoundException*") {
                            Write-Host "  WARNING: Can't add the entry to the property because it wasn't found in Exchange Online" -ForegroundColor Yellow
                            $ir++
                        }
                    }
                }
                if (($OldDG.BypassModerationFromSendersOrMembers).count -gt 0) {
                    foreach ($item in $OldDG.BypassModerationFromSendersOrMembers) {
                        Write-Host "  Adding $($item.Name) to the BypassModerationFromSendersOrMembers property"
                        Set-OnlineDistributionGroup -Identity "$OldName" -BypassModerationFromSendersOrMembers @{Add = $item.Name } -ErrorAction SilentlyContinue -ErrorVariable E1
                        if ($E1 -like "*ManagementObjectNotFoundException*") {
                            Write-Host "  WARNING: Can't add the entry to the property because it wasn't found in Exchange Online" -ForegroundColor Yellow
                            $ir++
                        }
                    }
                }
                if (($OldDG.ModeratedBy).count -gt 0) {
                    foreach ($item in $OldDG.ModeratedBy) {
                        Write-Host "  Adding $($item.Name) to the ModeratedBy property"
                        Set-OnlineDistributionGroup -Identity "$OldName" -ModeratedBy @{Add = $item.Name } -ErrorAction SilentlyContinue -ErrorVariable E1
                        if ($E1 -like "*ManagementObjectNotFoundException*") {
                            Write-Host "  WARNING: Can't add the entry to the property because it wasn't found in Exchange Online" -ForegroundColor Yellow
                            $ir++
                        }
                    }
                }
                if (($OldDG.GrantSendOnBehalfTo).count -gt 0) {
                    foreach ($item in $OldDG.GrantSendOnBehalfTo) {
                        Write-Host "  Adding $($item.Name) to the GrantSendOnBehalfTo property"
                        Set-OnlineDistributionGroup -Identity "$OldName" -GrantSendOnBehalfTo @{Add = $item.Name } -ErrorAction SilentlyContinue -ErrorVariable E1
                        if ($E1 -like "*ManagementObjectNotFoundException*") {
                            Write-Host "  WARNING: Can't add the entry to the property because it wasn't found in Exchange Online" -ForegroundColor Yellow
                            $ir++
                        }
                    }
                }
                if (($OldDG.ManagedBy).count -gt 0) {
                    foreach ($item in $OldDG.ManagedBy) {
                        Write-Host "  Adding $($item.Name) to the ManagedBy property"
                        Set-OnlineDistributionGroup -Identity "$OldName" -ManagedBy @{Add = $item.Name } -ErrorAction SilentlyContinue -ErrorVariable E1
                        if ($E1 -like "*ManagementObjectNotFoundException*") {
                            Write-Host "  WARNING: Can't add the entry to the property because it wasn't found in Exchange Online" -ForegroundColor Yellow
                            $ir++
                        }
                    }
                }
                if (($OldMembers).count -gt 0) {
                    foreach ($item in $OldMembers) {
                        Write-Host "  Adding $item as a member"
                        Add-OnlineDistributionGroupMember -Identity "$OldName" -Member $item -ErrorAction SilentlyContinue -ErrorVariable E1
                        if ($E1 -like "*ManagementObjectNotFoundException*") {
                            Write-Host "  WARNING: Can't add the entry to the property because it wasn't found in Exchange Online" -ForegroundColor Yellow
                            $ir++
                        }
                    }
                }
            }

            Write-Host "  Setting the rest of additional properties for: $Group"
            Set-OnlineDistributionGroup `
                -Identity "$Group" `
                -BypassNestedModerationEnabled $OldDG.BypassNestedModerationEnabled `
                -CustomAttribute1 $OldDG.CustomAttribute1 `
                -CustomAttribute2 $OldDG.CustomAttribute2 `
                -CustomAttribute3 $OldDG.CustomAttribute3 `
                -CustomAttribute4 $OldDG.CustomAttribute4 `
                -CustomAttribute5 $OldDG.CustomAttribute5 `
                -CustomAttribute6 $OldDG.CustomAttribute6 `
                -CustomAttribute7 $OldDG.CustomAttribute7 `
                -CustomAttribute8 $OldDG.CustomAttribute8 `
                -CustomAttribute9 $OldDG.CustomAttribute9 `
                -CustomAttribute10 $OldDG.CustomAttribute10 `
                -CustomAttribute11 $OldDG.CustomAttribute11 `
                -CustomAttribute12 $OldDG.CustomAttribute12 `
                -CustomAttribute13 $OldDG.CustomAttribute13 `
                -CustomAttribute14 $OldDG.CustomAttribute14 `
                -CustomAttribute15 $OldDG.CustomAttribute15 `
                -ExtensionCustomAttribute1 $OldDG.ExtensionCustomAttribute1 `
                -ExtensionCustomAttribute2 $OldDG.ExtensionCustomAttribute2 `
                -ExtensionCustomAttribute3 $OldDG.ExtensionCustomAttribute3 `
                -ExtensionCustomAttribute4 $OldDG.ExtensionCustomAttribute4 `
                -ExtensionCustomAttribute5 $OldDG.ExtensionCustomAttribute5 `
                -HiddenFromAddressListsEnabled $OldDG.HiddenFromAddressListsEnabled `
                -MailTip $OldDG.MailTip `
                -MemberDepartRestriction $OldDG.MemberDepartRestriction `
                -MemberJoinRestriction $OldDG.MemberJoinRestriction `
                -ModerationEnabled $OldDG.ModerationEnabled `
                -ReportToManagerEnabled $OldDG.ReportToManagerEnabled `
                -ReportToOriginatorEnabled $OldDG.ReportToOriginatorEnabled `
                -RequireSenderAuthenticationEnabled $OldDG.RequireSenderAuthenticationEnabled `
                -SendModerationNotifications $OldDG.SendModerationNotifications `
                -SendOofMessageToOriginatorEnabled $OldDG.SendOofMessageToOriginatorEnabled `
                -BypassSecurityGroupManagerCheck | Out-Null

            Write-Host "  $Group got successfully created"

            Write-Host "  Checking if $Group properties are the same on both sides"
            $NewDG = Get-OnlineDistributionGroup $Group
            $UniqueProps = "Name", "Alias", "DisplayName", "PrimarySmtpAddress", "BypassNestedModerationEnabled", "CustomAttribute1", "CustomAttribute2", "CustomAttribute3", "CustomAttribute4", "CustomAttribute5", "CustomAttribute6", "CustomAttribute7", "CustomAttribute8", "CustomAttribute9", "CustomAttribute10", "CustomAttribute11", "CustomAttribute12", "CustomAttribute13", "CustomAttribute14", "CustomAttribute15", "ExtensionCustomAttribute1", "ExtensionCustomAttribute2", "ExtensionCustomAttribute3", "ExtensionCustomAttribute4", "ExtensionCustomAttribute5", "HiddenFromAddressListsEnabled", "MailTip", "MemberDepartRestriction", "MemberJoinRestriction", "ModerationEnabled", "ReportToManagerEnabled", "ReportToOriginatorEnabled", "RequireSenderAuthenticationEnabled", "SendModerationNotifications", "SendOofMessageToOriginatorEnabled"

            foreach ($prop in $UniqueProps) {
                if ( $OldDG.$prop -ne $NewDG.$prop ) {
                    Write-Host "$prop not matching" -ForegroundColor Red
                    $i++
                }
            }

            Write-Host "" -NoNewline

            if ($i -gt 0) {
                Write-Host "  There were $i properties not matching between DL's. DL $Group was created in EXO but the one from on-premises won't be removed. Please review the log for this DL, correct the mismatching properties manually, remove the on-premises DL and create the MailContact on-premises"
                Stop-Transcript
                Rename-Item $LogPath\$group-log.txt $LogPath\Failed-$group-log.txt -Force
                Write-Host "  Process FAILED for $group and details can be found at $LogPath\Failed-$group-log.txt" -ForegroundColor Red
                $Failed++
            } else {
                Write-Host "  $Group validated correctly"
                Write-Host "  Removing $Group from on-premises"
                Remove-DistributionGroup $Group -Confirm:$false
                if ($null -eq (Get-DistributionGroup $Group -ErrorAction 'SilentlyContinue').IsValid) {
                    Write-Host "  Distribution Group $Group removed from on-premises"
                    Write-Host "  Creating $Group as a Mail-Contact on-premise"
                    $OutLoop = $true
                    Write-Host "  Waiting for the onmicrosoft.com address to be provisioned to the DL (this may take a while) " -NoNewline
                    while ($OutLoop) {
                        $NewDG = Get-OnlineDistributionGroup $Group
                        if ( $null -ne ($NewDG.EmailAddresses | Where-Object { $_.EndsWith('onmicrosoft.com') -and $_.StartsWith('smtp:') -and -not $_.EndsWith('mail.onmicrosoft.com') } ) ) {
                            $OutLoop = $false
                        }
                        Write-Host "." -NoNewline
                        Start-Sleep -Seconds 10
                    }
                    Write-Host ""
                    $MoeraEmailAddress = ($NewDG.EmailAddresses | Where-Object { $_.EndsWith('onmicrosoft.com') -and $_.StartsWith('smtp:') -and -not $_.EndsWith('mail.onmicrosoft.com') }).split(':')[1]
                    New-MailContact -Name $OldDG.Name -Alias $OldDG.Alias -DisplayName $OldDG.DisplayName -PrimarySmtpAddress $OldDG.PrimarySmtpAddress -ExternalEmailAddress $MoeraEmailAddress | Out-Null

                    if (((Get-MailContact $OldDG.Alias -ErrorAction 'SilentlyContinue').IsValid) -eq $true) {
                        Write-Host "  Mail-Contact was created successfully"
                        if ($ir -gt 0) {
                            Write-Host "  WARNING: $Group validated correctly, but there are entries that could not be added as members for one or more properties like AcceptMessagesOnlyFromSendersOrMembers, RejectMessagesFromSendersOrMembers, BypassModerationFromSendersOrMembers, GrantSendOnBehalfTo, ModeratedBy or Members" -ForegroundColor Yellow
                            Stop-Transcript
                            Rename-Item $LogPath\$group-log.txt $LogPath\Warning-$group-log.txt -Force
                            Write-Host "Group was migrated but ended up with warnings for $group and details can be found at $LogPath\Warning-$group-log.txt" -ForegroundColor Yellow
                            $Warning++
                        } else {
                            Stop-Transcript
                            Rename-Item $LogPath\$group-log.txt $LogPath\OK-$group-log.txt -Force
                            Write-Host "Process ended up correctly for $group and details can be found at $LogPath\OK-$group-log.txt" -ForegroundColor Green
                            $Success++
                        }
                    } else {
                        Write-Host "  Mail-Contact wasn't found on-premises. You need to create it Manually"
                        Stop-Transcript
                        Rename-Item $LogPath\$group-log.txt $LogPath\Failed-$group-log.txt -Force
                        Write-Host "Process FAILED for $group and details can be found at $LogPath\Failed-$group-log.txt" -ForegroundColor Red
                        $Failed++
                    }
                } else {
                    Write-Host "  Distribution Group $Group wasn't removed from on-premises" -ForegroundColor Red
                    Stop-Transcript
                    Rename-Item $LogPath\$group-log.txt $LogPath\Failed-$group-log.txt -Force
                    Write-Host "Process FAILED for $group and details can be found at $LogPath\Failed-$group-log.txt" -ForegroundColor Red
                    $Failed++
                }
            }
        } else {
            Write-Host "  ERROR: The distribution group '$Group' was not found in Exchange Online" -ForegroundColor Red
            Stop-Transcript
            Rename-Item $LogPath\$group-log.txt $LogPath\Failed-$group-log.txt -Force
            Write-Host "Process FAILED for $group and details can be found at $LogPath\Failed-$group-log.txt" -ForegroundColor Red
            $Failed++
        }
    } else {
        Write-Host "  ERROR: The distribution group '$Group' was not found in Exchange On-Premises" -ForegroundColor Red
        Stop-Transcript
        Rename-Item $LogPath\$group-log.txt $LogPath\Failed-$group-log.txt -Force
        Write-Host "Process FAILED for $group and details can be found at $LogPath\Failed-$group-log.txt" -ForegroundColor Red
        $Failed++
    }
    Remove-Item $LogPath\$Group.csv -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "-------------------------------------------"
Write-Host "SUMMARY: Total DL's included on the CSV file: $Total, " -NoNewline
Write-Host "Migrated with warning: $Warning, " -ForegroundColor Yellow -NoNewline
Write-Host "Failed: $Failed, " -ForegroundColor Red -NoNewline
Write-Host "Migrated Successfully: $Success" -ForegroundColor Green -NoNewline
Write-Host ""
