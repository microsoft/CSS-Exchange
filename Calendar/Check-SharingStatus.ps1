# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# This script runs a variety of cmdlets to establish a baseline of the sharing status of a Calendar.
#
# .PARAMETER Identity
#  Owner Mailbox to query, owner of the Mailbox sharing the calendar.
#  Receiver of the shared mailbox, often the Delegate.
#
# .EXAMPLE
# Check-SharingStatus.ps1 -Owner Owner@contoso.com -Receiver Receiver@contoso.com

# Define the parameters
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Owner,
    [Parameter(Mandatory=$true)]
    [string]$Receiver
)

$BuildVersion = ""

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if (Test-ScriptVersion -AutoUpdate) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."  -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

$script:PIIAccess = $true #Assume we have PII access until we find out otherwise

<#
.SYNOPSIS
    Formats the CalendarSharingInvite logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing accept logs for a given identity and outputs the most recent update for each recipient.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessCalendarSharingInviteLogs {
    param (
        [string]$Identity
    )

    # Define the header row
    $header = "Timestamp", "Mailbox", "Entry MailboxOwner", "Recipient", "RecipientType", "SharingType", "DetailLevel"
    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    Write-Output "------------------------"
    Write-Output "Looking for modern calendar sharing accept data for [$Identity]."

    # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
    try {
        # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName CalendarSharingInvite -ErrorAction SilentlyContinue

        $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName CalendarSharingInvite
    } catch {
        # Code to run if an error occurs
        Write-Error "An error occurred: $_"
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        Write-Output "No data found for [$Identity]."
        return
    }

    $logLines =@()
    # Split the output into an array of lines
    $logLines = $logOutput.MailboxLog -split "`r`n"

    # Loop through each line of the output
    foreach ($line in $logLines) {
        if ($line -like "*RecipientType*") {
            $csvString += $line + "`n"
        }
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("Entry MailboxOwner:", "")
    $csvString = $csvString.Replace("Recipient:", "")
    $csvString = $csvString.Replace("RecipientType:", "")
    $csvString = $csvString.Replace("Handler=", "")
    $csvString = $csvString.Replace("ms-exchange-", "")
    $csvString = $csvString.Replace("DetailLevel=", "")

    # Convert the CSV string to an object
    $csvObject = $csvString | ConvertFrom-Csv

    # Access the values as properties of the object
    foreach ($row in $csvObject) {
        Write-Debug "$($row.Recipient) - $($row.SharingType) - $($row.detailLevel)"
    }

    #Filter the output to get the most recent update foreach recipient
    $mostRecentRecipients = $csvObject | Sort-Object Recipient -Unique | Sort-Object Timestamp -Descending

    # Output the results to the console
    Write-Output "User [$Identity] has shared their calendar with the following recipients:"
    Write-Output $mostRecentRecipients | Format-Table -a Timestamp, Recipient, SharingType, DetailLevel
}

<#
.SYNOPSIS
    Formats the AcceptCalendarSharingInvite logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing invite logs.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessCalendarSharingAcceptLogs {
    param (
        [string]$Identity
    )

    # Define the header row
    $header = "Timestamp", "Mailbox", "SharedCalendarOwner", "FolderName"
    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    Write-Output "------------------------"
    Write-Output "Looking for Modern Calendar Sharing Accept data for [$Identity]."

    # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
    try {
        # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite -ErrorAction SilentlyContinue

        $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite
    } catch {
        # Code to run if an error occurs
        Write-Error "An error occurred: $_"
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        Write-Output "No AcceptCalendarSharingInvite Logs found for [$Identity]."
        return
    }

    $logLines =@()
    # Split the output into an array of lines
    $logLines = $logOutput.MailboxLog -split "`r`n"

    # Loop through each line of the output
    foreach ($line in $logLines) {
        if ($line -like "*CreateInternalSharedCalendarGroupEntry*") {
            $csvString += $line + "`n"
        }
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("Entry MailboxOwner:", "")
    $csvString = $csvString.Replace("Entry CreateInternalSharedCalendarGroupEntry: ", "")
    $csvString = $csvString.Replace("Creating a shared calendar for ", "")
    $csvString = $csvString.Replace("calendar name ", "")

    # Convert the CSV string to an object
    $csvObject = $csvString | ConvertFrom-Csv

    # Access the values as properties of the object
    foreach ($row in $csvObject) {
        Write-Debug "$($row.Timestamp) - $($row.SharedCalendarOwner) - $($row.FolderName) "
    }

    # Filter the output to get the most recent update for each recipient
    # $mostRecentSharedCalendars = $csvObject |sort-object SharedCalendarOwner -Unique | Sort-Object Timestamp -Descending

    # Output the results to the console
    Write-Host "User [$Identity] has accepted copies of the shared calendar from the following recipients on these dates:"
    #Write-Host $csvObject | Format-Table -a Timestamp, SharedCalendarOwner, FolderName
    $csvObject | Format-Table -a Timestamp, SharedCalendarOwner, FolderName
}

<#
.SYNOPSIS
    Display Calendar Owner information.
.DESCRIPTION
    This function displays key Calendar Owner information.
.PARAMETER Identity
    The SMTP Address for Owner of the shared calendar.
#>
function GetOwnerInformation {
    param (
        [string]$Owner
    )
    #Standard Owner information
    Write-Host -ForegroundColor DarkYellow "------------------------------------------------"
    Write-Host -ForegroundColor DarkYellow "Key Owner Mailbox Information:"
    $script:OwnerMB = Get-Mailbox $Owner
    # Write-Host "`t DisplayName:" $script:OwnerMB.DisplayName
    # Write-Host "`t Database:" $script:OwnerMB.Database
    # Write-Host "`t ServerName:" $script:OwnerMB.ServerName
    # Write-Host "`t LitigationHoldEnabled:" $script:OwnerMB.LitigationHoldEnabled
    # Write-Host "`t CalendarVersionStoreDisabled:" $script:OwnerMB.CalendarVersionStoreDisabled
    # Write-Host "`t CalendarRepairDisabled:" $script:OwnerMB.CalendarRepairDisabled
    # Write-Host "`t RecipientTypeDetails:" $script:OwnerMB.RecipientTypeDetails
    # Write-Host "`t RecipientType:" $script:OwnerMB.RecipientType
    Get-Mailbox $Owner | Format-List DisplayName, Database, ServerName, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

    if ($null -eq $script:OwnerMB) {
        Write-Host -ForegroundColor Red "Could not find Owner Mailbox [$Owner]."
        exit
    }

    Write-Host -ForegroundColor DarkYellow "Send on Behalf Granted to :"
    foreach ($del in $($script:OwnerMB.GrantSendOnBehalfTo)) {
        Write-Host -ForegroundColor Blue "`t$($del)"
    }
    Write-Host "`n`n`n"

    if ($script:OwnerMB.DisplayName -like "Redacted*") {
        Write-Host -ForegroundColor Yellow "Do Not have PII information for the Owner."
        Write-Host -ForegroundColor Yellow "Get PII Access for $($script:OwnerMB.Database)."
        $script:PIIAccess = $false
    }

    Write-Host  -ForegroundColor DarkYellow  "Owner Calendar Folder Statistics:"
    $OwnerCalendar = Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar
    $OwnerCalendarName = ($OwnerCalendar | Where-Object FolderPath -EQ "/Calendar").Name

    Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize

    Write-Host  -ForegroundColor DarkYellow "Owner Calendar Permissions:"
    Get-mailboxFolderPermission "${Owner}:\$OwnerCalendarName"  | Format-Table -a User, AccessRights, SharingPermissionFlags

    Write-Host  -ForegroundColor DarkYellow "Owner Root MB Permissions:"
    Get-mailboxPermission $Owner | Format-Table -a User, AccessRights, SharingPermissionFlags

    # Write-Host  -ForegroundColor DarkYellow "Owner Recoverable Items Folder Statistics:	"
    # Get-MailboxFolderStatistics -Identity $Owner -FolderScope RecoverableItems | Where-Object FolderPath -Like *Calendar* | Format-Table FolderPath, ItemsInFolder, FolderAndSubfolderSize

    Write-Host  -ForegroundColor DarkYellow "Owner Modern Sharing Sent Invites"
    ProcessCalendarSharingInviteLogs -Identity $Owner
}

<#
.SYNOPSIS
    Displays key information from the receiver of the shared Calendar.
.DESCRIPTION
    This function displays key Calendar Receiver information.
.PARAMETER Identity
    The SMTP Address for Receiver of the shared calendar.
#>
function GetReceiverInformation {
    param (
        [string]$Receiver
    )
    #Standard Receiver information
    Write-Host  -ForegroundColor Cyan "`r`r`r------------------------------------------------"
    Write-Host  -ForegroundColor Cyan "Key Receiver Information: [$Receiver]"
    Get-Mailbox $Receiver | Format-List DisplayName, Database, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

    Write-Host  -ForegroundColor Cyan "Receiver Calendar Folders (look for a copy of [$Owner] Calendar):"
    $CalStats = Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar
    $CalStats | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize
    $ReceiverCalendarName = ($CalStats | Where-Object FolderType -EQ "Calendar").Name

    if ($CalStats | Where-Object Name -Like $owner* ) {
        Write-Host -ForegroundColor Yellow "Looks like we might have found a copy of the Owner Calendar in the Receiver Calendar."
        $CalStats | Where-Object Name -Like $owner* | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize
        if (($CalStats | Where-Object Name -Like $owner*).count -gt 1) {
            Write-Host -ForegroundColor Yellow "Warning :Might have found more than one copy of the Owner Calendar in the Receiver Calendar."
        }
    } else {
        Write-Host -ForegroundColor Yellow "Warning: Could not Identify the Owner Calendar in the Receiver Calendar."
    }

    if ($ReceiverCalendarName -like "REDACTED-*" ) {
        Write-Host -ForegroundColor Yellow "Do Not have PII information for the Receiver"
        $script:PIIAccess = $false
    }

    Write-Host  -ForegroundColor Cyan "`n`nReceiver Accepted the Following Modern Calendar Sharing Accept Logs:"
    ProcessCalendarSharingAcceptLogs -Identity $Receiver

    if (Get-Command -Name Get-CalendarEntries -ErrorAction SilentlyContinue) {
        Write-Verbose "Found Get-CalendarEntries cmdlet. Running cmdlet: Get-CalendarEntries -Identity $Receiver"
        # ToDo: Check each value for proper sharing permissions (i.e.  $X.CalendarSharingPermissionLevel -eq "ReadWrite" )
        $ReceiverCalEntries = Get-CalendarEntries -Identity $Receiver
        Write-Host "CalendarGroupName : $($ReceiverCalEntries.CalendarGroupName)"
        Write-Host "CalendarName : $($ReceiverCalEntries.CalendarName)"
        Write-Host "OwnerEmailAddress : $($ReceiverCalEntries.OwnerEmailAddress)"
        Write-Host "SharingModelType: $($ReceiverCalEntries.SharingModelType)"
        Write-Host "IsOrphanedEntry: $($ReceiverCalEntries.IsOrphanedEntry)"

        # need to check if Get-CalendarValidationResult in the PS Workspace
        if ((Get-Command -Name Get-CalendarValidationResult -ErrorAction SilentlyContinue) -and
            $null -ne $ReceiverCalEntries) {
            Write-Host "Running cmdlet: Get-CalendarValidationResult -Version V2 -Identity $Receiver -SourceCalendarId $($ReceiverCalEntries[0].LocalFolderId) -TargetUserId $Owner -IncludeAnalysis 1 -OnlyReportErrors 1"
            $ewsId_del= $ReceiverCalEntries[0].LocalFolderId
            Get-CalendarValidationResult -Version V2 -Identity $Receiver -SourceCalendarId $ewsId_del -TargetUserId $Owner -IncludeAnalysis 1 -OnlyReportErrors 1
        }
    }

    if ($script:PIIAccess) {
        Write-Host "Checking for Owner copy Calendar in Receiver Calendar:"
        Write-Host "Running cmdlet:"
        Write-Host -NoNewline -ForegroundColor Yellow "Get-MailboxCalendarFolder -Identity ${Receiver}:\$ReceiverCalendarName\$($script:OwnerMB.DisplayName)"
        try {
            Get-MailboxCalendarFolder -Identity "${Receiver}:\$ReceiverCalendarName\$($script:OwnerMB.DisplayName)" | Format-List Identity, CreationTime, ExtendedFolderFlags, ExtendedFolderFlags2, CalendarSharingFolderFlags, CalendarSharingOwnerSmtpAddress, CalendarSharingPermissionLevel, SharingLevelOfDetails, SharingPermissionFlags, LastAttemptedSyncTime, LastSuccessfulSyncTime, SharedCalendarSyncStartDate
        } catch {
            Write-Error "Failed to get the Owner Calendar from the Receiver Mailbox.  This is fine if not using Modern Sharing."
        }
    } else {
        Write-Host "Do Not have PII information for the Receiver."
        Write-Host "Get PII Access for $($script:OwnerMB.Database)."
    }
}

# Main
GetOwnerInformation -Owner $Owner
GetReceiverInformation -Receiver $Receiver
