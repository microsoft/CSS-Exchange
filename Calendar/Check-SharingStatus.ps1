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
        Write-Host "No data found for [$Identity]."
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
    Write-Host "User [$Identity] has shared their calendar with the following recipients:"
    $mostRecentRecipients | Format-Table -a Timestamp, Recipient, SharingType, DetailLevel
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
        Write-Host "No AcceptCalendarSharingInvite Logs found for [$Identity]."
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
    Write-Host "Receiver [$Identity] has accepted copies of the shared calendar from the following recipients on these dates:"
    #Write-Host $csvObject | Format-Table -a Timestamp, SharedCalendarOwner, FolderName
    $csvObject | Format-Table -a Timestamp, SharedCalendarOwner, FolderName
}

<#
.SYNOPSIS
    Formats the InternetCalendar logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing invite logs.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessInternetCalendarLogs {
    param (
        [string]$Identity
    )

    # Define the header row
    $header = "Timestamp", "Mailbox", "SyncDetails", "PublishingUrl", "RemoteFolderName", "LocalFolderId", "Folder"

    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    try {
        # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite -ErrorAction SilentlyContinue

        $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName InternetCalendar
    } catch {
        # Code to run if an error occurs
        Write-Error "An error occurred: $_"
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        Write-Host "No InternetCalendar Logs found for [$Identity]."
        Write-Host -ForegroundColor Yellow "User [$Identity] is not receiving any Published Calendars."
        return
    }

    $logLines =@()

    # Split the output into an array of lines
    $logLines = $logOutput.MailboxLog -split "`r`n"

    # Loop through each line of the output
    foreach ($line in $logLines) {
        if ($line -like "*Entry Sync Details for InternetCalendar subscription DataType=calendar*") {
            $csvString += $line + "`n"
        }
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("Entry Sync Details for InternetCalendar subscription DataType=calendar", "InternetCalendar")
    $csvString = $csvString.Replace("PublishingUrl=", "")
    $csvString = $csvString.Replace("RemoteFolderName=", "")
    $csvString = $csvString.Replace("LocalFolderId=", "")
    $csvString = $csvString.Replace("folder ", "")

    # Convert the CSV string to an object
    $csvObject = $csvString | ConvertFrom-Csv

    # Clean up the Folder column
    foreach ($row in $csvObject) {
        $row.Folder = $row.Folder.Split("with")[0]
    }

    Write-Host -ForegroundColor Cyan "Receiver [$Identity] is/was receiving the following Published Calendars:"
    $csvObject | Sort-Object -Unique RemoteFolderName | Format-Table -a RemoteFolderName, Folder, PublishingUrl
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
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-Mailbox $Owner'"
    $script:OwnerMB = Get-Mailbox $Owner
    # Write-Host "`t DisplayName:" $script:OwnerMB.DisplayName
    # Write-Host "`t Database:" $script:OwnerMB.Database
    # Write-Host "`t ServerName:" $script:OwnerMB.ServerName
    # Write-Host "`t LitigationHoldEnabled:" $script:OwnerMB.LitigationHoldEnabled
    # Write-Host "`t CalendarVersionStoreDisabled:" $script:OwnerMB.CalendarVersionStoreDisabled
    # Write-Host "`t CalendarRepairDisabled:" $script:OwnerMB.CalendarRepairDisabled
    # Write-Host "`t RecipientTypeDetails:" $script:OwnerMB.RecipientTypeDetails
    # Write-Host "`t RecipientType:" $script:OwnerMB.RecipientType

    if (-not $script:OwnerMB) {
        Write-Host -ForegroundColor Yellow "Could not find Owner Mailbox [$Owner]."
        Write-Host -ForegroundColor DarkYellow "Defaulting to External Sharing or Publishing."
        return
    }

    $script:OwnerMB | Format-List DisplayName, Database, ServerName, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

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

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Folder Statistics:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar'"
    $OwnerCalendar = Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar
    $OwnerCalendarName = ($OwnerCalendar | Where-Object FolderType -EQ "Calendar").Name

    $OwnerCalendar | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-mailboxFolderPermission "${Owner}:\$OwnerCalendarName" | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    Get-mailboxFolderPermission "${Owner}:\$OwnerCalendarName" | Format-Table -a User, AccessRights, SharingPermissionFlags

    Write-Host -ForegroundColor DarkYellow "Owner Root MB Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-mailboxPermission $Owner | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    Get-mailboxPermission $Owner | Format-Table -a User, AccessRights, SharingPermissionFlags

    Write-Host -ForegroundColor DarkYellow "Owner Modern Sharing Sent Invites"
    ProcessCalendarSharingInviteLogs -Identity $Owner

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Folder Information:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxCalendarFolder "${Owner}:\$OwnerCalendarName"'"

    $OwnerCalendarFolder = Get-MailboxCalendarFolder "${Owner}:\$OwnerCalendarName"
    if ($OwnerCalendarFolder.PublishEnabled) {
        Write-Host -ForegroundColor Green "Owner Calendar is Published."
        $script:OwnerPublished = $true
    } else {
        Write-Host -ForegroundColor Yellow "Owner Calendar is not Published."
        $script:OwnerPublished = $false
    }

    if ($OwnerCalendarFolder.ExtendedFolderFlags.Contains("SharedOut")) {
        Write-Host -ForegroundColor Green "Owner Calendar is Shared Out using Modern Sharing."
        $script:OwnerModernSharing = $true
    } else {
        Write-Host -ForegroundColor Yellow "Owner Calendar is not Shared Out."
        $script:OwnerModernSharing = $false
    }
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
    Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
    Write-Host -ForegroundColor Cyan "Key Receiver MB Information: [$Receiver]"
    Write-Host -ForegroundColor Cyan "Running: 'Get-Mailbox $Receiver'"
    $script:ReceiverMB = Get-Mailbox $Receiver

    if (-not $script:ReceiverMB) {
        Write-Host -ForegroundColor Yellow "Could not find Receiver Mailbox [$Receiver]."
        Write-Host -ForegroundColor Yellow "Defaulting to External Sharing or Publishing."
        return
    }

    $script:ReceiverMB | Format-List DisplayName, Database, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

    if ($script:OwnerMB.OrganizationalUnitRoot -eq $script:ReceiverMB.OrganizationalUnitRoot) {
        Write-Host -ForegroundColor Yellow "Owner and Receiver are in the same OU."
        Write-Host -ForegroundColor Yellow "Owner and Receiver will be using Internal Sharing."
        $script:SharingType = "InternalSharing"
    } else {
        Write-Host -ForegroundColor Yellow "Owner and Receiver are in different OUs."
        Write-Host -ForegroundColor Yellow "Owner and Receiver will be using External Sharing or Publishing."
        $script:SharingType = "ExternalSharing"
    }

    Write-Host -ForegroundColor Cyan "Receiver Calendar Folders (look for a copy of [$($OwnerMB.DisplayName)] Calendar):"
    Write-Host -ForegroundColor Cyan "Running: 'Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar'"
    $CalStats = Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar
    $CalStats | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize
    $ReceiverCalendarName = ($CalStats | Where-Object FolderType -EQ "Calendar").Name

    # Note $Owner has a * at the end in case we have had multiple setup for the same user, they will be appended with a " 1", etc.
    if (($CalStats | Where-Object Name -Like $owner*) -or ($CalStats | Where-Object Name -Like "$($ownerMB.DisplayName)*" )) {
        Write-Host -ForegroundColor Green "Looks like we might have found a copy of the Owner Calendar in the Receiver Mailbox."
        Write-Host -ForegroundColor Green "This is a good indication the there is a Modern Sharing Relationship between these users."
        Write-Host -ForegroundColor Green "If the clients use the Modern Sharing or not is a up to the client."
        $script:ModernSharing = $true

        $CalStats | Where-Object Name -Like $owner* | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize
        if (($CalStats | Where-Object Name -Like $owner*).count -gt 1) {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
        }
    } else {
        Write-Host -ForegroundColor Yellow "Warning: Could not Identify the Owner's [$Owner] Calendar in the Receiver Mailbox."
    }

    if ($ReceiverCalendarName -like "REDACTED-*" ) {
        Write-Host -ForegroundColor Yellow "Do Not have PII information for the Receiver"
        $script:PIIAccess = $false
    }

    ProcessCalendarSharingAcceptLogs -Identity $Receiver
    ProcessInternetCalendarLogs -Identity $Receiver

    if (($script:SharingType -like "InternalSharing") -or
    ($script:SharingType -like "ExternalSharing")) {
        # Validate Modern Sharing Status
        if (Get-Command -Name Get-CalendarEntries -ErrorAction SilentlyContinue) {
            Write-Verbose "Found Get-CalendarEntries cmdlet. Running cmdlet: Get-CalendarEntries -Identity $Receiver"
            # ToDo: Check each value for proper sharing permissions (i.e.  $X.CalendarSharingPermissionLevel -eq "ReadWrite" )
            $ReceiverCalEntries = Get-CalendarEntries -Identity $Receiver
            # Write-Host "CalendarGroupName : $($ReceiverCalEntries.CalendarGroupName)"
            # Write-Host "CalendarName : $($ReceiverCalEntries.CalendarName)"
            # Write-Host "OwnerEmailAddress : $($ReceiverCalEntries.OwnerEmailAddress)"
            # Write-Host "SharingModelType: $($ReceiverCalEntries.SharingModelType)"
            # Write-Host "IsOrphanedEntry: $($ReceiverCalEntries.IsOrphanedEntry)"

            Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
            Write-Host "New Model Calendar Sharing Entries:"
            $ReceiverCalEntries | Where-Object SharingModelType -Like New | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry

            Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
            Write-Host "Old Model Calendar Sharing Entries:"
            Write-Host "Consider upgrading these to the new model."
            $ReceiverCalEntries | Where-Object SharingModelType -Like Old | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry

            # need to check if Get-CalendarValidationResult in the PS Workspace
            if ((Get-Command -Name Get-CalendarValidationResult -ErrorAction SilentlyContinue) -and
                $null -ne $ReceiverCalEntries) {
                $ewsId_del= $ReceiverCalEntries[0].LocalFolderId
                Write-Host "Running cmdlet: Get-CalendarValidationResult -Version V2 -Identity $Receiver -SourceCalendarId $ewsId_del -TargetUserId $Owner -IncludeAnalysis 1 -OnlyReportErrors 1 | FT -a GlobalObjectId, EventValidationResult  "
                Get-CalendarValidationResult -Version V2 -Identity $Receiver -SourceCalendarId $ewsId_del -TargetUserId $Owner -IncludeAnalysis 1 -OnlyReportErrors 1 | Format-List UserPrimarySMTPAddress, Subject, GlobalObjectId, EventValidationResult, EventComparisonResult
            }
        }

        #Output key Modern Sharing information
        if (($script:PIIAccess) -and (-not ([string]::IsNullOrEmpty($script:OwnerMB)))) {
            Write-Host "Checking for Owner copy Calendar in Receiver Calendar:"
            Write-Host "Running cmdlet:"
            Write-Host -NoNewline -ForegroundColor Yellow "Get-MailboxCalendarFolder -Identity ${Receiver}:\$ReceiverCalendarName\$($script:OwnerMB.DisplayName)"
            try {
                Get-MailboxCalendarFolder -Identity "${Receiver}:\$ReceiverCalendarName\$($script:OwnerMB.DisplayName)" | Format-List Identity, CreationTime, ExtendedFolderFlags, ExtendedFolderFlags2, CalendarSharingFolderFlags, CalendarSharingOwnerSmtpAddress, CalendarSharingPermissionLevel, SharingLevelOfDetails, SharingPermissionFlags, LastAttemptedSyncTime, LastSuccessfulSyncTime, SharedCalendarSyncStartDate
            } catch {
                Write-Error "Failed to get the Owner Calendar from the Receiver Mailbox.  This is fine if not using Modern Sharing."
            }
        } else {
            Write-Host "Do Not have PII information for the Owner, so can not check the Receivers Copy of the Owner Calendar."
            Write-Host "Get PII Access for both mailboxes and try again."
        }
    }
}

# Main
$script:ModernSharing
$script:SharingType
GetOwnerInformation -Owner $Owner
GetReceiverInformation -Receiver $Receiver

Write-Host -ForegroundColor Blue "`r`r`r------------------------------------------------"
Write-Host -ForegroundColor Blue "Summary:"
Write-Host -ForegroundColor Blue "Mailbox Owner [$Owner] and Receiver [$Receiver] are using [$script:SharingType] for Calendar Sharing."
Write-Host -ForegroundColor Blue "It appears like the backend [$(if ($script:ModernSharing) {"IS"} else {"is NOT"})] using Modern Calendar Sharing."
