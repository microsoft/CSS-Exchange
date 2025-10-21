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
# .\Check-SharingStatus.ps1 -Owner Owner@contoso.com -Receiver Receiver@contoso.com

# Define the parameters
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Owner,
    [Parameter(Mandatory=$true)]
    [string]$Receiver,
    [Parameter()]
    [bool]$ModernSharingOnly = $true
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
    $header4Line = "Timestamp", "Mailbox",  "SharedCalendarOwner", "FolderName"
    $header5Line = "Timestamp", "MailboxLast", "MailboxFirst", "SharedCalendarOwner", "FolderName"

    # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
    try {
        # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite -ErrorAction SilentlyContinue
        Write-Host "Collecting AcceptCalendarSharingInvite logs for [$Identity] ..."
        $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite 2>$null
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
    $filteredLogLines = @()
    foreach ($line in $logLines) {
        if ($line -like "*CreateInternalSharedCalendarGroupEntry*") {
            $filteredLogLines += $line + "`n"
        }
    }
    $ElementCount = ($filteredLogLines[0] -split ',').Count

    if ($ElementCount -eq 4) {
        $header = $header4Line
    } elseif ($ElementCount -eq 5) {
        $header = $header5Line
    } else {
        Write-Host "Unexpected number of elements [$ElementCount] in the log lines for [$Identity]."
        return
    }

    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    foreach ($line in $filteredLogLines) {
        $csvString += $line + "`n"
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("'", "")
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
    #Write-Host -ForegroundColor Cyan "Receiver [$Identity] has accepted copies of the shared calendar from the following recipients:"
    #$csvObject | Sort-Object { [DateTime]$_.Timestamp } -Descending | Sort-Object SharedCalendarOwner -Unique | Sort-Object { [DateTime]$_.Timestamp } -Descending | Format-Table -a Timestamp, SharedCalendarOwner, FolderName

    # Output the results to the console
    #Write-Host "Receiver [$Identity] has accepted copies of the shared calendar from the following recipients in the last 180 days:"
    #$csvObject | Where-Object { [DateTime]$_.Timestamp -gt (Get-Date).AddDays(-180) } | Format-Table -a Timestamp, SharedCalendarOwner, FolderName

    Write-Host "Receiver [$Identity] has accepted copies of the shared calendar from the following recipients in the last 180 days:"
    if ($csvObject.Timestamp.Substring(0, 2) -gt 12) {
        Write-Verbose "Trying European DateTime Format - dd/MM/yyyy HH:mm:ss"
        $culture = [System.Globalization.CultureInfo]::CreateSpecificCulture("en-GB")
    } else {
        $culture = [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US")
    }
    $csvObject | Where-Object { [DateTime]::Parse($_.Timestamp, $culture) -gt (Get-Date).AddDays(-180) }| Format-Table -a Timestamp, SharedCalendarOwner, FolderName
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
        Write-Error "An error occurred processing InternetCalendar logs."
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        Write-Host -ForegroundColor Green "==========================================="
        Write-Host -ForegroundColor Green "It is safe to ignore the big error about, it is just saying that there are no InternetCalendar logs."
        Write-Host -ForegroundColor Green "No InternetCalendar Logs found for [$Identity]."
        Write-Host -ForegroundColor Green "User [$Identity] is not receiving any Published Calendars."
        Write-Host -ForegroundColor Green "==========================================="
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
    $OwnerCalendarStats = Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar
    $OwnerCalendarName = ($OwnerCalendarStats | Where-Object FolderType -EQ "Calendar").Name

    $OwnerCalendarStats | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxFolderPermission "${Owner}:\$OwnerCalendarName" | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    $OwnerCalendarPerms = Get-MailboxFolderPermission "${Owner}:\$OwnerCalendarName" 
    $OwnerCalendarPerms | Format-Table -a User, AccessRights, SharingPermissionFlags

    # Warn if the size is greater than 1 GB
    if ([int]$OwnerCalendarStats[0].FolderSize.Split("(")[1].Replace(" bytes)","") -gt 1000000000) {
        Write-Host -ForegroundColor Yellow "Warning: Owner Calendar size is greater than 1 GB. This can impact calendar performance."
        Write-Host -ForegroundColor Yellow "`t Consider archiving old calendar items or reducing the size of attachments in calendar items."
    }

    # Warn if the Calendar count is greater than 100,000 items
   if ([int]$OwnerCalendarStats[0].ItemsInFolder -gt 100000) {
        Write-Host -ForegroundColor Yellow "Warning: Owner Calendar has more than 100,000 items. This can impact calendar performance."
        Write-Host -ForegroundColor Yellow "`t Consider archiving old calendar items."
    }

    Write-Host -ForegroundColor DarkYellow "Owner Root Mailbox Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxPermission $Owner | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    Get-MailboxPermission $Owner | Format-Table -a User, AccessRights, SharingPermissionFlags

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

    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxCalendarFolder -Identity "${Owner}:\$OwnerCalendarName"'"
    $CalFolderProps = Get-MailboxCalendarFolder -Identity "${Owner}:\$OwnerCalendarName" 
    Write-Host -ForegroundColor DarkYellow "`t ExtendedFolderFlags: $($CalFolderProps.ExtendedFolderFlags)"
    if ($CalFolderProps.ExtendedFolderFlags -like "*SharedOut*") {
        Write-Host -ForegroundColor Green "`t Calendar is Shared Out using Modern Sharing."
    } else {
        Write-Host -ForegroundColor Red "`t Calendar is not Shared Out using Modern Sharing."
    }

    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-CalendarActiveSharingInformation -Identity "${Owner}:\$OwnerCalendarName"'"    
    $OwnerActiveSharingInfo = Get-CalendarActiveSharingInformation -Identity "${Owner}:\$OwnerCalendarName"
    if ($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees.count -gt 0) {
        Write-Host -ForegroundColor Green "`t Calendar has [$($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees.count)] Active Receivers."
        $receivers = $OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees | ForEach-Object {
            [PSCustomObject]@{
                EmailAddress            = $_.EmailAddress
                SharingPermissionFlag   = ($_.SharingPermissionFlags -join ",")
                LastSyncTime            = $_.LastSyncTime
            }
        }
        Write-Host -ForegroundColor DarkYellow "Look for the Receiver [$Receiver] in the list of Active Receivers."

        $receivers | Format-Table -AutoSize EmailAddress, SharingPermissionFlag, LastSyncTime
    } else {
        Write-Host -ForegroundColor Yellow "`t Calendar has no Active Receivers according to Get-CalendarActiveSharingInformation."
    }
    Write-Host -ForegroundColor DarkYellow "`n`n`n------------------------------------------------"
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

    $OwnerCalendarName = $($OwnerMB.DisplayName)
    Write-Host -ForegroundColor Cyan "Receiver Calendar Folders (look for a copy of [$OwnerCalendarName] Calendar):"
    Write-Host -ForegroundColor Cyan "Running: 'Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar'"
    $CalStats = Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar
    $CalStats | Format-Table -a FolderPath, ItemsInFolder, FolderAndSubfolderSize
    $ReceiverCalendarName = ($CalStats | Where-Object FolderType -EQ "Calendar").Name

    $ReceiverRegionalConfig = Get-MailboxRegionalConfiguration -Identity $Receiver
    $script:ReceiverLocal =  $ReceiverRegionalConfig.Language
    $script:ReceiverDateFormat = $ReceiverRegionalConfig.DateFormat
    Write-Host -ForegroundColor Cyan "Receiver Regional Configuration:"
    Write-Host -ForegroundColor Cyan "`t Language: $($script:ReceiverLocal)"
    Write-Host -ForegroundColor Cyan "`t DateFormat: $($script:ReceiverDateFormat)"


    # Warning if there are multiple copies of the Owner Calendar in the Receiver Mailbox.
    if (($CalStats | Where-Object Name -Like "$OwnerCalendarName*").count -gt 1) {
        Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
    }

    # Warning if the Receivers copy of the Calendar name is the default "Calendar".
    if (($CalStats.name -like "Cal*").count -gt 1) { 
        Write-Host -ForegroundColor Yellow "Warning: Receiver might have multiple Calendars named 'Calendar'."
        Write-Host -ForegroundColor Yellow "Warning: This can cause confusion with which calendar is being referenced."
    }

    # Warning if the Calendar name has a (1) or similar at the end.
    if ($OwnerCalendarName -match "\(\d+\)$") {
        Write-Host -ForegroundColor Yellow "Warning: Receiver Calendar name has a (1) or similar at the end. This indicates the Receiver has / had multiple Calendars from the Owner. Best practice is to remove all of these calendars and share again."
    }

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
    if (!$ModernSharingOnly){
        ProcessInternetCalendarLogs -Identity $Receiver
    }

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

            if (!$ModernSharingOnly) {
                Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
                Write-Host "Old Model Calendar Sharing Entries:"
                Write-Host "Consider upgrading these to the new model."
                $ReceiverCalEntries | Where-Object SharingModelType -Like Old | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry
            }

            # need to check if Get-CalendarValidationResult in the PS Workspace
            if ((Get-Command -Name Get-CalendarValidationResult -ErrorAction SilentlyContinue) -and
                $null -ne $ReceiverCalEntries) {
                $ewsId_del= $ReceiverCalEntries[0].LocalFolderId
                Write-Host "Trying to run cmdlet: Get-CalendarValidationResult -Version V2 -Identity $Receiver -SourceCalendarId $ewsId_del -TargetUserId $Owner -IncludeAnalysis 1 -OnlyReportErrors 1 | FT -a GlobalObjectId, EventValidationResult  "
                try {
                    $ValidationResults = Get-CalendarValidationResult -Version V2 -Identity $Receiver -SourceCalendarId $ewsId_del -TargetUserId $Owner -IncludeAnalysis 1 -OnlyReportErrors 1 2>$null
                    $ValidationResults | Format-List UserPrimarySMTPAddress, Subject, GlobalObjectId, EventValidationResult, EventComparisonResult
                } catch {
                    Write-Error "Failed to run Get-CalendarValidationResult: $_"
                }
            }
        }

        #Output key Modern Sharing information
        if (($script:PIIAccess) -and (-not ([string]::IsNullOrEmpty($script:OwnerMB)))) {
            Write-Host "Checking for Owner copy Calendar in Receiver Calendar:"
            Write-Host "Running cmdlet:"
            Write-Host -NoNewline -ForegroundColor Yellow "Get-MailboxCalendarFolder -Identity ${Receiver}:\$ReceiverCalendarName\$($script:OwnerMB.DisplayName)"
            try {
                $MBCalFolder = Get-MailboxCalendarFolder -Identity "${Receiver}:\$ReceiverCalendarName\$($script:OwnerMB.DisplayName)"
                $MBCalFolder | Format-List Identity, CreationTime, ExtendedFolderFlags, CalendarSharingFolderFlags, CalendarSharingOwnerSmtpAddress, CalendarSharingPermissionLevel, SharingLevelOfDetails, SharingPermissionFlags, LastAttemptedSyncTime, LastSuccessfulSyncTime, SharedCalendarSyncStartDate

                if ($MBCalFolder.LastAttemptedSyncTime -eq $MBCalFolder.LastSuccessfulSyncTime) {
                    Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar appears to be syncing properly (LastAttemptedSyncTime = LastSuccessfulSyncTime)."
                } else {
                    Write-Host -ForegroundColor Red "Warning: The Receiver's copy of the Owner's Calendar does not appear to be syncing properly (LastAttemptedSyncTime != LastSuccessfulSyncTime)."
                }

                If ($null -ne $MBCalFolder.SharedCalendarSyncStartDate) {
                    Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar should have data back to: $(($MBCalFolder.SharedCalendarSyncStartDate).split(" ")[0])."
                    Write-Host "`t This can be changed with the Set-MailboxCalendarFolder cmdlet."
                } else {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar does not have a SharedCalendarSyncStartDate."
                }

            } catch {
                Write-Error "Failed to get the Owner's Calendar from the Receiver's Mailbox.  This is fine if not using Modern Sharing."
            }

            # Collect Sharing related logs for further analysis if needed
            $SharingLog =  Export-MailboxDiagnosticLogs $Receiver -ComponentName Sharing
            $SSA = Export-MailboxDiagnosticLogs $Receiver -ComponentName SharingSyncAssistant
            $SharingValidator = Export-MailboxDiagnosticLogs $Receiver -ComponentName CalendarSharingInconsistencyValidator
            $SharingRepair = Export-MailboxDiagnosticLogs $Receiver -ComponentName CalendarSharingInconsistencyRepair


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
