# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Export to Excel
function Export-CalLogExcel {
    Write-Host -ForegroundColor Cyan "Exporting Enhanced CalLogs to Excel Tab [$ShortId]..."
    $ExcelParamsArray = GetExcelParams -path $FileName -tabName $ShortId

    $excel = $GCDOResults | Export-Excel @ExcelParamsArray -PassThru

    FormatHeader ($excel)

    Export-Excel -ExcelPackage $excel -WorksheetName $ShortId -MoveToStart

    # Export Raw Logs for Developer Analysis
    Write-Host -ForegroundColor Cyan "Exporting Raw CalLogs to Excel Tab [$($ShortId + "_Raw")]..."
    $script:GCDO | Export-Excel -Path  $FileName -WorksheetName $($ShortId + "_Raw") -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd
    LogScriptInfo
}

function LogScriptInfo {
    # Only need to run once per script execution.
    if ($null -eq $script:CollectedCmdLine) {
        $RunInfo = @()
        $RunInfo += [PSCustomObject]@{
            Key   = "Script Name"
            Value = $($script:command.MyCommand.Name)
        }
        $RunInfo += [PSCustomObject]@{
            Key   ="RunTime"
            Value = Get-Date
        }
        $RunInfo += [PSCustomObject]@{
            Key   = "Command Line"
            Value = $($script:command.Line)
        }
        $RunInfo += [PSCustomObject]@{
            Key   = "Script Version"
            Value =  $script:BuildVersion
        }
        $RunInfo += [PSCustomObject]@{
            Key   = "User"
            Value =  whoami.exe
        }
        $RunInfo += [PSCustomObject]@{
            Key   = "PowerShell Version"
            Value = $PSVersionTable.PSVersion
        }
        $RunInfo += [PSCustomObject]@{
            Key   = "OS Version"
            Value = $(Get-CimInstance -ClassName Win32_OperatingSystem).Version
        }
        $RunInfo += [PSCustomObject]@{
            Key   = "More Info"
            Value = "https://learn.microsoft.com/en-us/exchange/troubleshoot/calendars/analyze-calendar-diagnostic-logs"
        }

        $RunInfo | Export-Excel -Path $FileName -WorksheetName "Script Info" -MoveToEnd
        $script:CollectedCmdLine = $true
    }
    # If someone runs the script the script again logs will update, but ScriptInfo does not update. Need to add new table for each run.
}

function Export-TimelineExcel {
    Write-Host -ForegroundColor Cyan "Exporting Timeline to Excel..."
    $script:TimeLineOutput | Export-Excel -Path $FileName -WorksheetName $($ShortId + "_TimeLine") -Title "Timeline for $Identity" -AutoSize -FreezeTopRow -BoldTopRow
}

function GetExcelParams($path, $tabName) {
    if ($script:IsOrganizer) {
        $TableStyle = "Light10" # Orange for Organizer
        $TitleExtra = ", Organizer"
    } elseif ($script:IsRoomMB) {
        Write-Host -ForegroundColor green "Room Mailbox Detected"
        $TableStyle = "Light11" # Green for Room Mailbox
        $TitleExtra = ", Resource"
    } else {
        $TableStyle = "Light12" # Light Blue for normal
        # Dark Blue for Delegates (once we can determine this)
    }

    if ($script:CalLogsDisabled) {
        $TitleExtra += ", WARNING: CalLogs are Turned Off for $Identity! This will be a incomplete story"
    }

    return @{
        Path                    = $path
        FreezeTopRow            = $true
        #  BoldTopRow              = $true
        Verbose                 = $false
        TableStyle              = $TableStyle
        WorksheetName           = $tabName
        TableName               = $tabName
        FreezeTopRowFirstColumn = $true
        AutoFilter              = $true
        AutoNameRange           = $true
        Append                  = $true
        Title                   = "Enhanced Calendar Logs for $Identity" + $TitleExtra + " for MeetingID [$($script:GCDO[0].CleanGlobalObjectId)]."
        TitleSize               = 14
        ConditionalText         = $ConditionalFormatting
    }
}

# Need better way of tagging cells than the Range.  Every time one is updated, you need to update all the ones after it.
$ConditionalFormatting = $(
    # Client, ShortClientInfoString and LogClientInfoString
    New-ConditionalText "Outlook" -ConditionalTextColor Green -BackgroundColor $null
    New-ConditionalText "OWA" -ConditionalTextColor DarkGreen -BackgroundColor $null
    New-ConditionalText "Teams" -ConditionalTextColor DarkGreen -BackgroundColor $null
    New-ConditionalText "Transport" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText "Repair" -ConditionalTextColor DarkRed -BackgroundColor LightPink
    New-ConditionalText "Other ?BA" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText "TimeService" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText "Other REST" -ConditionalTextColor DarkRed -BackgroundColor $null
    New-ConditionalText "Unknown" -ConditionalTextColor DarkRed -BackgroundColor $null
    New-ConditionalText "ResourceBookingAssistant" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText "Calendar Replication" -ConditionalTextColor Blue -BackgroundColor $null

    # LogRowType
    New-ConditionalText -Range "C:C" -ConditionalType ContainsText -Text "Interesting" -ConditionalTextColor Green -BackgroundColor $null
    New-ConditionalText -Range "C:C" -ConditionalType ContainsText -Text "SeriesException" -ConditionalTextColor Green -BackgroundColor $null
    New-ConditionalText -Range "C:C" -ConditionalType ContainsText -Text "DeletedSeriesException" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range "C:C" -ConditionalType ContainsText -Text "MeetingMessageChange" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range "C:C" -ConditionalType ContainsText -Text "SyncOrReplication" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText -Range "C:C" -ConditionalType ContainsText -Text "OtherAssistant" -ConditionalTextColor Orange -BackgroundColor $null

    # TriggerAction
    New-ConditionalText -Range "G:G" -ConditionalType ContainsText -Text "Create" -ConditionalTextColor Green -BackgroundColor $null
    New-ConditionalText -Range "G:G" -ConditionalType ContainsText -Text "Delete" -ConditionalTextColor Red -BackgroundColor $null

    # ItemClass
    New-ConditionalText -Range "H:H" -ConditionalType ContainsText -Text "IPM.Appointment" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText -Range "H:H" -ConditionalType ContainsText -Text "Cancellation" -ConditionalTextColor Black -BackgroundColor Orange
    New-ConditionalText -Range "H:H" -ConditionalType ContainsText -Text ".Request" -ConditionalTextColor DarkGreen -BackgroundColor $null
    New-ConditionalText -Range "H:H" -ConditionalType ContainsText -Text ".Resp." -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range "H:H" -ConditionalType ContainsText -Text "IPM.OLE.CLASS" -ConditionalTextColor Plum -BackgroundColor $null

    # FreeBusyStatus
    New-ConditionalText -Range "L3:L9999" -ConditionalType ContainsText -Text "Free" -ConditionalTextColor Red -BackgroundColor $null
    New-ConditionalText -Range "L3:L9999" -ConditionalType ContainsText -Text "Tentative" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range "L3:L9999" -ConditionalType ContainsText -Text "Busy" -ConditionalTextColor Green -BackgroundColor $null

    # Shared Calendar information
    New-ConditionalText -Range "Q3:Q9999" -ConditionalType Equal -Text "Not Shared" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText -Range "Q3:Q9999" -ConditionalType Equal -Text "TRUE" -ConditionalTextColor Blue -BackgroundColor Orange

    # MeetingRequestType
    New-ConditionalText -Range "T:T" -ConditionalType ContainsText -Text "Outdated" -ConditionalTextColor DarkRed -BackgroundColor LightPink

    # CalendarItemType
    New-ConditionalText -Range "AA3:AA9999" -ConditionalType ContainsText -Text "RecurringMaster" -ConditionalTextColor $null -BackgroundColor Plum

    # AppointmentAuxiliaryFlags
    New-ConditionalText -Range "AD3:AD9999" -ConditionalType ContainsText -Text "Copied" -ConditionalTextColor DarkRed -BackgroundColor LightPink
    New-ConditionalText -Range "AC3:AC9999" -ConditionalType ContainsText -Text "ForwardedAppointment" -ConditionalTextColor DarkRed -BackgroundColor $null

    # ResponseType
    New-ConditionalText -Range "AG3:AG9999" -ConditionalType ContainsText -Text "Organizer" -ConditionalTextColor Orange -BackgroundColor $null
)

function FormatHeader {
    param(
        [object] $excel
    )
    $sheet = $excel.Workbook.Worksheets[$ShortId]
    $HeaderRow = 2
    $n = 0

    # Static List of Columns for now...
    $sheet.Column(++$n) | Set-ExcelRange -Width 6 -HorizontalAlignment Center         # LogRow
    Set-CellComment -Text "This is the Enhanced Calendar Logs for [$Identity] for MeetingID `n [$($script:GCDO[0].CleanGlobalObjectId)]." -Row $HeaderRow -ColumnNumber $n -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -NumberFormat "m/d/yyyy h:mm:ss" -HorizontalAlignment Center #LogTimestamp
    Set-CellComment -Text "LogTimestamp: Time when the change was recorded in the CalLogs. This and all Times are in UTC." -Row $HeaderRow -ColumnNumber $n -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # LogRowType
    Set-CellComment -Text "LogRowType: Interesting logs are what to focus on, filter all the others out to start with." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # SubjectProperty
    Set-CellComment -Text "SubjectProperty: The Subject of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # Client
    Set-CellComment -Text "Client (ShortClientInfoString): The 'friendly' Client name of the client that made the change." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 5 -HorizontalAlignment Left          # LogClientInfoString
    Set-CellComment -Text "LogClientInfoString: Full Client Info String of client that made the change." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 12 -HorizontalAlignment Center       # TriggerAction
    Set-CellComment -Text "TriggerAction (CalendarLogTriggerAction): The type of action that caused the change." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 18 -HorizontalAlignment Left         # ItemClass
    Set-CellComment -Text "ItemClass: The Class of the Calendar Item" -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center        # Seq:Exp:ItemVersion
    Set-CellComment -Text "Seq:Exp:ItemVersion (AppointmentLastSequenceNumber:AppointmentSequenceNumber:ItemVersion): The Sequence Version, the Exception Version, and the Item Version.  Each type of item has its own count." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # Organizer
    Set-CellComment -Text "Organizer (From.FriendlyDisplayName): The Organizer of the Calendar Item." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # From
    Set-CellComment -Text "From: The SMTP address of the Organizer of the Calendar Item." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 12 -HorizontalAlignment Center         # FreeBusyStatus
    Set-CellComment -Text "FreeBusy (FreeBusyStatus): The FreeBusy Status of the Calendar Item." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # ResponsibleUser
    Set-CellComment -Text "ResponsibleUser(ResponsibleUserName): The Responsible User of the change." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # Sender
    Set-CellComment -Text "Sender (SenderEmailAddress): The Sender of the change." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 16 -HorizontalAlignment Left         # LogFolder
    Set-CellComment -Text "LogFolder (ParentDisplayName): The Log Folder that the CalLog was in." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 16 -HorizontalAlignment Left         # OriginalLogFolder
    Set-CellComment -Text "OriginalLogFolder (OriginalParentDisplayName): The Original Log Folder that the item was in / delivered to." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 15 -HorizontalAlignment Left         # SharedFolderName
    Set-CellComment -Text "SharedFolderName: Was this from a Modern Sharing, and if so what Folder." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Left         # ReceivedBy
    Set-CellComment -Text "ReceivedBy: The Receiver of the Calendar Item. Should always be the owner of the Mailbox." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Left         # ReceivedRepresenting
    Set-CellComment -Text "ReceivedRepresenting: Who the item was Received for, of then the Delegate." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # MeetingRequestType
    Set-CellComment -Text "MeetingRequestType: The Meeting Request Type of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 23 -NumberFormat "m/d/yyyy h:mm:ss" -HorizontalAlignment Center         # StartTime
    Set-CellComment -Text "StartTime: The Start Time of the Meeting. This and all Times are in UTC." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 23 -NumberFormat "m/d/yyyy h:mm:ss" -HorizontalAlignment Center         # EndTime
    Set-CellComment -Text "EndTime: The End Time of the Meeting. This and all Times are in UTC." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 17 -NumberFormat "m/d/yyyy h:mm:ss"  -HorizontalAlignment Left         # OriginalStartDate
    Set-CellComment -Text "OriginalStartDate: The Original Start Date of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Left         # TimeZone
    Set-CellComment -Text "TimeZone: The Time Zone of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Left         # Location
    Set-CellComment -Text "Location: The Location of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # CalendarItemType
    Set-CellComment -Text "CalendarItemType: The Calendar Item Type of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # IsException
    Set-CellComment -Text "IsException: Is this an Exception?" -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left         # RecurrencePattern
    Set-CellComment -Text "RecurrencePattern: The Recurrence Pattern of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 30 -HorizontalAlignment Center       # AppointmentAuxiliaryFlags
    Set-CellComment -Text "AppointmentAuxiliaryFlags: The Appointment Auxiliary Flags of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 30 -HorizontalAlignment Left         # DisplayAttendeesAll
    Set-CellComment -Text "DisplayAttendeesAll: List of the Attendees of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center        # AttendeeCount
    Set-CellComment -Text "AttendeeCount: The Attendee Count." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Left          # AppointmentState
    Set-CellComment -Text "AppointmentState: The Appointment State of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # ResponseType
    Set-CellComment -Text "ResponseType: The Response Type of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 20 -HorizontalAlignment Center         # ClientIntent
    Set-CellComment -Text "ClientIntent: The Client Intent of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # AppointmentRecurring
    Set-CellComment -Text "AppointmentRecurring: Is this a Recurring Meeting?" -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # HasAttachment
    Set-CellComment -Text "HasAttachment: Does this Meeting have an Attachment?" -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # IsCancelled
    Set-CellComment -Text "IsCancelled: Is this Meeting Cancelled?" -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # IsAllDayEvent
    Set-CellComment -Text "IsAllDayEvent: Is this an All Day Event?" -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 10 -HorizontalAlignment Center         # IsSeriesCancelled
    Set-CellComment -Text "IsSeriesCancelled: Is this a Series Cancelled Meeting?" -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 30 -HorizontalAlignment Left           # SendMeetingMessagesDiagnostics
    Set-CellComment -Text "SendMeetingMessagesDiagnostics: Compound Property to describe why meeting was or was not sent to everyone." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 50 -HorizontalAlignment Left           # AttendeeCollection
    Set-CellComment -Text "AttendeeCollection: The Attendee Collection of the Meeting, use -TrackingLogs to get values." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet
    $sheet.Column(++$n) | Set-ExcelRange -Width 40 -HorizontalAlignment Center          # CalendarLogRequestId
    Set-CellComment -Text "CalendarLogRequestId: The Calendar Log Request ID of the Meeting." -Row $HeaderRow -ColumnNumber $n  -Worksheet $sheet

    # Update header rows after all the others have been set.
    # Title Row
    $sheet.Row(1) | Set-ExcelRange -HorizontalAlignment Left
    Set-CellComment -Text "For more information see: Https:\\aka.ms\AnalyzeCalLogs"  -Row 1 -ColumnNumber 1  -Worksheet $sheet

    # Set the Header row to be bold and left aligned
    $sheet.Row($HeaderRow) | Set-ExcelRange -Bold -HorizontalAlignment Left
}
