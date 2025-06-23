# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Export to Excel
function Export-CalLogExcel {
    Write-Host -ForegroundColor Cyan "Exporting Enhanced CalLogs to Excel Tab [$ShortId]..."
    $script:lastRow = 1000 # Default last row, will be updated later
    $script:firstRow = 3 # Row 1 is the Title, Row 2 is the Header
    $script:lastColumn = "AL" # Column AL is the last column in the Excel sheet

    $ExcelParamsArray = GetExcelParams -path $FileName -tabName $ShortId

    $excel = $GCDOResults | Export-Excel @ExcelParamsArray -PassThru

    FormatHeader ($excel)
    CheckRows ($excel)
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

    $script:lastRow = $script:GCDO.Count + $firstRow - 1 # Last row is the number of items in the GCDO array + 2 for the header and title rows.
    Write-Host -ForegroundColor Gray "Last Row is $lastRow, First Row is $firstRow, Last Column is $lastColumn"

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

$ColumnMap = @{
    LogTimestamp            = "A"
    LogRowType              = "B"
    SubjectProperty         = "C"
    Client                  = "D"
    LogClientInfoString     = "E"
    TriggerAction           = "F"
    ItemClass               = "G"
    SeqExpItemVersion       = "H"
    Organizer               = "I"
    From                    = "J"
    FreeBusyStatus          = "K"
    ResponsibleUser         = "L"
    Sender                  = "M"
    LogFolder               = "N"
    OriginalLogFolder       = "O"
    SharedFolderName        = "P"
    ReceivedRepresenting    = "Q"
    MeetingRequestType      = "R"
    StartTime               = "S"
    EndTime                 = "T"
    OriginalStartDate       = "U"
    Location                = "V"
    CalendarItemType        = "W"
    RecurrencePattern       = "X"
    AppointmentAuxiliaryFlags = "Y"
    DisplayAttendeesAll     = "Z"
    AttendeeCount           = "AA"
    AppointmentState        = "AB"
    ResponseType            = "AC"
    ClientIntent            = "AD"
    AppointmentRecurring    = "AE"
    HasAttachment           = "AF"
    IsCancelled             = "AG"
    IsAllDayEvent           = "AH"
    IsSeriesCancelled       = "AI"
    SendMeetingMessagesDiagnostics = "AJ"
    AttendeeCollection      = "AK"
    CalendarLogRequestId    = "AL"
}

function GetExcelColumnNumber {
    param([string]$ColumnLetter)
    $number = 0
    $letters = $ColumnLetter.ToUpper().ToCharArray()
    foreach ($char in $letters) {
        $number = $number * 26 + ([int][char]$char - [int][char]'A' + 1)
    }
    return $number
}

function Get-ColumnRange {
    param(
        [string]$PropertyName,
        [int]$StartRow = 3,
        [int]$EndRow = $script:lastRow
    )

    if ($EndRow -eq 0) {
        $EndRow = 2000
    }

    $col = $ColumnMap[$PropertyName]

    # if ($null -eq $col) { throw "Unknown property: $PropertyName" }
    if ($StartRow -and $EndRow) {
      #  Write-Host -ForegroundColor DarkGray "Getting column range for $PropertyName : $col, StartRow: $StartRow, EndRow: $EndRow"
        return $col + $StartRow + ":" + $col + $EndRow
    } else {
        return $col + ":" + $col
    }
}

$ConditionalFormatting = @(
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

    Write-Host -ForegroundColor DarkGreen "Adding Conditional Formatting for :: ConditionalFormatting"
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "Interesting" -ConditionalTextColor Green -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "SeriesException" -ConditionalTextColor Green -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "DeletedSeriesException" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "MeetingMessageChange" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "SyncOrReplication" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "OtherAssistant" -ConditionalTextColor Orange -BackgroundColor $null

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'TriggerAction') -ConditionalType ContainsText -Text "Create" -ConditionalTextColor Green -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'TriggerAction') -ConditionalType ContainsText -Text "Delete" -ConditionalTextColor Red -BackgroundColor $null

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text "IPM.Appointment" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text "Cancellation" -ConditionalTextColor Black -BackgroundColor Orange
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text ".Request" -ConditionalTextColor DarkGreen -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text ".Resp." -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text "IPM.OLE.CLASS" -ConditionalTextColor Plum -BackgroundColor $null

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'FreeBusyStatus' -StartRow 3 -EndRow 1000) -ConditionalType ContainsText -Text "Free" -ConditionalTextColor Red -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'FreeBusyStatus' -StartRow 3 -EndRow 1000) -ConditionalType ContainsText -Text "Tentative" -ConditionalTextColor Orange -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'FreeBusyStatus' -StartRow 3 -EndRow 1000) -ConditionalType ContainsText -Text "Busy" -ConditionalTextColor Green -BackgroundColor $null

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'SharedFolderName' -StartRow 3 -EndRow 1000) -ConditionalType Equal -Text "Not Shared" -ConditionalTextColor Blue -BackgroundColor $null
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'SharedFolderName' -StartRow 3 -EndRow 1000) -ConditionalType NotContainsText -Text "Not Shared" -ConditionalTextColor Black -BackgroundColor Tan

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'MeetingRequestType') -ConditionalType ContainsText -Text "Outdated" -ConditionalTextColor DarkRed -BackgroundColor LightPink

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'CalendarItemType') -ConditionalType ContainsText -Text "RecurringMaster" -ConditionalTextColor $null -BackgroundColor Plum

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'AppointmentAuxiliaryFlags') -ConditionalType ContainsText -Text "Copied" -ConditionalTextColor DarkRed -BackgroundColor LightPink
    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'AppointmentAuxiliaryFlags') -ConditionalType ContainsText -Text "ForwardedAppointment" -ConditionalTextColor DarkRed -BackgroundColor $null

    New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ResponseType') -ConditionalType ContainsText -Text "Organizer" -ConditionalTextColor Orange -BackgroundColor $null
)

function CheckRows {
    param(
        [object] $excel
    )
    $sheet = $excel.Workbook.Worksheets[$ShortId]

    # Highlight the Resp in LightGoldenRodYellow
    CheckColumnForText -sheet $sheet -columnNumber $(GetExcelColumnNumber($ColumnMap.ItemClass)) -textToFind "Resp" -cellcolor "LightGoldenRodYellow" -fontColor "Black"
    
    # Highlight the RUM in Red
    CheckColumnForText -sheet $sheet -columnNumber $(GetExcelColumnNumber($ColumnMap.AppointmentAuxiliaryFlags)) -textToFind "RepairUpdateMessage" -cellcolor "White" -fontColor "DarkRed"

    #Highlight the Cancellation in Orange
    CheckColumnsForValues -sheet $sheet -columnNumber1  $(GetExcelColumnNumber($ColumnMap.ItemClass)) -value1 "Cancellation" -columnNumber2  $(GetExcelColumnNumber($ColumnMap.TriggerAction)) -value2 "Create" -cellcolor "Khaki" -fontColor "Black"

    # Highlight the Create from Transport in light blue
    CheckColumnsForValues -sheet $sheet -columnNumber1  $(GetExcelColumnNumber($ColumnMap.LogClientInfoString)) -value1 "Transport" -columnNumber2  $(GetExcelColumnNumber($ColumnMap.TriggerAction)) -value2 "Create" -cellcolor "LightBlue" -fontColor "Black"

    $excel.Save()
}

# check if a column contains a specific text and highlight the row
# This function highlights a row in the Excel sheet based on the row number and specified colors.
# Parameters:
#   - $sheet: The Excel worksheet object.
function CheckColumnForText {
    param (
        [object] $sheet,
        [int] $columnNumber,
        [string] $textToFind,
        [string] $cellcolor = "Yellow",
        [string] $fontColor = "DarkRed"
    )
    
    Write-Host -ForegroundColor Green "Checking column $columnNumber for text '$textToFind'..."
    for ($row = 3; $row -le $sheet.Dimension.End.Row; $row++) {
        $cellValue = $sheet.Cells[$row, $columnNumber].Text
        # Write-Host -ForegroundColor DarkBlue "Checking row $row, column $columnNumber : $cellValue"        

        if ($cellValue -like "*$textToFind*") {
        #   Write-Host -ForegroundColor Yellow "Found '$textToFind' in row $row, column $columnNumber"
            HighliteRow -sheet $sheet -rowNumber $row -cellcolor $cellcolor -fontColor $fontColor
        }
    }
    # Write-Host -ForegroundColor Cyan "Highliting rows with '$textToFind' completed."

}

# Checks if two columns in the same row match specified values and highlights the row if both match.
function CheckColumnsForValues {
    param (
        [object] $sheet,
        [int] $columnNumber1,
        [string] $value1,
        [int] $columnNumber2,
        [string] $value2,
        [string] $cellcolor = "LightPink",
        [string] $fontColor = "DarkRed"
    )

    Write-Host -ForegroundColor Green "Checking for rows where column $columnNumber1 = '$value1' AND column $columnNumber2 = '$value2'..."
    for ($row = 3; $row -le $sheet.Dimension.End.Row; $row++) {
        $cellValue1 = $sheet.Cells[$row, $columnNumber1].Text
        $cellValue2 = $sheet.Cells[$row, $columnNumber2].Text
        # Write-Host -ForegroundColor DarkBlue "Row '$row': Col$columnNumber1='$cellValue1', Col$columnNumber2='$cellValue2'"

        if ($cellValue1 -like "*$value1*" -and $cellValue2 -like "*$value2*") {
            Write-Host -ForegroundColor Yellow "Found match in row '$row': '$value1' and '$value2'"
            HighliteRow -sheet $sheet -rowNumber $row -cellcolor $cellcolor -fontColor $fontColor
        }
    }
    # Write-Host -ForegroundColor Cyan "Highlighting rows with both values completed."
}

function HighliteRow {
    param(
        [object] $sheet,
        [string] $rowNumber,
        [string] $cellcolor = "Thistle",
        [string] $fontColor = "DarkRed"
    )
    # Highlight the entire row with the specified color
    # 'A' to our last row, 'AM'.
    $rowName = "A" + $row + ":" + $lastColumn + $row

    Write-Host -ForegroundColor Green "Highliting row $rowName with cell color [$cellcolor] and font color [$fontColor]"
    $sheet.Cells[$rowName].Style.Fill.PatternType = 'Solid'
    $sheet.Cells[$rowName].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::$cellcolor)
    $sheet.Cells[$rowName].Style.Font.Color.SetColor([System.Drawing.Color]::$fontColor)
}

function FormatHeader {
    param(
        [object] $excel
    )
    $sheet = $excel.Workbook.Worksheets[$ShortId]
    $HeaderRow = 2

    # Define header metadata: property name, width, alignment, number format, comment
    $headerMeta = @(
        @{ Name = "LogTimestamp"; Width = 20; Align = "Center"; NumberFormat = "m/d/yyyy h:mm:ss"; Comment = "LogTimestamp: Time when the change was recorded in the CalLogs. This and all Times are in UTC." }
        @{ Name = "LogRowType"; Width = 20; Align = "Left"; Comment = "LogRowType: Interesting logs are what to focus on, filter all the others out to start with." }
        @{ Name = "SubjectProperty"; Width = 20; Align = "Left"; Comment = "SubjectProperty: The Subject of the Meeting." }
        @{ Name = "Client"; Width = 20; Align = "Left"; Comment = "Client (ShortClientInfoString): The 'friendly' Client name of the client that made the change." }
        @{ Name = "LogClientInfoString"; Width = 5; Align = "Left"; Comment = "LogClientInfoString: Full Client Info String of client that made the change." }
        @{ Name = "TriggerAction"; Width = 12; Align = "Center"; Comment = "TriggerAction (CalendarLogTriggerAction): The type of action that caused the change." }
        @{ Name = "ItemClass"; Width = 18; Align = "Left"; Comment = "ItemClass: The Class of the Calendar Item" }
        @{ Name = "SeqExpItemVersion"; Width = 10; Align = "Center"; Comment = "Seq:Exp:ItemVersion (AppointmentLastSequenceNumber:AppointmentSequenceNumber:ItemVersion): The Sequence Version, the Exception Version, and the Item Version.  Each type of item has its own count." }
        @{ Name = "Organizer"; Width = 20; Align = "Left"; Comment = "Organizer (From.FriendlyDisplayName): The Organizer of the Calendar Item." }
        @{ Name = "From"; Width = 20; Align = "Left"; Comment = "From: The SMTP address of the Organizer of the Calendar Item." }
        @{ Name = "FreeBusyStatus"; Width = 12; Align = "Center"; Comment = "FreeBusy (FreeBusyStatus): The FreeBusy Status of the Calendar Item." }
        @{ Name = "ResponsibleUser"; Width = 20; Align = "Left"; Comment = "ResponsibleUser(ResponsibleUserName): The Responsible User of the change." }
        @{ Name = "Sender"; Width = 20; Align = "Left"; Comment = "Sender (SenderEmailAddress): The Sender of the change." }
        @{ Name = "LogFolder"; Width = 16; Align = "Left"; Comment = "LogFolder (ParentDisplayName): The Log Folder that the CalLog was in." }
        @{ Name = "OriginalLogFolder"; Width = 16; Align = "Left"; Comment = "OriginalLogFolder (OriginalParentDisplayName): The Original Log Folder that the item was in / delivered to." }
        @{ Name = "SharedFolderName"; Width = 15; Align = "Left"; Comment = "SharedFolderName: Was this from a Modern Sharing, and if so what Folder." }
        @{ Name = "ReceivedRepresenting"; Width = 10; Align = "Left"; Comment = "ReceivedRepresenting: Who the item was Received for, of then the Delegate." }
        @{ Name = "MeetingRequestType"; Width = 10; Align = "Center"; Comment = "MeetingRequestType: The Meeting Request Type of the Meeting." }
        @{ Name = "StartTime"; Width = 23; Align = "Center"; NumberFormat = "m/d/yyyy h:mm:ss"; Comment = "StartTime: The Start Time of the Meeting. This and all Times are in UTC." }
        @{ Name = "EndTime"; Width = 23; Align = "Center"; NumberFormat = "m/d/yyyy h:mm:ss"; Comment = "EndTime: The End Time of the Meeting. This and all Times are in UTC." }
        @{ Name = "OriginalStartDate"; Width = 15; Align = "Left"; NumberFormat = "m/d/yy"; Comment = "OriginalStartDate: The Original Start Date of the Meeting." }
        @{ Name = "Location"; Width = 10; Align = "Left"; Comment = "Location: The Location of the Meeting." }
        @{ Name = "CalendarItemType"; Width = 15; Align = "Center"; Comment = "CalendarItemType: The Calendar Item Type of the Meeting." }
        @{ Name = "RecurrencePattern"; Width = 20; Align = "Left"; Comment = "RecurrencePattern: The Recurrence Pattern of the Meeting." }
        @{ Name = "AppointmentAuxiliaryFlags"; Width = 30; Align = "Center"; Comment = "AppointmentAuxiliaryFlags: The Appointment Auxiliary Flags of the Meeting." }
        @{ Name = "DisplayAttendeesAll"; Width = 30; Align = "Left"; Comment = "DisplayAttendeesAll: List of the Attendees of the Meeting." }
        @{ Name = "AttendeeCount"; Width = 10; Align = "Center"; Comment = "AttendeeCount: The Attendee Count." }
        @{ Name = "AppointmentState"; Width = 20; Align = "Left"; Comment = "AppointmentState: The Appointment State of the Meeting." }
        @{ Name = "ResponseType"; Width = 10; Align = "Center"; Comment = "ResponseType: The Response Type of the Meeting." }
        @{ Name = "ClientIntent"; Width = 20; Align = "Center"; Comment = "ClientIntent: The Client Intent of the Meeting." }
        @{ Name = "AppointmentRecurring"; Width = 10; Align = "Center"; Comment = "AppointmentRecurring: Is this a Recurring Meeting?" }
        @{ Name = "HasAttachment"; Width = 10; Align = "Center"; Comment = "HasAttachment: Does this Meeting have an Attachment?" }
        @{ Name = "IsCancelled"; Width = 10; Align = "Center"; Comment = "IsCancelled: Is this Meeting Cancelled?" }
        @{ Name = "IsAllDayEvent"; Width = 10; Align = "Center"; Comment = "IsAllDayEvent: Is this an All Day Event?" }
        @{ Name = "IsSeriesCancelled"; Width = 10; Align = "Center"; Comment = "IsSeriesCancelled: Is this a Series Cancelled Meeting?" }
        @{ Name = "SendMeetingMessagesDiagnostics"; Width = 30; Align = "Left"; Comment = "SendMeetingMessagesDiagnostics: Compound Property to describe why meeting was or was not sent to everyone." }
        @{ Name = "AttendeeCollection"; Width = 50; Align = "Left"; Comment = "AttendeeCollection: The Attendee Collection of the Meeting, use -TrackingLogs to get values." }
        @{ Name = "CalendarLogRequestId"; Width = 40; Align = "Center"; Comment = "CalendarLogRequestId: The Calendar Log Request ID of the Meeting." }
    )

    foreach ($meta in $headerMeta) {
        $colLetter = $ColumnMap[$meta.Name]
        if ($null -eq $colLetter) { continue }
        $colIdx = [int][char]$colLetter[0] - [int][char]'A' + 1
        # Handle double-letter columns (e.g., "AB", "AM", etc.)
        if ($colLetter.Length -gt 1) {
            $colIdx = 0
            foreach ($c in $colLetter.ToCharArray()) {
                $colIdx = $colIdx * 26 + ([int][char]$c - [int][char]'A' + 1)
            }
        }
        $col = $sheet.Column($colIdx)
        $params = @{ Width = $meta.Width; HorizontalAlignment = $meta.Align }
        if ($meta.ContainsKey("NumberFormat")) { $params.NumberFormat = $meta.NumberFormat }
        $col | Set-ExcelRange @params
        Set-CellComment -Text $meta.Comment -Row $HeaderRow -ColumnNumber $colIdx -Worksheet $sheet
    }

    # Title Row
    $sheet.Row(1) | Set-ExcelRange -HorizontalAlignment Left
    Set-CellComment -Text "For more information see: Https:\\aka.ms\AnalyzeCalLogs"  -Row 1 -ColumnNumber 1  -Worksheet $sheet

    # Set the Header row to be bold and left aligned
    $sheet.Row($HeaderRow) | Set-ExcelRange -Bold -HorizontalAlignment Left
}
