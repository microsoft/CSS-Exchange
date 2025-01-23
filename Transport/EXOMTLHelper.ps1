# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Measure-EmailDelayInMTL.ps1
	Requires: User Rights
    Major Release History:
        08/05/2024 - Initial Release

.SYNOPSIS
Generates a report of the maximum message delay for all messages in an Message Tracking Log.

.DESCRIPTION
Gather message tracking log details of all message to / from a given recipient for a given time range.
Recommend using Start-HistoricalSearch in EXO.

The script will provide an output of all unique message ids with the following information:
MessageID
Time Sent
Total Time in transit

Useful for determining if a "slow" message was a one off or a pattern.

.PARAMETER MTLFile
MTL File to process.

.PARAMETER ReportPath
Folder path for the output file.


.OUTPUTS
CSV File with the following information.
    MessageID               ID of the Message
    TimeSent                First time we see the message in the MTL
    TimeReceived            Last delivery time in the MTL
    MessageDelay            How long before the message was delivered

Default Output File:
$PSScriptRoot\MTL_report.csv

.EXAMPLE
.\Measure-EmailDelayInMTL -MTLPath C:\temp\MyMtl.csv

Generates a report from the MyMtl.csv file.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $MTLFile,
    [Parameter()]
    [string]
    $ReportPath = $PSScriptRoot,
    [Parameter()]
    [string]
    $MessageID
)

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

### Utilities ###
Function Import-MTL {
    [CmdletBinding()]
    [OutputType([array])]
    Param(
        # File path for MTL to import
        [Parameter(Mandatory = $true)]
        [string]
        $FilePath
    )

    # Test the path of the MTL
    if (!(Test-Path $FilePath)) {
        Write-Error "Unable to find the specified file" -ErrorAction Stop
    }

    # Try to load the file with Unicode since we need to start somewhere.
    $initial_mtl = Import-Csv $FilePath -Encoding Unicode

    # If it is null then we need to try without Unicode
    if ($null -eq $initial_mtl) {
        Write-Host "Failed to Load as Unicode; trying normal load"
        $initial_mtl = Import-Csv $FilePath
        # If we still have nothing then log an error and fail
        if ($null -eq $initial_mtl) {
            Write-Error "Failed to load CSV" -ErrorAction Stop
        }
        # Need to know that we loaded without Unicode.
        else {
            Write-Host "Loaded CSV without Unicode"
        }
    } else {
        Write-Host "Loaded MTL with Unicode"
    }

    # Making sure the MTL contains the fields we want.
    if (!(Test-CSVData -CSV $initial_mtl -ColumnsToCheck "date_time_utc", "source_context", "connector_id", "source", "event_id", "message_id", "recipient_address", "recipient_status", "recipient_count", "related_recipient_address", "reference", "message_subject", "sender_address", "return_path", "message_info", "directionality", "custom_data")) {
        Write-Error "MTL is missing one or more required fields." -ErrorAction Stop
    }

    # Converting our strings into [DateTime]
    Write-Host "Converting date_time_utc values"
    for ($i = 0; $i -lt $initial_mtl.Count; $i++) {
        $initial_mtl[$i].date_time_utc = Get-Date($initial_mtl[$i].date_time_utc)
    }

    return $initial_mtl
}

# Gather up all of the entries related to a single MessageID
Function Group-ByMessageID {
    [CmdletBinding()]
    [OutputType([array])]
    param (
        # MTL array to process
        [Parameter(Mandatory = $true)]
        [array]$MTL,
        # MessageID to group by
        [Parameter(Mandatory = $true)]
        [string]$MessageID
    )

    # Filter the MTL by our messageID
    [array]$Output = $MTL | Where-Object { $_.message_id -eq $MessageID }

    # Make sure we found the messageID
    If ($null -eq $Output) {
        Write-Error ("MessageID " + $MessageID + " not found in provide MTL.") -ErrorAction Stop
    }

    ### Do we want to search the reference Colum here as well??

    Return $Output
}

# Gather up all of the entries by recipient
Function Group-ByRecipient {
    [CmdletBinding()]
    [OutputType([array])]
    param (
        # MTL array to process
        [Parameter(Mandatory = $true)]
        [array]
        $MTL,
        # MessageID to group by
        [Parameter(Mandatory = $true)]
        [string]
        $Recipient
    )

    # Filter the MTL by the provided recipient
    [array]$Output = $MTL | Where-Object { $_.recipient_address -like ('*' + $Recipient + '*') }

    # Make sure we found the recipient
    If ($null -eq $Output) {
        Write-Error ("Recipient " + $Recipient + " not found in provide MTL.") -ErrorAction Stop
    }

    ### Do we want to search the reference Colum here as well??

    Return $Output
}

# Test if we have only a single MessageID provided in the MTL
Function Test-UniqueMessageID {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $MTL
    )

    if (($MTL | Select-Object -Property message_id -Unique).count -gt 1) {
        Return $false
    } else {
        Return $true
    }
}

# Determine if we have a unique recipient in the MTL
Function Test-UniqueRecipient {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $MTL
    )

    if (($MTL | Select-Object -Property recipient_address -Unique).count -gt 1) {
        Return $false
    } else {
        Return $true
    }
}

function Test-CSVData {
    param(
        [array]$CSV,
        [array]$ColumnsToCheck
    )

    # Check to make sure we have data in the CSV
    if (($null -eq $CSV) -or !($CSV.count -gt 0)) {
        Write-Error "Provided CSV null or empty" -ErrorAction Stop
        return $false
    }

    # Read thru the data and make sure we have the needed columns
    $ColumnHeaders = ($CSV | Get-Member -MemberType NoteProperty).Name
    foreach ( $ColumnToCheck in $ColumnsToCheck) {
        if (!($ColumnHeaders.ToLower().Contains($ColumnToCheck.ToLower())) ) {
            return $false
        }
    }
    return $true
}

Function Write-OutputFile {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $header,
        [Parameter(Mandatory = $false)]
        [string]
        $message,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.OrderedHashtable]
        $myTable
    )

    $file = $ReportFile

    Add-Content -Path $file  $header.ToUpper()
    Add-Content -Path $file "===================="
    $myTable | Format-Table -AutoSize -HideTableHeaders | Out-String | Add-Content -Path $file
}

### Diagnostics ###

# Determine and report the type of client that submitted the message
Function Test-SubmissionData {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $messageIDFilteredEvents
    )

    # Select the StoreDriver Submit event for this messageID
    $entry = $messageIDFilteredEvents | Where-Object { $_.source -eq "STOREDRIVER" -and $_.event_id -eq "RECEIVE" }
    if ($entry.count -gt 1) { Write-Error "Found more than one STOREDRIVER RECIEVE event for this message" }
    else { $toParse = $entry.source_context }

    # Extract the submission data
    $submission = ConvertFrom-StringData ($toParse -replace ",", " `n") -Delimiter ":"

    # Build the reporting hashtable
    $hash = [ordered]@{
        ClientType        = $submission.ClientType
        CreationTime      = $submission.CreationTime
        SubmittingMailbox = $submission.Mailbox
        MessageClass      = $submission.MessageClass
    }

    Write-OutputFile -header "Submission information" -myTable $hash

}

Function Test-MIMEData {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $messageIDFilteredEvents
    )

    # Select the StoreDriver Submit event for this messageID
    $entry = $messageIDFilteredEvents | Where-Object { $_.source -eq "SMTP" -and $_.event_id -eq "RECEIVE" }
    if ($entry.count -gt 1) { Write-Error "Found more than one SMTP RECIEVE event for this message" }
    else { $toParse = $entry.custom_data }

    $mimeData = (ConvertFrom-StringData ($toParse -replace ";", " `n") -Delimiter "=")["S:MimeParts"].split("S:")[1].split("/")

    # Build the reporting hashtable
    $hash = [ordered]@{
        AttachmentCount           = $mimeData[0]
        EmbeddedAttachments       = $mimeData[1]
        NumberOfMimeParts         = $mimeData[2]
        EmailMessageType          = $mimeData[3]
        EmailMimeComplianceStatus = $mimeData[4]
    }

    Write-OutputFile -header "Detected Mime Information on Submission" -myTable $hash
}

Function Test-MTLStatistics {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $messageIDFilteredEvents
    )

    # Sort the events by time.
    $sortedEvents = $messageIDFilteredEvents | Sort-Object -Property "date_time_utc"
    $storeReceiveEvents = $messageIDFilteredEvents | Where-Object { $_.source -eq "STOREDRIVER" -and $_.event_id -like "RECEIVE" }
    $SMTPReceiveEvents = $messageIDFilteredEvents | Where-Object { $_.source -eq "SMTP" -and $_.event_id -like "RECEIVE" }
    $deliveryEvents = $messageIDFilteredEvents | Where-Object { $_.event_id -like "DELIVER" }
    $sendExternalEvents = $messageIDFilteredEvents | Where-Object { $_.event_id -like "SENDEXTERNAL" }

    $hash = [ordered]@{
        MessageID          = $sortedEvents[0].message_id
        FirstEvent         = $sortedEvents[0].date_time_utc
        LastEvent          = $sortedEvents[-1].date_time_utc
        StoreReceiveEvents = $storeReceiveEvents.count
        STMPReceiveEvents  = $SMTPReceiveEvents.count
        DeliveryEvents     = $deliveryEvents.count
        SendExternalEvents = $sendExternalEvents.count
    }

    Write-OutputFile -header "General MTL Statistics" -myTable $hash
}

### Main ###

#Import the MTL file.
$MTL = Import-MTL -FilePath $MTLFile

# Make sure the path for the output is good
if (!(Test-Path $ReportPath)) {
    Write-Error ("Unable to find report path " + $ReportPath)
} else {
    $ReportFile = (Join-Path -Path $ReportPath -ChildPath ("MTL Report " + (Get-Date -Format FileDateTime).ToString() + ".txt"))
}

# If no messageID was provided make sure that there is only one in the MTL
if ([string]::IsNullOrEmpty($MessageID)) {
    if (!(Test-UniqueMessageID -MTL $MTL)) {
        Write-Error "Multiple MessageIDs detected in MTL please using -MessageID to specify the one to examine" -ErrorAction Stop
    } else {
        $MessageIDFilteredMTL = $MTL
    }
}
# If a messageID was provided then filter based on it
else {
    $MessageIDFilteredMTL = Group-ByMessageID -MTL $MTL -MessageID $MessageID
}

# Run the set of tests that we want to run and generate the output.
Write-Output "Generating Reporting"
Test-MTLStatistics -messageIDFilteredEvents $MessageIDFilteredMTL
Test-SubmissionData -messageIDFilteredEvents $MessageIDFilteredMTL
Test-MIMEData -messageIDFilteredEvents $MessageIDFilteredMTL
Write-Output $ReportFile