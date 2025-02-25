# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Get-EXOMTLReport.ps1
	Requires: User Rights

.SYNOPSIS
Reads thru an EXO sourced Message Tracking log to generate plain text reporting on what is in the log.

.DESCRIPTION
Reads Message Tracking Detailed logs from EXO to generate reporting on critical information that they contain.
Start-HistoricalSearch -ReportTitle <title> -StartDate <24 hours before sent> -EndDate <24 hours after sent> -ReportType MessageTraceDetail  -MessageID <message ID> -NotifyAddress <address to notify>

Parses and provides details about the message in the MTL.
Helpful in troubleshooting message delivery issues.

.PARAMETER MTLFile
MTL File to process.

.PARAMETER ReportPath
Folder path for the output file.

.PARAMETER MessageID
MessageID of a message to parse if there is more than one in the MTL.

.OUTPUTS
Text File broken into sections that contain the output of the various data gathering run against the MTL.

Default Output File:
$PSScriptRoot\MTL_Report_<date>.txt

.EXAMPLE
.\Get-EXOMTLReport.ps1 -MTLPath C:\temp\MyMtl.csv -MessageID <123214124@myserver.com>

Generates a report from the MyMtl.csv file of the message with ID <123214124@myserver.com>

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
function Import-MTL {
    [CmdletBinding()]
    [OutputType([array])]
    param (
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
        Write-Output "Failed to Load as Unicode; trying normal load"
        $initial_mtl = Import-Csv $FilePath
        # If we still have nothing then log an error and fail
        if ($null -eq $initial_mtl) {
            Write-Error "Failed to load CSV" -ErrorAction Stop
        }
        # Need to know that we loaded without Unicode.
        else {
            Write-Output "Loaded CSV without Unicode"
        }
    } else {
        Write-Output "Loaded MTL with Unicode"
    }

    # Making sure the MTL contains the fields we want.
    if (!(Test-CSVData -CSV $initial_mtl -ColumnsToCheck "date_time_utc", "source_context", "connector_id", "source", "event_id", "message_id", "recipient_address", "recipient_status", "recipient_count", "related_recipient_address", "reference", "message_subject", "sender_address", "return_path", "message_info", "directionality", "custom_data")) {
        Write-Error "MTL is missing one or more required fields." -ErrorAction Stop
    } else { Write-Output "CSV Passed Validation" }

    # Converting our strings into [DateTime]
    Write-Output "Converting date_time_utc values"
    for ($i = 0; $i -lt $initial_mtl.Count; $i++) {
        try {
            $initial_mtl[$i].date_time_utc = Get-Date($initial_mtl[$i].date_time_utc)
        } catch {
            Write-Error ("Problem converting date information: " + $Error) -ErrorAction Stop
        }
    }

    return $initial_mtl
}

# Gather up all of the entries related to a single MessageID
function Group-ByMessageID {
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
    if ($null -eq $Output) {
        Write-Error ("MessageID " + $MessageID + " not found in provide MTL.") -ErrorAction Stop
    }

    ### Do we want to search the reference Colum here as well??

    return $Output
}

# Gather up all of the entries by recipient
function Group-ByRecipient {
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
    if ($null -eq $Output) {
        Write-Error ("Recipient " + $Recipient + " not found in provide MTL.") -ErrorAction Stop
    }

    ### Do we want to search the reference Colum here as well??

    return $Output
}

# Test if we have only a single MessageID provided in the MTL
function Test-UniqueMessageID {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $MTL
    )

    if (($MTL | Select-Object -Property message_id -Unique).count -gt 1) {
        return $false
    } else {
        return $true
    }
}

# Determine if we have a unique recipient in the MTL
function Test-UniqueRecipient {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $MTL
    )

    if (($MTL | Select-Object -Property recipient_address -Unique).count -gt 1) {
        return $false
    } else {
        return $true
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
    $ColumnHeaders = ($CSV | Get-Member -MemberType NoteProperty).Name.replace("`"", "")
    foreach ( $ToCheck in $ColumnsToCheck) {
        if (!($ColumnHeaders -contains $ToCheck)) {
            # Write-Output ("Missing " + $ToCheck)
            return $false
        }
    }
    return $true
}

function Write-OutputFile {
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
function Get-StoreSubmissionData {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $messageIDFilteredEvents
    )

    # Select the StoreDriver Submit event for this messageID
    [array]$entry = $messageIDFilteredEvents | Where-Object { $_.source -eq "STOREDRIVER" -and $_.event_id -eq "RECEIVE" }

    # If we have more than one submission event that is a problem
    if ($entry.count -gt 1){Write-Warning "Detected multiple Submission events for the same message"}

    # We can have multiple SMTP RECEIVE events if they are using add on services
    foreach ($event in $entry) {
        # Extract the submission data
        $submission = ConvertFrom-StringData ($event.source_context -replace ",", " `n") -Delimiter ":"

        # Build the reporting hashtable
        $hash = [ordered]@{
            DateTimeUTC       = $event.date_time_utc
            ClientType        = $submission.ClientType
            CreationTime      = $submission.CreationTime
            SubmittingMailbox = $submission.Mailbox
            MessageClass      = $submission.MessageClass
        }

        Write-OutputFile -header "Submission Information" -myTable $hash
    }
}

function Get-MIMEData {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $messageIDFilteredEvents
    )

    # Select the StoreDriver Submit event for this messageID
    [array]$entry = $messageIDFilteredEvents | Where-Object { $_.source -eq "SMTP" -and $_.event_id -eq "RECEIVE" }

    # We can have multiple SMTP RECEIVE events if they are using add on services
    foreach ($event in $entry) {
        # If there is something wrong with the CSV we can end up with a null custom_data field, detect and skip.
        if ([string]::IsNullOrEmpty($event.custom_data)) {
            Write-Warning "Custom Data field Empty for SMTP RECEIVE event. Skipping"
        } else {
            $mimeData = (ConvertFrom-StringData ($event.custom_data -replace ";", " `n") -Delimiter "=")["S:MimeParts"].split("S:")[1].split("/")

            # Build the reporting hashtable
            $hash = [ordered]@{
                DateTimeUTC               = $event.date_time_utc
                AttachmentCount           = $mimeData[0]
                EmbeddedAttachments       = $mimeData[1]
                NumberOfMimeParts         = $mimeData[2]
                EmailMessageType          = $mimeData[3]
                EmailMimeComplianceStatus = $mimeData[4]
            }

            Write-OutputFile -header "Detected Mime Information on Submission" -myTable $hash
        }
    }
}

function Get-MTLStatistics {
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
    $SMTPResubmitEvents = $messageIDFilteredEvents | Where-Object { $_.event_id -like "RESUBMIT" }

    $hash = [ordered]@{
        MessageID          = $sortedEvents[0].message_id
        FirstEvent         = $sortedEvents[0].date_time_utc
        LastEvent          = $sortedEvents[-1].date_time_utc
        StoreReceiveEvents = $storeReceiveEvents.count
        SMTPReceiveEvents  = $SMTPReceiveEvents.count
        SMTPResubmitEvents = $SMTPResubmitEvents.count
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
    $ReportFile = (Join-Path -Path $ReportPath -ChildPath ("MTL_Report_" + (Get-Date -Format FileDateTime).ToString() + ".txt"))
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
Get-MTLStatistics -messageIDFilteredEvents $MessageIDFilteredMTL
Get-SToreSubmissionData -messageIDFilteredEvents $MessageIDFilteredMTL
Get-MIMEData -messageIDFilteredEvents $MessageIDFilteredMTL
Write-Output $ReportFile
