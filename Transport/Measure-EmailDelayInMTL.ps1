﻿# Copyright (c) Microsoft Corporation.
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
    [Parameter()]
    [string]
    $MTLFile,
    [Parameter()]
    [string]
    $ReportPath = $PSScriptRoot
)

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

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
        if ($ColumnHeaders.Contains($ColumnToCheck) ) {
            # Nothing to do.
        } else {
            return $false
        }
    }
    return $true
}

if (Test-ScriptVersion -AutoUpdate) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."
    return
}

# make sure out output variable is null
$output = $Null

# Test for the provided file and load it.
# Need to make sure the MTL file is there and if so load it.
# Straight from EXO it will be in unicode ... but if it is modified it might not be.
# First verify the file
if (!(Test-Path $MTLFile)) {
    Write-Error "Unable to find the specified file" -ErrorAction Stop
}

# Try to load the file with unicode since this should be the most common
$mtl = Import-Csv $MTLFile -Encoding Unicode

# If it is null then we need to try without unicode
if ($null -eq $mtl) {
    Write-Host "Failed to Load as Unicode; trying normal load"
    $mtl = Import-Csv $MTLFile
    # If we still have nothing the log and error and fail
    if ($null -eq $mtl) {
        Write-Error "Failed to load CSV" -ErrorAction Stop
    }
    # need to know that we loaded without unicode.
    else {
        Write-Host "Loaded CSV without unicode"
        $unicode = $false
    }
} else {
    Write-Host "Loaded MTL with unicode"
    $unicode = $true
}

# Validate the MTL
if (!(Test-CSVData -CSV $mtl -ColumnsToCheck "event_id", "source", "message_id", "date_time_utc")) {
    Write-Error "MTL is missing one or more required fields: `"event_id`",`"source`",`"message_id`",`"date_time_utc`"" -ErrorAction Stop
}

# If we did a non-unicode load then we need to fixup date_time_utc from string object to [DateTime] objects
if (!($unicode)) {
    Write-Host "Fixing up date_time_utc values"
    for ($i = 0; $i -lt $mtl.Count; $i++) {
        $mtl[$i].date_time_utc = Get-Date($mtl[$i].date_time_utc)
    }
}

# get all of the unique message IDs in the file.
[array]$uniqueMessageIDs = $mtl | Select-Object -ExpandProperty message_id | Sort-Object | Get-Unique

if ($uniqueMessageIDs.count -eq 0) {
    Write-Error "No Unique MessageIDs found in data."
}

# Carve the data up into smaller collections
# Most of what is in the MTL we don't need for this.
$SMTPReceive = $mtl | Where-Object { ($_.event_id -eq 'Receive') -and ($_.source -eq 'SMTP') }
$StoreDeliver = $mtl | Where-Object { ($_.event_id -eq 'Deliver') -and ($_.source -eq 'StoreDriver') }
$SMTPDeliver = $mtl | Where-Object { ($_.event_id -eq 'SendExternal') -and ($_.source -eq 'SMTP') }

# Loop thru each unique messageID
foreach ($id in $uniqueMessageIDs) {

    # make sure we aren't carrying anything over from the previous foreach.
    $AllSentTimes = $Null
    $AllStoreDeliverTimes = $Null
    $AllRemoteDeliverTimes = $Null

    # extract the times for a message ID ... there can be more than one of each of these.
    [array]$AllSentTimes = ($SMTPReceive | Where-Object { ($_.message_id -eq $id) }).date_time_utc
    [array]$AllStoreDeliverTimes = ($StoreDeliver | Where-Object { ($_.message_id -eq $id) }).date_time_utc
    [array]$AllRemoteDeliverTimes = ($SMTPDeliver | Where-Object { ($_.message_id -eq $id) }).date_time_utc

    # Process the time sent
    if ($AllSentTimes.count -eq 0) {
        Write-Warning ($id.ToString() + " unable to find sent time. Discarding messageID")
        continue
    }

    # If we didn't find any delivery information then drop the message ID
    if ($AllStoreDeliverTimes.count -eq 0 -and $AllRemoteDeliverTimes.count -eq 0) {
        Write-Warning ($id + " not able to find delivery time in MTL. Discarding messageID")
    }
    # Process the message information
    else {

        # Get the newest time sent that we found
        $SortedTimeSent = Get-Date ($AllSentTimes | Sort-Object | Select-Object -First 1)

        # Combine all of the delivery times and grab the newest one
        $SortedTimeDelivered = (($AllStoreDeliverTimes + $AllRemoteDeliverTimes) | Sort-Object | Select-Object -Last 1)

        # Build report object
        $report = [PSCustomObject]@{
            MessageID    = $id
            TimeSent     = $TimeSent
            TimeReceived = $SortedTimeSent
            MessageDelay = $SortedTimeDelivered - $SortedTimeSent
        }

        # Build output object
        [array]$output = [array]$output + $report
    }
}

# Make sure we have something to output
if ($null -eq $output) {
    Write-Error "No output generated" -ErrorAction Stop
} else {

    # Export the data to the output file
    $outputFile = (Join-Path -Path $ReportPath -ChildPath "MTL_report.csv")
    $output | Export-Csv -IncludeTypeInformation:$false -Path $outputFile
    Write-Output ("Report written to file " + $outputFile)

    # Gather general statistical data and output to the screen
    $Stats = ($output.MessageDelay.TotalMilliseconds | Measure-Object -Average -Maximum -Minimum)

    $GeneralData = [PSCustomObject]@{
        EmailCount   = $Stats.Count
        MaximumDelay = [TimeSpan]::FromMilliseconds($Stats.Maximum)
        MinimumDelay = [TimeSpan]::FromMilliseconds($Stats.Minimum)
        AverageDelay = [TimeSpan]::FromMilliseconds($Stats.Average)
    }

    Write-Output $GeneralData
}