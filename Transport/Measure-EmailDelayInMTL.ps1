# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Test-ExchAVExclusions.ps1
	Requires: Administrator rights
    Major Release History:
        05/07/2024 - Initial Release

.SYNOPSIS
Generates a report of the minimum message delay for all messages in an Message Tracking Log.

.DESCRIPTION
Gather message tracking log details of all message to / from a given recipient for a given time range.
Recommend using start-historicalsearch in EXO.

The script will provide an output of all unique message ids with the following information:
MessageID
Time Sent
First Time the Message was Delivered
Last Time the Message was Delivered
Total Time in transit

Useful for determining if a "slow" message was a one off or a pattern.

.PARAMETER MTLFile
MTL File to process

.OUTPUTS
CSV File with the following informaiton.
    ID                      messageID
    Sent                    Time the Message was sent.
    FirstRecieved           When a Recipient first Recieved the message.
    LastRecieved            When the last recipient recieved the message. (This will match first Recieved if the message was sent to one recipient.)
    RecievedDifferential    Difference between First and Last Recieved (how long it took to deliver to all recipients)
    MessageDelay            Difference between First Recieved and Time Sent

$PSScriptRoot\MTLReport-#DateTime#.csv

.EXAMPLE
.\Measure-EmailDelayInMTL -MTLPath C:\temp\MyMtl.csv

Generates the report from the MyMtl.csv file.

#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $MTLFile
)

. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1

# Autoupdate
if (Test-ScriptVersion -AutoUpdate) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."
    return
}

# make sure out output variable is null
$output = $Null

# Test for the provided file and load it.
if (Test-Path $MTLFile) {
    Write-Output "Loading MTL file."
    $mtl = Import-Csv $MTLFile -Encoding Unicode
} else {
    Write-Error "Unable to find specified file"
}

# get all of the unique message IDs in the file.
$uniqueMessageIDs = $mtl | Select-Object -ExpandProperty message_id | Sort-Object | Get-Unique

# Carve the data up into smaller collections to make searching faster.
# Most of what is in the MTL we don't need for this.
$SMTPRecieve = $mtl | Where-Object { ($_.event_id -eq 'RECEIVE') -and ($_.source -eq 'SMTP') }
$StoreDeliver = $mtl | Where-Object { ($_.event_id -eq 'DELIVER') -and ($_.source -eq 'STOREDRIVER') }
$SMTPDeliver = $mtl | Where-Object { ($_.event_id -eq 'SENDEXTERNAL') -and ($_.source -eq 'SMTP') }

# Loop thru each unique messageID
foreach ($id in $uniqueMessageIDs) {

    # make sure we aren't carrying anyting over from the previous foreach.
    $AllSentTimes = $Null
    $AllStoreDeliverTimes = $Null
    $AllRemoteDeliverTimes = $Null

    # extract the times for a message ID ... there can be more than one of each of these.
    [array]$AllSentTimes = ($SMTPRecieve | Where-Object { ($_.message_id -eq $id) }).date_time_utc
    [array]$AllStoreDeliverTimes = ($StoreDeliver | Where-Object { ($_.message_id -eq $id) }).date_time_utc
    [array]$AllRemoteDeliverTimes = ($SMTPDeliver | Where-Object { ($_.message_id -eq $id.message_id) }).date_time_utc

    # Process the time sent
    if ($AllSentTimes.count -eq 0) {
        Write-Warning ($id.message_id.tostring() + "unable to find sent time. Discarding messageID")
        quit
    } else {
        $TimeSent = Get-Date ($AllSentTimes | Sort-Object | Select-Object -First 1)
    }

    # If we didn't find any delivery information then drop the message ID
    if ($AllStoreDeliverTimes.count -eq 0 -and $AllRemoteDeliverTimes.count -eq 0) {
        Write-Warning ($id.message_id.tostring() + "not able to find delivery time in MTL. Discarding messageID")
        quit
    }

    # Process the message information
    else {

        # Combine all of the delivery times.
        [array]$AllDeliveries = ($AllStoreDeliverTimes + $AllRemoteDeliverTimes) | Sort-Object

        $report = [PSCustomObject]@{
            ID                   = $id
            Sent                 = $TimeSent
            FirstRecieved        = (Get-Date $AllDeliveries[0])
            LastRecieved         = (Get-Date $AllDeliveries[-1])
            RecievedDifferential = (Get-Date $AllDeliveries[-1]) - (Get-Date $AllDeliveries[0])
            MessageDelay         = (Get-Date $AllDeliveries[0]) - $timesent
        }

        [array]$output = [array]$output + $report
    }
}

$Stats = ($output.MessageDelay.TotalMilliseconds | Measure-Object -Average -Maximum -Minimum)

$GeneralData = [PSCustomObject]@{
    EmailCount   = $Stats.Count
    MaximumDelay = [TimeSpan]::FromMilliseconds($Stats.Maximum)
    MinimumDelay = [TimeSpan]::FromMilliseconds($Stats.Minimum)
    AverageDelay = [TimeSpan]::FromMilliseconds($Stats.Average)
}

Write-Output $GeneralData
