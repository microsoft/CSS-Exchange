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
Time Recieved
Total Time in transit.

Useful for determining if a "slow" message was a one off or a pattern.

.PARAMETER MTLFile
Will test not just the root folders but all SubFolders.
Generally should not be needed unless all folders pass without -Recuse but AV is still suspected.

.OUTPUTS
CSV with messageID and times.
$PSScriptRoot\MTLReport-#DataTime#.csv

.EXAMPLE
.\Get-EmailDelay -MTLPath C:\temp\MyMtl.csv

Generates the report from the MyMtl.csv file.

#>

Function Measure-EmailDelayInMTL {


    $output = $Null
    $mtl = Import-Csv '.\MTDetail_Informe de seguimiento de mensajes (_2024-05-01T005824.161Z_)_a6d21a9d-9c5b-4529-ad67-3546f9089874.csv' -Encoding Unicode

    $uniqueMessageIDs = $mtl | Select-Object -Property message_id -Unique

    foreach ($id in $uniqueMessageIDs) {

        $localdeliver = $Null
        $remotedeliver = $Null
        $timerecieved = $Null

        $timesent = Get-Date ($mtl | Where-Object { ($_.message_id -eq $id.message_id) -and ($_.event_id -eq 'RECEIVE') -and ($_.source -eq 'SMTP') }).date_time_utc

        [array]$localdeliver = ($mtl | Where-Object { ($_.message_id -eq $id.message_id) -and ($_.event_id -eq 'DELIVER') -and ($_.source -eq 'STOREDRIVER') }).date_time_utc
        [array]$remotedeliver = ($mtl | Where-Object { ($_.message_id -eq $id.message_id) -and ($_.event_id -eq 'SENDEXTERNAL') -and ($_.source -eq 'SMTP') }).date_time_utc


        if ($localdeliver.count -eq 0 -and $remotedeliver.count -eq 0) {
            Write-Warning ($id.message_id.tostring() + "not able to find delivery time in MTL.")
        } else {

            if ($localdeliver.count -eq 0) {
                $timerecieved = Get-Date ($remotedeliver | Sort-Object | Select-Object -First 1)
            } else {
                $timerecieved = Get-Date ($localdeliver | Sort-Object | Select-Object -First 1)
            }

            $report = [PSCustomObject]@{
                ID       = $id.message_id
                Sent     = $TimeSent
                Recieved = $timerecieved
                Delay    = $timerecieved - $timesent
            }

            [array]$output = [array]$output + $report
        }
    }
    return $output
}