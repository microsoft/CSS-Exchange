# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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