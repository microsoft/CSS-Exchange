# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    .SYNOPSIS
    This script aggregates message trace events hourly and generates a report with the top o365 recipients

    .DESCRIPTION

    .PARAMETER StartDate
     The StartDate parameter specifies the end date of the date range

    .PARAMETER EndDate
     The EndDate parameter specifies the end date of the date range. It is recommended to limit the start-end date range to a range of hours. i.e. an ~ 5 to 7 hours.

    .PARAMETER TimeoutAfter
     The TimeoutAfter parameter specifies the number of minutes before the script stop working.
     This is to make sure that the script does not run for infinity. The default value is 30 minutes.

     .PARAMETER Threshold
      The Threshold parameter specifies the min threshold for the received limit.
      It is used to filter the hourly aggregation.
      The default value is 3600 messages.

    .EXAMPLE

     $results = Compute-TopExoRecipientsFromMessageTrace -StartDate (Get-Date).AddHours(-7) -EndDate (Get-Date)

    .OUTPUTS
     $results.TopRecipients : hourly report for top recipients over the threshold
     $results.HourlyReport  : hourly aggregated message events without applying the threshold
     $results.MessageTraceEevents: all downloaded message trace events without aggregations
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory=$true)]
    [DateTime]$StartDate,
    [Parameter(Mandatory=$true)]
    [DateTime]$EndDate,
    [Parameter(Mandatory=$false)]
    [int]$Threshold = 3600,
    [Parameter(Mandatory=$false)]
    [int]$TimeoutAfter = 30
)

$CreateHourlyReport =
{
    param($eventList, $Threshold)
    $eventList = $eventList | Sort-Object RecipientAddress, Received
    $eventList.foreach(
        {
            $hourlyEvent = $hourlyReport[-1] #data is sorted to min get operations. we only need to compare with last element in the array
            if ($hourlyEvent.RecipientAddress -eq $_.RecipientAddress -and $hourlyEvent.Hour -eq $_.Received.Hour) {
                $hourlyEvent.MessageCount +=1
            } else {
                $eventObj = New-Object PSObject -Property @{ Hour=$_.Received.Hour; Date=$_.Received.Date.ToString("dd/mm/yyyy dd:hh tt"); MessageCount=1; RecipientAddress=$_.RecipientAddress };
                [void]$hourlyReport.Add($eventObj)
            }
        }
    )
    return $hourlyReport.Where( { $_.MessageCount -ge $Threshold -and (Get-Mailbox $_.RecipientAddress -ErrorAction SilentlyContinue) -ne $null }) | Sort-Object MessageCount -Descending | Select-Object Date, MessageCount, RecipientAddress
}

$GetDeliveredMessageTraceEvents =
{
    param([DateTime]$StartDate, [DateTime]$EndDate, $TimeoutAfter)
    [int]$page=1
    [DateTime]$timeout = (Get-Date).AddMinutes($TimeoutAfter)

    Do {
        Write-Host "Processing Page $($page)"
        $pageList = New-Object -TypeName "System.Collections.ArrayList"
        $pageList = Get-MessageTrace -StartDate $StartDate -EndDate $EndDate -Page $page -PageSize 5000 -Status Delivered
        $eventList += $pageList
        $page++
    }While ($pageList.count -eq 5000 -and (Get-Date) -lt $timeout)
    return $eventList
}

#Main
$hourlyReport = New-Object -TypeName "System.Collections.ArrayList"
$eventList = New-Object -TypeName "System.Collections.ArrayList"

Write-Host "Start Message Trace"
$eventList = Invoke-Command -ScriptBlock $GetDeliveredMessageTraceEvents -ArgumentList $StartDate, $EndDate, $TimeoutAfter

Write-Host "Create Hourly Report"
$topList = Invoke-Command -ScriptBlock $CreateHourlyReport -ArgumentList $eventList, $Threshold

$props = [ordered]@{
    'TopRecipients'      = $topList
    'HourlyReport'       = $hourlyReport
    'MessageTraceEvents' = $eventList
}
$results = New-Object -TypeName PSObject -Property $props;
return $results

