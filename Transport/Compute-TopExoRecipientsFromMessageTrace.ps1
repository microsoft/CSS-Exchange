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
     $results.MessageTraceEvents: all downloaded message trace events without aggregations
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
    param($eventList, $Threshold, $hourlyReport)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $eventList = $eventList | Sort-Object RecipientAddress, Received
    $sw.Stop()
    Write-Host "  Sort events: $($sw.Elapsed.ToString('hh\:mm\:ss\.fff'))"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $eventList.foreach(
        {
            $utcReceived = $_.Received.ToUniversalTime()
            $hourlyEvent = $hourlyReport[-1] #data is sorted to min get operations. we only need to compare with last element in the array
            if ($hourlyEvent.RecipientAddress -eq $_.RecipientAddress -and $hourlyEvent.HourOfDayUTC -eq $utcReceived.Hour -and $hourlyEvent.ReceivedDate -eq $utcReceived.Date) {
                $hourlyEvent.MessageCount +=1
            } else {
                $eventObj = New-Object PSObject -Property @{ HourOfDayUTC=$utcReceived.Hour; ReceivedDate=$utcReceived.Date; Date=$utcReceived.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); MessageCount=1; RecipientAddress=$_.RecipientAddress }
                [void]$hourlyReport.Add($eventObj)
            }
        }
    )
    $sw.Stop()
    Write-Host "  Aggregate events: $($sw.Elapsed.ToString('hh\:mm\:ss\.fff')) ($($hourlyReport.Count) hourly entries)"

    $aboveThreshold = $hourlyReport.Where( { $_.MessageCount -ge $Threshold })
    Write-Host "  Entries above threshold ($Threshold): $($aboveThreshold.Count)"
    if ($aboveThreshold.Count -gt 100) {
        Write-Warning "More than 100 entries above threshold. Get-Mailbox lookups may take a long time to complete."
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $lookupCount = 0
    $totalLookups = $aboveThreshold.Count
    $topRecipients = $aboveThreshold.Where( {
            $lookupCount++
            Write-Progress -Activity "Get-Mailbox lookups" -Status "$lookupCount of $totalLookups - $($_.RecipientAddress)" -PercentComplete (($lookupCount / $totalLookups) * 100)
            (Get-Mailbox $_.RecipientAddress -ErrorAction SilentlyContinue) -ne $null
        }) | Sort-Object MessageCount -Descending | Select-Object Date, MessageCount, RecipientAddress
    Write-Progress -Activity "Get-Mailbox lookups" -Completed
    $sw.Stop()
    Write-Host "  Get-Mailbox lookups: $($sw.Elapsed.ToString('hh\:mm\:ss\.fff')) ($totalLookups lookups, $($($topRecipients | Measure-Object).Count) matched)"

    if (-not $topRecipients) {
        Write-Warning "No recipients found exceeding the threshold of $Threshold messages per hour."
    }
    return $topRecipients
}

$GetDeliveredMessageTraceEvents =
{
    param([DateTime]$StartDate, [DateTime]$EndDate, $TimeoutAfter)
    [DateTime]$timeout = (Get-Date).AddMinutes($TimeoutAfter)

    $pageCount = 1
    Write-Progress -Activity "Fetching message trace data" -Status "Retrieving initial results (page 1)..."
    $eventList =Get-MessageTraceV2 -StartDate $StartDate -EndDate $EndDate -WarningVariable MoreResultsAvailable -ResultSize 5000 3>$null
    while ($MoreResultsAvailable -and (Get-Date) -lt $timeout) {
        $pageCount++
        Write-Progress -Activity "Fetching message trace data" -Status "Retrieved $($eventList.Count) messages so far (page $pageCount)..."
        $Query = ($MoreResultsAvailable -join "").TrimStart("There are more results, use the following command to get more. ")
        $ScriptBlock = [ScriptBlock]::Create($Query)
        $moreMessages = Invoke-Command -ScriptBlock $ScriptBlock -WarningVariable MoreResultsAvailable -Verbose:$false 3>$null
        $eventList += $moreMessages
    }
    Write-Progress -Activity "Fetching message trace data" -Completed
    return $eventList
}

#Main

try {
    $savedProgressPreference = $ProgressPreference
    $ProgressPreference = 'Continue'

    $hourlyReport = New-Object -TypeName "System.Collections.ArrayList"
    $eventList = New-Object -TypeName "System.Collections.ArrayList"
    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "Start Message Trace"
    $stepTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $eventList = Invoke-Command -ScriptBlock $GetDeliveredMessageTraceEvents -ArgumentList $StartDate, $EndDate, $TimeoutAfter
    $stepTimer.Stop()
    Write-Host "Message Trace completed in $($stepTimer.Elapsed.ToString('hh\:mm\:ss\.fff')). Events retrieved: $($eventList.Count)"

    Write-Host "Create Hourly Report"
    $stepTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $topList = Invoke-Command -ScriptBlock $CreateHourlyReport -ArgumentList $eventList, $Threshold, $hourlyReport
    $stepTimer.Stop()
    Write-Host "Hourly Report completed in $($stepTimer.Elapsed.ToString('hh\:mm\:ss\.fff')). Hourly entries: $($hourlyReport.Count), Top recipients: $(($topList | Measure-Object).Count)"

    $totalTimer.Stop()
    Write-Host "Total execution time: $($totalTimer.Elapsed.ToString('hh\:mm\:ss\.fff'))"

    $props = [ordered]@{
        'TopRecipients'      = $topList
        'HourlyReport'       = $hourlyReport | Select-Object Date, HourOfDayUTC, MessageCount, RecipientAddress
        'MessageTraceEvents' = $eventList
    }
    $results = New-Object -TypeName PSObject -Property $props
    return $results
} finally {
    $ProgressPreference = $savedProgressPreference
}
