# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore Goid

function Write-RbaNextSteps {
    Write-RbaDashLineBox @("Next Steps") -Color Cyan
    Write-Host "Review the saved RBA log to see how meeting requests were processed."
    Write-Host "To collect a new RBA log:"
    Write-Host -ForegroundColor Yellow "`tExport-MailboxDiagnosticLogs -Identity $Identity -ComponentName RBA"
    Write-Host
    Write-Host "For additional troubleshooting, send a future test meeting to the room, then collect RBA logs and Calendar Diagnostic Objects for the organizer and room."
    Write-Host "Calendar Diagnostic Objects tool:"
    Write-Host -ForegroundColor Cyan "`thttps://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-CalendarDiagnosticObjectsSummary.ps1"
    Write-Host "`r`nFeedback: CalLogFormatterDevs@microsoft.com"
}

function Get-RbaLogData {
    Write-Host -ForegroundColor Cyan "Running: Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName RBA"
    $diagnosticLog = Invoke-RbaCollector -Name "RbaLog" -Action {
        Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName RBA -ErrorAction Stop
    }

    if ($null -ne $diagnosticLog) {
        [array]$script:RBALog = @($diagnosticLog.MailboxLog -split "`r?`n" | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
    }
}

function Get-RbaMeetingIdsFromLogLines {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines
    )

    $meetingIds = [System.Collections.Generic.List[string]]::new()
    $content = $Lines -join [Environment]::NewLine
    $labelPattern = '(?i)(?:CleanGlobalObjectId|GlobalObjectId|Global Object Id|MeetingId|Meeting ID|UID)\s*[:=]\s*[\[\{]?(?<MeetingId>[A-Za-z0-9+/=_-]{16,})'
    foreach ($match in [regex]::Matches($content, $labelPattern)) {
        $meetingIds.Add(($match.Groups['MeetingId'].Value -replace ',', ''))
    }

    $processRequestPattern = '(?i)\bBegin Process(?:Update)?Request\s+Goid:\s*[\[\{]?(?<MeetingId>[A-Za-z0-9+/=_,-]{16,})'
    foreach ($match in [regex]::Matches($content, $processRequestPattern)) {
        $meetingIds.Add(($match.Groups['MeetingId'].Value -replace ',', ''))
    }

    foreach ($match in [regex]::Matches($content, '(?i)\b040000008,?[A-F0-9]{23,}\b')) {
        $meetingIds.Add(($match.Value -replace ',', ''))
    }

    return @($meetingIds | Sort-Object -Unique)
}

function ConvertTo-RbaNormalizedMeetingId {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return (($Value.Trim() -replace '^[\[\{]', '') -replace '[\]\}]$', '') -replace ',', ''
}

function Split-RbaLogProcessingBlocks {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines
    )

    if ($Lines.Count -eq 0) {
        return @()
    }

    $exactStartPattern = 'START - HandleEventInternal Automatic Booking is enabled for resource\.\s*$'
    $startIndexes = @(0..($Lines.Count - 1) | Where-Object { $Lines[$_] -match $exactStartPattern })
    $blocks = [System.Collections.Generic.List[object]]::new()

    if ($startIndexes.Count -eq 0) {
        $blocks.Add([PSCustomObject]@{
                sequence           = 1
                startLine          = 1
                endLine            = $Lines.Count
                startBoundaryFound = $false
                boundaryStatus     = "MissingStartBoundary"
                startMarker        = $null
                startTimeText      = $null
                meetingIds         = @(Get-RbaMeetingIdsFromLogLines -Lines $Lines)
                lines              = @($Lines)
            })
        return $blocks.ToArray()
    }

    for ($blockIndex = 0; $blockIndex -lt $startIndexes.Count; $blockIndex++) {
        $endIndex = $startIndexes[$blockIndex]
        $startIndex = if ($blockIndex -eq 0) {
            0
        } else {
            $startIndexes[$blockIndex - 1] + 1
        }
        $blockLines = @($Lines[$startIndex..$endIndex])
        $startMarker = [string]$Lines[$endIndex]
        $startTimeText = if ($startMarker.Contains(',')) {
            ($startMarker -split ',', 2)[0].Trim()
        } else {
            $null
        }
        $blocks.Add([PSCustomObject]@{
                sequence           = $blockIndex + 1
                startLine          = $startIndex + 1
                endLine            = $endIndex + 1
                startBoundaryFound = $true
                boundaryStatus     = $(if ($blockIndex -eq 0) { "SourceStartToExactStart" } else { "BetweenExactStartBoundaries" })
                startMarker        = $startMarker
                startTimeText      = $startTimeText
                meetingIds         = @(Get-RbaMeetingIdsFromLogLines -Lines $blockLines)
                lines              = $blockLines
            })
    }

    $lastStartIndex = $startIndexes[-1]
    if ($lastStartIndex -lt ($Lines.Count - 1)) {
        $partialLines = @($Lines[($lastStartIndex + 1)..($Lines.Count - 1)])
        if (@($partialLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            $blocks.Add([PSCustomObject]@{
                    sequence           = $blocks.Count + 1
                    startLine          = $lastStartIndex + 2
                    endLine            = $Lines.Count
                    startBoundaryFound = $false
                    boundaryStatus     = "MissingStartBoundary"
                    startMarker        = $null
                    startTimeText      = $null
                    meetingIds         = @(Get-RbaMeetingIdsFromLogLines -Lines $partialLines)
                    lines              = $partialLines
                })
        }
    }

    return $blocks.ToArray()
}

function Test-RbaLogLinesContainText {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines,

        [Parameter(Mandatory)]
        [string]$Text
    )

    foreach ($line in $Lines) {
        if ($line.IndexOf($Text, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Test-RbaLogLinesContainSubject {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines,

        [Parameter(Mandatory)]
        [string]$Text
    )

    foreach ($line in $Lines) {
        $subjectText = $null
        if ($line -match '(?i)\bReceived Request from:.*?\bsubject\s+(?<Subject>.+)$') {
            $subjectText = $Matches['Subject']
        } elseif ($line -match '(?i)(?:^|,\s*)Subject\s*:\s*(?<Subject>.+)$') {
            $subjectText = $Matches['Subject']
        }

        if ($null -ne $subjectText -and
            $subjectText.IndexOf($Text, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Get-RbaLogLineTimeText {
    param(
        [AllowNull()]
        [string]$Line
    )

    if (-not [string]::IsNullOrWhiteSpace($Line) -and $Line -match '^(?<TimeText>[^,]+),') {
        return $Matches['TimeText'].Trim()
    }
    return $null
}

function Get-RbaTargetedMeetingDetails {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )

    $lines = @($Events | ForEach-Object { @($_.rawLog) })
    if ($lines.Count -eq 0) {
        return [PSCustomObject]@{
            firstLogTimeText      = $null
            lastLogTimeText       = $null
            lastUpdateTimeText    = $null
            recurrenceStatus      = "Unknown"
            policyResult          = "Unknown"
            disposition           = "Unknown"
            forwardedToDelegates  = $false
            delegateMessageCount  = $null
            tentativeResponseSent = $false
        }
    }

    $timestampedLines = @($lines | Where-Object { $_ -match '^[^,]+,' })
    $initialRequestLines = @($lines | Where-Object { $_ -match '(?i)\bBegin ProcessRequest\s+Goid:' })
    $updateLines = @($lines | Where-Object { $_ -match '(?i)\b(?:Begin|End) ProcessUpdateRequest\s+Goid:' })
    $meetingActivityLines = @($timestampedLines | Where-Object {
            $_ -match '(?i)\b(?:Begin|End) Process(?:Update)?Request\s+Goid:' -or
            $_ -match '(?i)Action:(?:Accept|Decline|Tentative)' -or
            $_ -match '(?i)meeting cancellation|Cancellation processing completed' -or
            $_ -match '(?i)\bEND - Sending the .*response to organizer\.' -or
            $_ -match '(?i)\bPostProcessing completed on '
        })
    $recurringDetected = @($lines | Where-Object {
            $_ -match '(?i)\bIsRecurring\s*[:=]\s*True\b' -or
            $_ -match '(?i)\bRecurring meeting request\b' -or
            $_ -match '(?i)Recurrence ends is past the booking window\. Meeting will be declined\.' -or
            $_ -match '(?i)Truncating meeting recurrence end window'
        }).Count -gt 0
    $notRecurringDetected = @($lines | Where-Object {
            $_ -match '(?i)\bIsRecurring\s*[:=]\s*False\b' -or
            $_ -match '(?i)\bNon-recurring meeting request\b'
        }).Count -gt 0
    $policyResults = @($Events | ForEach-Object { $_.policyResult } |
            Where-Object { $_ -ne "Unknown" } | Sort-Object -Unique)
    $dispositions = @($Events | ForEach-Object { $_.disposition } |
            Where-Object { $_ -ne "Unknown" } | Sort-Object -Unique)
    $delegateMessageCounts = @($Events | ForEach-Object { $_.delegateMessageCount } |
            Where-Object { $null -ne $_ })

    return [PSCustomObject]@{
        firstLogTimeText      = Get-RbaLogLineTimeText -Line $(if ($initialRequestLines.Count -gt 0) { $initialRequestLines[-1] } elseif ($timestampedLines.Count -gt 0) { $timestampedLines[-1] } else { $null })
        lastLogTimeText       = Get-RbaLogLineTimeText -Line $(if ($meetingActivityLines.Count -gt 0) { $meetingActivityLines[0] } elseif ($timestampedLines.Count -gt 0) { $timestampedLines[0] } else { $null })
        lastUpdateTimeText    = Get-RbaLogLineTimeText -Line $(if ($updateLines.Count -gt 0) { $updateLines[0] } else { $null })
        recurrenceStatus      = $(if ($recurringDetected) { "Recurring" } elseif ($notRecurringDetected) { "NotRecurring" } else { "Unknown" })
        policyResult          = $(if ($policyResults.Count -eq 1) { $policyResults[0] } elseif ($policyResults.Count -gt 1) { "Mixed" } else { "Unknown" })
        disposition           = $(if ($dispositions.Count -eq 1) { $dispositions[0] } elseif ($dispositions.Count -gt 1) { "Multiple" } else { "Unknown" })
        forwardedToDelegates  = @($Events | Where-Object { $_.delegateReferralDetected }).Count -gt 0
        delegateMessageCount  = $(if ($delegateMessageCounts.Count -gt 0) { ($delegateMessageCounts | Measure-Object -Sum).Sum } else { $null })
        tentativeResponseSent = @($Events | Where-Object { $_.tentativeResponseSent }).Count -gt 0
    }
}

function Get-RbaTargetedMeetingSummaries {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$MeetingIds,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )

    return @($MeetingIds | ForEach-Object {
            $currentMeetingId = $_
            $meetingEvents = @($Events | Where-Object { @($_.meetingIds) -contains $currentMeetingId })
            $details = Get-RbaTargetedMeetingDetails -Events $meetingEvents
            [PSCustomObject]@{
                meetingId             = $currentMeetingId
                eventCount            = $meetingEvents.Count
                firstLogTimeText      = $details.firstLogTimeText
                lastLogTimeText       = $details.lastLogTimeText
                lastUpdateTimeText    = $details.lastUpdateTimeText
                recurrenceStatus      = $details.recurrenceStatus
                policyResult          = $details.policyResult
                disposition           = $details.disposition
                tentativeResponseSent = $details.tentativeResponseSent
                forwardedToDelegates  = $details.forwardedToDelegates
                delegateMessageCount  = $details.delegateMessageCount
                acceptCount           = @($meetingEvents | Where-Object { $_.actions -contains "Accept" }).Count
                tentativeCount        = @($meetingEvents | Where-Object { $_.actions -contains "Tentative" }).Count
                declineCount          = @($meetingEvents | Where-Object { $_.actions -contains "Decline" }).Count
                updateCount           = @($meetingEvents | Where-Object { $_.updateDetected }).Count
                cancellationCount     = @($meetingEvents | Where-Object { $_.cancellationDetected }).Count
                delegateReferralCount = @($meetingEvents | Where-Object { $_.delegateReferralDetected }).Count
                eventSequences        = @($meetingEvents.sequence)
            }
        })
}

function Get-RbaTargetedLogBlockObject {
    param(
        [Parameter(Mandatory)]
        [object]$Block,

        [Parameter(Mandatory)]
        [bool]$SubjectMatched
    )

    $actions = @($Block.lines | ForEach-Object {
            foreach ($match in [regex]::Matches($_, '(?i)Action:(?<Action>Accept|Decline|Tentative)')) {
                $match.Groups['Action'].Value
            }
        } | Sort-Object -Unique)
    $evaluationResults = @($Block.lines | ForEach-Object {
            foreach ($match in [regex]::Matches($_, '(?i)Meeting request evaluate returns result\s+(?<Action>Accept|Decline|Tentative)')) {
                $match.Groups['Action'].Value
            }
        } | Sort-Object -Unique)
    $dispositions = @($actions + $evaluationResults | Sort-Object -Unique)
    $delegateMessageCounts = @($Block.lines | ForEach-Object {
            foreach ($match in [regex]::Matches($_, '(?i)Sending approval messages to\s+(?<Count>\d+)\s+delegates\.')) {
                [int]$match.Groups['Count'].Value
            }
        })
    $inPolicyDetected = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Defaulting to in policy.'
    $outOfPolicyDetected = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Not in policy.'

    return [PSCustomObject]@{
        sequence                   = $Block.sequence
        startLine                  = $Block.startLine
        endLine                    = $Block.endLine
        startBoundaryFound         = $Block.startBoundaryFound
        boundaryStatus             = $Block.boundaryStatus
        startMarker                = $Block.startMarker
        startTimeText              = $Block.startTimeText
        eventTimeText              = $Block.startTimeText
        rawLogOrder                = "NewestFirst"
        chronologicalReadDirection = "BottomToTop"
        subjectMatched             = $SubjectMatched
        meetingIds                 = @($Block.meetingIds)
        actions                    = $actions
        policyResult               = $(if ($inPolicyDetected -and $outOfPolicyDetected) { "Mixed" } elseif ($inPolicyDetected) { "InPolicy" } elseif ($outOfPolicyDetected) { "OutOfPolicy" } else { "Unknown" })
        disposition                = $(if ($dispositions.Count -eq 1) { $dispositions[0] } elseif ($dispositions.Count -gt 1) { "Multiple" } else { "Unknown" })
        updateDetected             = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Begin ProcessUpdateRequest'
        cancellationDetected       = Test-RbaLogLinesContainText -Lines $Block.lines -Text "It's a meeting cancellation."
        delegateReferralDetected   = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Forwarding Request To Delegates'
        delegateMessageCount       = $(if ($delegateMessageCounts.Count -gt 0) { ($delegateMessageCounts | Measure-Object -Sum).Sum } else { $null })
        tentativeResponseSent      = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'END - Sending the tentatively acceptance response to organizer.'
        externalProcessingSkipped  = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Skipping processing because user settings for processing external items is false.'
        horizonDeclineDetected     = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Recurrence ends is past the booking window. Meeting will be declined.'
        recurrenceTruncateDetected = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Truncating meeting recurrence end window'
        rawLog                     = @($Block.lines)
    }
}

function Get-RbaMeetingLogSearchObject {
    $normalizedRequestedMeetingId = if (-not [string]::IsNullOrWhiteSpace($MeetingId)) {
        ConvertTo-RbaNormalizedMeetingId -Value $MeetingId
    } else { $null }
    $searchType = if (-not [string]::IsNullOrWhiteSpace($Subject)) {
        "Subject"
    } elseif (-not [string]::IsNullOrWhiteSpace($normalizedRequestedMeetingId)) {
        "MeetingId"
    } else { "None" }

    if ($searchType -eq "None") {
        return [PSCustomObject]@{
            searchType                       = $searchType
            searchSubject                    = $null
            searchMeetingId                  = $null
            status                           = "NotRequested"
            sourceOrder                      = "NewestFirst"
            eventOrder                       = "NewestFirst"
            rawLogChronologicalReadDirection = "BottomToTop"
            subjectMatchCount                = 0
            meetingIds                       = @()
            eventCount                       = 0
            acceptCount                      = 0
            tentativeCount                   = 0
            declineCount                     = 0
            updateCount                      = 0
            cancellationCount                = 0
            delegateReferralCount            = 0
            externalSkippedCount             = 0
            horizonDeclineCount              = 0
            recurrenceTruncateCount          = 0
            firstLogTimeText                 = $null
            lastLogTimeText                  = $null
            lastUpdateTimeText               = $null
            recurrenceStatus                 = "Unknown"
            policyResult                     = "Unknown"
            disposition                      = "Unknown"
            forwardedToDelegates             = $false
            delegateMessageCount             = $null
            tentativeResponseSent            = $false
            meetings                         = @()
            events                           = @()
        }
    }

    if ($script:collectorStatuses["RbaLog"].status -ne "Success") {
        return [PSCustomObject]@{
            searchType                       = $searchType
            searchSubject                    = $Subject
            searchMeetingId                  = $normalizedRequestedMeetingId
            status                           = "LogUnavailable"
            sourceOrder                      = "NewestFirst"
            eventOrder                       = "NewestFirst"
            rawLogChronologicalReadDirection = "BottomToTop"
            subjectMatchCount                = 0
            meetingIds                       = @()
            eventCount                       = 0
            acceptCount                      = 0
            tentativeCount                   = 0
            updateCount                      = 0
            cancellationCount                = 0
            declineCount                     = 0
            delegateReferralCount            = 0
            externalSkippedCount             = 0
            horizonDeclineCount              = 0
            recurrenceTruncateCount          = 0
            firstLogTimeText                 = $null
            lastLogTimeText                  = $null
            lastUpdateTimeText               = $null
            recurrenceStatus                 = "Unknown"
            policyResult                     = "Unknown"
            disposition                      = "Unknown"
            forwardedToDelegates             = $false
            delegateMessageCount             = $null
            tentativeResponseSent            = $false
            meetings                         = @()
            events                           = @()
        }
    }

    $blocks = @(Split-RbaLogProcessingBlocks -Lines @($script:RBALog))
    $completeBlocks = @($blocks | Where-Object { $_.startBoundaryFound })
    if ($searchType -eq "MeetingId") {
        $selectedBlocks = @($completeBlocks | Where-Object {
                @($_.meetingIds) -contains $normalizedRequestedMeetingId
            })
        $ambiguousBlockMatch = @($blocks | Where-Object {
                -not $_.startBoundaryFound -and
                @($_.meetingIds) -contains $normalizedRequestedMeetingId
            }).Count -gt 0
        $events = @($selectedBlocks | ForEach-Object {
                Get-RbaTargetedLogBlockObject -Block $_ -SubjectMatched $false
            })
        $meetingDetails = Get-RbaTargetedMeetingDetails -Events $events
        [string[]]$matchedMeetingIds = @()
        [object[]]$meetingSummaries = @()
        if ($events.Count -gt 0) {
            $matchedMeetingIds = @($normalizedRequestedMeetingId)
            $meetingSummaries = @(Get-RbaTargetedMeetingSummaries -MeetingIds $matchedMeetingIds -Events $events)
        }

        return [PSCustomObject]@{
            searchType                       = $searchType
            searchSubject                    = $null
            searchMeetingId                  = $normalizedRequestedMeetingId
            status                           = $(if ($events.Count -gt 0) { "Found" } elseif ($ambiguousBlockMatch) { "AmbiguousBoundary" } else { "NotFound" })
            sourceOrder                      = "NewestFirst"
            eventOrder                       = "NewestFirst"
            rawLogChronologicalReadDirection = "BottomToTop"
            subjectMatchCount                = 0
            meetingIds                       = $matchedMeetingIds
            eventCount                       = $events.Count
            acceptCount                      = @($events | Where-Object { $_.actions -contains "Accept" }).Count
            tentativeCount                   = @($events | Where-Object { $_.actions -contains "Tentative" }).Count
            declineCount                     = @($events | Where-Object { $_.actions -contains "Decline" }).Count
            updateCount                      = @($events | Where-Object { $_.updateDetected }).Count
            cancellationCount                = @($events | Where-Object { $_.cancellationDetected }).Count
            delegateReferralCount            = @($events | Where-Object { $_.delegateReferralDetected }).Count
            externalSkippedCount             = @($events | Where-Object { $_.externalProcessingSkipped }).Count
            horizonDeclineCount              = @($events | Where-Object { $_.horizonDeclineDetected }).Count
            recurrenceTruncateCount          = @($events | Where-Object { $_.recurrenceTruncateDetected }).Count
            firstLogTimeText                 = $meetingDetails.firstLogTimeText
            lastLogTimeText                  = $meetingDetails.lastLogTimeText
            lastUpdateTimeText               = $meetingDetails.lastUpdateTimeText
            recurrenceStatus                 = $meetingDetails.recurrenceStatus
            policyResult                     = $meetingDetails.policyResult
            disposition                      = $meetingDetails.disposition
            forwardedToDelegates             = $meetingDetails.forwardedToDelegates
            delegateMessageCount             = $meetingDetails.delegateMessageCount
            tentativeResponseSent            = $meetingDetails.tentativeResponseSent
            meetings                         = $meetingSummaries
            events                           = $events
        }
    }

    $subjectBlocks = @($completeBlocks | Where-Object {
            Test-RbaLogLinesContainSubject -Lines $_.lines -Text $Subject
        })
    $ambiguousSubjectBlocks = @($blocks | Where-Object {
            -not $_.startBoundaryFound -and
            (Test-RbaLogLinesContainSubject -Lines $_.lines -Text $Subject)
        })
    if ($subjectBlocks.Count -eq 0) {
        return [PSCustomObject]@{
            searchType                       = $searchType
            searchSubject                    = $Subject
            searchMeetingId                  = $null
            status                           = $(if ($ambiguousSubjectBlocks.Count -gt 0) { "AmbiguousBoundary" } else { "NotFound" })
            sourceOrder                      = "NewestFirst"
            eventOrder                       = "NewestFirst"
            rawLogChronologicalReadDirection = "BottomToTop"
            subjectMatchCount                = $ambiguousSubjectBlocks.Count
            meetingIds                       = @()
            eventCount                       = 0
            acceptCount                      = 0
            tentativeCount                   = 0
            updateCount                      = 0
            cancellationCount                = 0
            declineCount                     = 0
            delegateReferralCount            = 0
            externalSkippedCount             = 0
            horizonDeclineCount              = 0
            recurrenceTruncateCount          = 0
            firstLogTimeText                 = $null
            lastLogTimeText                  = $null
            lastUpdateTimeText               = $null
            recurrenceStatus                 = "Unknown"
            policyResult                     = "Unknown"
            disposition                      = "Unknown"
            forwardedToDelegates             = $false
            delegateMessageCount             = $null
            tentativeResponseSent            = $false
            meetings                         = @()
            events                           = @()
        }
    }

    $meetingIds = @($subjectBlocks | ForEach-Object {
            @($_.meetingIds) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        } | Sort-Object -Unique)
    $selectedBlocks = if ($meetingIds.Count -gt 0) {
        @($completeBlocks | Where-Object {
                $blockMeetingIds = @($_.meetingIds)
                $blockMatches = $false
                foreach ($resolvedMeetingId in $meetingIds) {
                    if ($blockMeetingIds -contains $resolvedMeetingId) {
                        $blockMatches = $true
                        break
                    }
                }
                $blockMatches
            })
    } else {
        $subjectBlocks
    }

    $events = @($selectedBlocks | ForEach-Object {
            Get-RbaTargetedLogBlockObject -Block $_ `
                -SubjectMatched (Test-RbaLogLinesContainSubject -Lines $_.lines -Text $Subject)
        })
    $status = if ($meetingIds.Count -gt 0) { "Found" } else { "FoundWithoutMeetingId" }
    $meetingDetails = Get-RbaTargetedMeetingDetails -Events $events
    $meetingSummaries = @(Get-RbaTargetedMeetingSummaries -MeetingIds $meetingIds -Events $events)

    return [PSCustomObject]@{
        searchType                       = $searchType
        searchSubject                    = $Subject
        searchMeetingId                  = $null
        status                           = $status
        sourceOrder                      = "NewestFirst"
        eventOrder                       = "NewestFirst"
        rawLogChronologicalReadDirection = "BottomToTop"
        subjectMatchCount                = $subjectBlocks.Count
        meetingIds                       = $meetingIds
        eventCount                       = $events.Count
        acceptCount                      = @($events | Where-Object { $_.actions -contains "Accept" }).Count
        tentativeCount                   = @($events | Where-Object { $_.actions -contains "Tentative" }).Count
        declineCount                     = @($events | Where-Object { $_.actions -contains "Decline" }).Count
        updateCount                      = @($events | Where-Object { $_.updateDetected }).Count
        cancellationCount                = @($events | Where-Object { $_.cancellationDetected }).Count
        delegateReferralCount            = @($events | Where-Object { $_.delegateReferralDetected }).Count
        externalSkippedCount             = @($events | Where-Object { $_.externalProcessingSkipped }).Count
        horizonDeclineCount              = @($events | Where-Object { $_.horizonDeclineDetected }).Count
        recurrenceTruncateCount          = @($events | Where-Object { $_.recurrenceTruncateDetected }).Count
        firstLogTimeText                 = $meetingDetails.firstLogTimeText
        lastLogTimeText                  = $meetingDetails.lastLogTimeText
        lastUpdateTimeText               = $meetingDetails.lastUpdateTimeText
        recurrenceStatus                 = $meetingDetails.recurrenceStatus
        policyResult                     = $meetingDetails.policyResult
        disposition                      = $meetingDetails.disposition
        forwardedToDelegates             = $meetingDetails.forwardedToDelegates
        delegateMessageCount             = $meetingDetails.delegateMessageCount
        tentativeResponseSent            = $meetingDetails.tentativeResponseSent
        meetings                         = $meetingSummaries
        events                           = $events
    }
}

function Write-RbaTargetedMeetingSummary {
    param(
        [Parameter(Mandatory)]
        [object]$MeetingSummary,

        [string]$Indent = "  "
    )

    Write-Host "$($Indent)Meeting ID                 $($MeetingSummary.meetingId)"
    Write-Host "$($Indent)Correlated events          $($MeetingSummary.eventCount)"
    Write-Host "$($Indent)First meeting log          $($MeetingSummary.firstLogTimeText)"
    Write-Host "$($Indent)Latest meeting log         $($MeetingSummary.lastLogTimeText)"
    Write-Host "$($Indent)Last meeting update        $(if ($null -ne $MeetingSummary.lastUpdateTimeText) { $MeetingSummary.lastUpdateTimeText } else { '[None found]' })"
    Write-Host "$($Indent)Recurrence                 $($MeetingSummary.recurrenceStatus)"
    Write-Host "$($Indent)Policy result              $(switch ($MeetingSummary.policyResult) { 'InPolicy' { 'In policy' } 'OutOfPolicy' { 'Out of policy' } default { $MeetingSummary.policyResult } })"
    Write-Host "$($Indent)Disposition                $(switch ($MeetingSummary.disposition) { 'Accept' { 'Accepted' } 'Tentative' { 'Tentatively accepted' } 'Decline' { 'Declined' } default { $MeetingSummary.disposition } })"
    Write-Host "$($Indent)Tentative response sent    $(if ($MeetingSummary.tentativeResponseSent) { 'Yes' } else { 'No' })"
    Write-Host "$($Indent)Forwarded to delegates     $(if ($MeetingSummary.forwardedToDelegates) { 'Yes' } else { 'No' })"
    if ($null -ne $MeetingSummary.delegateMessageCount) {
        Write-Host "$($Indent)Delegate approval messages $($MeetingSummary.delegateMessageCount)"
    }
    Write-Host "$($Indent)Actions                    Accept=$($MeetingSummary.acceptCount), Tentative=$($MeetingSummary.tentativeCount), Decline=$($MeetingSummary.declineCount)"
    Write-Host "$($Indent)Updates / cancellations    $($MeetingSummary.updateCount) / $($MeetingSummary.cancellationCount)"
}

function Write-RbaLogSummary {
    Write-RbaDashLineBox @("RBA Log Summary") -Color Blue -DashChar =

    if ($script:collectorStatuses["RbaLog"].status -ne "Success") {
        Write-Warning "RBA Log summary could not be evaluated because the log is unavailable."
        return
    }

    if ($script:RBALog.count -gt 1) {
        $Starts = $script:RBALog | Select-String -Pattern "START -"
        $FirstDate = "[Unknown]"
        $LastDate = "[Unknown]"

        if ($starts.count -gt 1) {
            $LastDate = ($Starts[0] -split ",")[0].Trim()
            $FirstDate = ($starts[$($Starts.count) -1 ] -split ",")[0].Trim()
        }

        $AcceptLogs = $script:RBALog | Select-String -Pattern "Action:Accept"
        $DeclineLogs = $script:RBALog | Select-String -Pattern "Action:Decline"
        $TentativeLogs = $script:RBALog | Select-String -Pattern "Action:Tentative"
        $UpdatedLogs = $script:RBALog | Select-String -Pattern "Begin ProcessUpdateRequest"
        $SkippedExternal = $script:RBALog | Select-String -Pattern "Skipping processing because user settings for processing external items is false."
        $DelegateReferrals = $script:RBALog | Select-String -Pattern "Forwarding Request To Delegates"
        $NonMeetingRequests = $script:RBALog | Select-String -Pattern "Item is not a meeting request"
        $Cancellations = $script:RBALog | Select-String -Pattern "It's a meeting cancellation."

        Write-Host "RBA log activity for [$Identity]:"
        Write-Host ("  {0,-26} {1,6}" -f "Log entries", $script:RBALog.count)
        Write-Host ("  {0,-26} {1,6}" -f "Processed events", $Starts.count)
        Write-Host ("  {0,-26} {1,6}" -f "Accepted", $AcceptLogs.count)
        Write-Host ("  {0,-26} {1,6}" -f "Tentatively accepted", $TentativeLogs.count)
        Write-Host ("  {0,-26} {1,6}" -f "Declined", $DeclineLogs.count)
        Write-Host ("  {0,-26} {1,6}" -f "Updates", $UpdatedLogs.count)
        Write-Host ("  {0,-26} {1,6}" -f "Cancellations", $Cancellations.count)
        Write-Host ("  {0,-26} {1,6}" -f "Delegate referrals", $DelegateReferrals.count)
        Write-Host ("  {0,-26} {1,6}" -f "Non-meeting requests", $NonMeetingRequests.count)
        Write-Host ("  {0,-26} {1,6}" -f "Skipped external meetings", $SkippedExternal.count)
        Write-Host "  Date range                 $FirstDate to $LastDate"

        if ($AcceptLogs.count -ne 0) {
            $LastAccept = ($AcceptLogs[0] -split ",")[0].Trim()
            Write-Host "  Last accepted              $LastAccept"
        }

        if ($TentativeLogs.count -ne 0) {
            $LastTentative = ($TentativeLogs[0] -split ",")[0].Trim()
            Write-Host "  Last tentatively accepted  $LastTentative"
        }

        if ($DeclineLogs.count -ne 0) {
            $LastDecline = ($DeclineLogs[0] -split ",")[0].Trim()
            Write-Host "  Last declined              $LastDecline"
        }

        if ($UpdatedLogs.count -ne 0) {
            $LastUpdated = ($UpdatedLogs[0] -split ",")[0].Trim()
            Write-Host "  Last updated               $LastUpdated"
        }

        if ($DelegateReferrals.count -ne 0) {
            $LastDelegateReferral = ($DelegateReferrals[0] -split ",")[0].Trim()
            Write-Host "  Last delegate referral     $LastDelegateReferral"
        }

        if ($NonMeetingRequests.count -ne 0) {
            $LastNonMeetingRequest = ($NonMeetingRequests[0] -split ",")[0].Trim()
            Write-Host "  Last non-meeting request   $LastNonMeetingRequest"
        }

        if ($script:MeetingLogSearch.status -ne "NotRequested") {
            Write-Host
            Write-Host -ForegroundColor DarkBlue "Targeted meeting search:"
            if ($script:MeetingLogSearch.searchType -eq "Subject") {
                Write-Host "  Subject                    [$($script:MeetingLogSearch.searchSubject)]"
                Write-Host "  Subject matches            $($script:MeetingLogSearch.subjectMatchCount)"
            } else {
                Write-Host "  Requested meeting ID       $($script:MeetingLogSearch.searchMeetingId)"
            }
            Write-Host "  Search result              $($script:MeetingLogSearch.status)"
            Write-Host "  Correlated events (total)  $($script:MeetingLogSearch.eventCount)"
            if (@($script:MeetingLogSearch.meetingIds).Count -gt 0) {
                $meetingSummaries = @($script:MeetingLogSearch.meetings)
                if ($meetingSummaries.Count -gt 1) {
                    Write-Warning "The subject matched $($meetingSummaries.Count) meeting IDs. Results are separated below; rerun with -MeetingId to investigate one meeting."
                    for ($meetingIndex = 0; $meetingIndex -lt $meetingSummaries.Count; $meetingIndex++) {
                        Write-Host
                        Write-Host -ForegroundColor DarkBlue "  Meeting $($meetingIndex + 1) of $($meetingSummaries.Count):"
                        Write-RbaTargetedMeetingSummary -MeetingSummary $meetingSummaries[$meetingIndex] -Indent "    "
                    }
                } else {
                    Write-RbaTargetedMeetingSummary -MeetingSummary $meetingSummaries[0]
                }
                if ($script:MeetingLogSearch.searchType -eq "Subject") {
                    Write-Host "  Subject discovery completed; subsequent correlation uses the meeting ID(s)."
                }
            } elseif ($script:MeetingLogSearch.status -eq "NotFound") {
                Write-Warning "The requested meeting was not found in the retained RBA log. Older events may have rolled off."
            } elseif ($script:MeetingLogSearch.status -eq "FoundWithoutMeetingId") {
                Write-Warning "The subject was found, but no meeting ID could be extracted for correlation."
            } elseif ($script:MeetingLogSearch.status -eq "AmbiguousBoundary") {
                Write-Warning "The requested meeting text was found only in RBA log content without an exact processing boundary. No raw targeted evidence was exported."
            }
        }

        if ($SkippedExternal.count -ne 0) {
            if ($SkippedExternal.Count -lt 3) {
                Write-Host -ForegroundColor Yellow "Warning: $($SkippedExternal.count) external meetings were skipped because external-item processing is disabled."
            } else {
                Write-Host -ForegroundColor Red "Warning: $($SkippedExternal.count) external meetings were skipped because external-item processing is disabled."
                Write-Host -ForegroundColor Red "Many skipped external meetings may indicate a Transport configuration issue. Validate that internal meetings are not marked as external."
            }
        }

        $script:RbaLogFilename = "RBA-Logs_$outputFileStem`_$runTimestamp.txt"
        $script:RBALog.replace(", Entry Action: Message, LogComment", "").replace("Mailbox: ", "") |
            Out-File -FilePath $script:RbaLogFilename -Encoding utf8
        Write-Host -ForegroundColor Cyan "`r`nRBA logs saved as [$script:RbaLogFilename] in the current directory."

        Write-RbaNextSteps
    } else {
        Write-Warning "No RBA Logs found.  Send a test meeting invite to the room and try again if this is a newly created room mailbox."
    }
}
