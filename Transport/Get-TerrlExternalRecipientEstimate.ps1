# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore TERRL Terrl pscustomobject microsoftexchange

<#
.SYNOPSIS
    Measure a tenant's Tenant External Recipient Rate Limit (TERRL) consumption over a 24-hour
    window using Get-MessageTraceV2, and rank the senders/domains contributing most.

.DESCRIPTION
    The Tenant External Recipient Rate Limit (TERRL) limits how many external recipients an
    Exchange Online tenant can send to during a rolling 24-hour period. An external recipient is
    an address whose domain is not an accepted domain in the tenant. The tenant's limit is based
    on its Exchange Online license count.

    This script uses Get-MessageTraceV2 data to estimate TERRL usage and identify the senders and
    recipient domains contributing most to it. It can query message trace directly, accept trace
    rows from the pipeline, or analyze a previously exported CSV.

    Message trace does not contain every property used by TERRL enforcement, so the result is an
    estimate and may be higher than the live count. Use Get-LimitsEnforcementStatus for the
    current enforcement status and observed value.

.PARAMETER StartDate
    Start of the window. Default: EndDate - 24h.

.PARAMETER EndDate
    End of the window. Default: now (local). Get-MessageTraceV2 filters on Received time.

.PARAMETER AcceptedDomain
    The tenant's accepted (internal) SMTP domains. A recipient is EXTERNAL when its domain is not
    in this list. If omitted, the script calls Get-AcceptedDomain from the active EXO session.

.PARAMETER ExcludeNullSender
    Exclude NDR/DSN/system mail identified by a null/blank ("<>") or postmaster/mailer-daemon
    sender. Default $true (approximates the MessageIsNdr filter).

.PARAMETER JournalRecipient
    Additional EXO journal-rule destination addresses. The script also discovers enabled Exchange
    Online journal rules with Get-JournalRule. A row is classified as an EXO journal report only
    when the sender matches the tenant's journal-report sender configuration and the recipient is
    a configured destination.
    On-premises-generated journal reports are not detectable from EXO journal-rule configuration.

.PARAMETER JournalReportSender
    Additional EXO journal-report envelope sender addresses. The script normally discovers the
    sender from Get-TransportConfig.JournalingReportNdrTo. If that setting is empty, it follows
    Transport behavior and constructs the Microsoft Exchange Recipient address from the fixed
    MicrosoftExchange329e... local-part and the tenant's default accepted domain.

.PARAMETER PageSize
    Get-MessageTraceV2 -ResultSize per request. Default and maximum 5000. Use 1 to exercise
    request pacing.

.PARAMETER TopSenders
    Number of top contributing senders/domains to return. Default 25.

.PARAMETER CompareToEnforcementStatus
    Also call Get-LimitsEnforcementStatus and print the live ObservedValue/Threshold next to the
    script's estimate.

.PARAMETER InputObject
    Get-MessageTraceV2 rows received from the PowerShell pipeline. When rows are piped in, the
    script measures only those rows and does not perform its own live trace query.

.PARAMETER MessageTraceCsv
    Path to a CSV previously exported from a trace run. Bypasses the live call.

.PARAMETER CsvPath
    Optional path to export the top-sender table.

.PARAMETER DefineFunctionsOnly
    Load the functions without running the live report (for dot-sourcing in tests).

.EXAMPLE
    .\Get-TerrlExternalRecipientEstimate.ps1 -AcceptedDomain "contoso.com" -CompareToEnforcementStatus

    Queries the previous 24 hours and compares the estimate with the live enforcement status.

.EXAMPLE
    .\Get-TerrlExternalRecipientEstimate.ps1 -MessageTraceCsv ".\trace.csv" -AcceptedDomain "contoso.com"

    Analyzes a previously exported message trace without querying message trace.

.EXAMPLE
    Get-MessageTraceV2 -StartDate (Get-Date).AddHours(-4) -EndDate (Get-Date) -ResultSize 5000 |
        .\Get-TerrlExternalRecipientEstimate.ps1 -AcceptedDomain "contoso.com"

    Analyzes message trace rows supplied through the pipeline.

.NOTES
    TERRL overview:
    https://techcommunity.microsoft.com/blog/exchange/introducing-exchange-online-tenant-outbound-email-limits/4372797
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [Parameter()]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [datetime]$StartDate,

    [Parameter()]
    [string[]]$AcceptedDomain,

    [Parameter()]
    [bool]$ExcludeNullSender = $true,

    [Parameter()]
    [string[]]$JournalRecipient,

    [Parameter()]
    [string[]]$JournalReportSender,

    [Parameter()]
    [ValidateRange(1, 5000)]
    [int]$PageSize = 5000,

    [Parameter()]
    [ValidateRange(1, 2147483647)]
    [int]$TopSenders = 25,

    [Parameter()]
    [switch]$CompareToEnforcementStatus,

    [Parameter(ValueFromPipeline)]
    [object]$InputObject,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MessageTraceCsv,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath,

    [Parameter()]
    [switch]$DefineFunctionsOnly
)

begin {
    $pipelineRows = [System.Collections.Generic.List[object]]::new()
    $pipelineWasConnected = $MyInvocation.ExpectingInput

    # ==================================================================================================
    # Pure helpers (testable)
    # ==================================================================================================

    function Get-TerrlAddressDomain {
        <# Returns the lower-cased domain of an SMTP address, or $null if unparsable / null sender. #>
        [OutputType([string])]
        param([string]$Address)
        if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
        $a = $Address.Trim().Trim('<', '>').Trim()
        if ([string]::IsNullOrWhiteSpace($a)) { return $null }
        $at = $a.LastIndexOf('@')
        if ($at -lt 0 -or $at -eq ($a.Length - 1)) { return $null }
        return $a.Substring($at + 1).Trim().ToLowerInvariant()
    }

    function ConvertTo-TerrlDomainSet {
        <# Builds a case-insensitive HashSet of bare domains from a list. #>
        [OutputType([System.Collections.Generic.HashSet[string]])]
        param([string[]]$Domain)
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($d in $Domain) {
            if (-not [string]::IsNullOrWhiteSpace($d)) {
                [void]$set.Add($d.Trim().TrimStart('@').ToLowerInvariant())
            }
        }
        return $set
    }

    function Test-TerrlInternalRecipientDomain {
        <# True when the recipient domain is internal (accepted), i.e. NOT counted by TERRL. #>
        [OutputType([bool])]
        param(
            [string]$Domain,
            [System.Collections.Generic.HashSet[string]]$AcceptedSet
        )
        if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }
        $d = $Domain.Trim().ToLowerInvariant()
        if ($AcceptedSet -and $AcceptedSet.Contains($d)) { return $true }
        return $false
    }

    function Test-TerrlNullSender {
        [OutputType([bool])]
        param([string]$SenderAddress)
        if ([string]::IsNullOrWhiteSpace($SenderAddress)) { return $true }
        $s = $SenderAddress.Trim()
        return ($s -eq '<>' -or $s -eq '<' -or $s -eq '>')
    }

    function Test-TerrlSystemSender {
        [OutputType([bool])]
        param([string]$SenderAddress)
        if ([string]::IsNullOrWhiteSpace($SenderAddress)) { return $false }
        $s = $SenderAddress.Trim().Trim('<', '>').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($s)) { return $false }
        $local = if ($s.Contains('@')) { $s.Substring(0, $s.IndexOf('@')) } else { $s }
        if ($local -eq 'postmaster' -or $local -eq 'mailer-daemon') { return $true }
        # Well-known Exchange system mailbox used for system-generated mail.
        if ($s.StartsWith('microsoftexchange329e71ec88ae4615bbc36ab6ce41109e@')) { return $true }
        return $false
    }

    function Test-TerrlExchangeOnlineJournalReport {
        [OutputType([bool])]
        param(
            [string]$SenderAddress,
            [string]$Recipient,
            [System.Collections.Generic.HashSet[string]]$JournalSet,
            [System.Collections.Generic.HashSet[string]]$JournalSenderSet
        )

        if ($null -eq $JournalSet -or $JournalSet.Count -eq 0 -or
            $null -eq $JournalSenderSet -or $JournalSenderSet.Count -eq 0) {
            return $false
        }
        if ([string]::IsNullOrWhiteSpace($SenderAddress) -or
            [string]::IsNullOrWhiteSpace($Recipient)) {
            return $false
        }

        $normalizedSender = $SenderAddress.Trim().Trim('<', '>').ToLowerInvariant()
        $normalizedRecipient = $Recipient.Trim().Trim('<', '>').ToLowerInvariant()
        $senderLocalPart = if ($normalizedSender.Contains('@')) {
            $normalizedSender.Substring(0, $normalizedSender.IndexOf('@'))
        } else {
            $normalizedSender
        }
        $isMicrosoftExchangeRecipient =
        $senderLocalPart -eq 'microsoftexchange329e71ec88ae4615bbc36ab6ce41109e'

        return (
            ($JournalSenderSet.Contains($normalizedSender) -or $isMicrosoftExchangeRecipient) -and
            $JournalSet.Contains($normalizedRecipient)
        )
    }

    # ==================================================================================================
    # Core classifier (PURE -- this is the primary unit-test surface)
    # ==================================================================================================

    function Measure-TerrlFromTraceRows {
        <#
    .SYNOPSIS
        Classify Get-MessageTraceV2 rows against the TERRL rules and return a structured estimate.
    .OUTPUTS
        pscustomobject with ExternalRecipientsCounted, DistinctExternalRecipients,
        DistinctOutboundMessages, AcceptedRecipientRows, TopSenders, TopRecipientDomains,
        and Exclusions.
    #>
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param(
            [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
            [Parameter(Mandatory)][string[]]$AcceptedDomain,
            [bool]$ExcludeNullSender = $true,
            [string[]]$JournalRecipient,
            [string[]]$JournalReportSender,
            [int]$TopSenders = 25
        )

        $acceptedSet = ConvertTo-TerrlDomainSet -Domain $AcceptedDomain

        $journalSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($j in $JournalRecipient) { if ($j) { [void]$journalSet.Add($j.Trim().Trim('<', '>').ToLowerInvariant()) } }

        $journalSenderSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($s in $JournalReportSender) { if ($s) { [void]$journalSenderSet.Add($s.Trim().Trim('<', '>').ToLowerInvariant()) } }

        $countedUnitKeys = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $distinctRecipientSet = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $distinctMessageSet = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $senderMessageSet = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $senderRecipientCounts = [System.Collections.Generic.Dictionary[string, int]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $senderMessageCounts = [System.Collections.Generic.Dictionary[string, int]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $domainCounts = [System.Collections.Generic.Dictionary[string, int]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $exclusionCounts = [System.Collections.Generic.Dictionary[string, int]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        $total = 0
        $acceptedRows = 0
        $exchangeOnlineJournalRows = 0

        # This is the only full pass over the trace rows. Classification, deduplication, and all
        # report aggregates are updated here to avoid retaining a second classified-row collection.
        foreach ($r in $Rows) {
            $senderAddress = [string]$r.SenderAddress
            $recipient = [string]$r.RecipientAddress
            $status = [string]$r.Status
            $recipientDomain = Get-TerrlAddressDomain -Address $recipient

            $reason = 'Counted'
            if ($null -eq $recipientDomain) {
                $reason = 'UnparsableRecipient'
            } elseif (Test-TerrlExchangeOnlineJournalReport `
                    -SenderAddress $senderAddress `
                    -Recipient $recipient `
                    -JournalSet $journalSet `
                    -JournalSenderSet $journalSenderSet) {
                $reason = 'ExchangeOnlineJournalReport'            # IsJournal
            } elseif (Test-TerrlInternalRecipientDomain -Domain $recipientDomain -AcceptedSet $acceptedSet) {
                $reason = 'InternalRecipient'                      # THE ONE RULE / IsRoutedOnlyToAcceptedDomains
            } elseif ($status.Trim() -eq 'Expanded') {
                $reason = 'ExpandedDistributionGroup'              # DL placeholder; members have rows
            } elseif ($ExcludeNullSender -and (Test-TerrlNullSender -SenderAddress $senderAddress)) {
                $reason = 'NullSender (NDR/DSN/system)'            # MessageIsNdr
            } elseif (Test-TerrlSystemSender -SenderAddress $senderAddress) {
                $reason = 'SystemSender (NDR/DSN)'
            }

            if ($reason -ne 'Counted') {
                if ($exclusionCounts.ContainsKey($reason)) {
                    $exclusionCounts[$reason]++
                } else {
                    $exclusionCounts[$reason] = 1
                }

                if ($reason -eq 'InternalRecipient') {
                    $acceptedRows++
                } elseif ($reason -eq 'ExchangeOnlineJournalReport') {
                    $exchangeOnlineJournalRows++
                }
                continue
            }

            $messageKey = '{0}|{1}' -f [string]$r.MessageTraceId, [string]$r.MessageId
            $countedUnitKey = '{0}|{1}' -f $messageKey, $recipient
            if (-not $countedUnitKeys.Add($countedUnitKey)) {
                continue
            }

            $total++
            [void]$distinctRecipientSet.Add($recipient)
            [void]$distinctMessageSet.Add($messageKey)

            $senderKey = if ([string]::IsNullOrWhiteSpace($senderAddress)) {
                '(null sender)'
            } else {
                $senderAddress.Trim().ToLowerInvariant()
            }
            if ($senderRecipientCounts.ContainsKey($senderKey)) {
                $senderRecipientCounts[$senderKey]++
            } else {
                $senderRecipientCounts[$senderKey] = 1
                $senderMessageCounts[$senderKey] = 0
            }

            if ($senderMessageSet.Add(('{0}|{1}' -f $senderKey, $messageKey))) {
                $senderMessageCounts[$senderKey]++
            }

            if ($domainCounts.ContainsKey($recipientDomain)) {
                $domainCounts[$recipientDomain]++
            } else {
                $domainCounts[$recipientDomain] = 1
            }
        }

        $senderRanking = @(
            foreach ($senderKey in $senderRecipientCounts.Keys) {
                [pscustomobject]@{
                    Sender             = $senderKey
                    ExternalRecipients = $senderRecipientCounts[$senderKey]
                    Messages           = $senderMessageCounts[$senderKey]
                    PercentOfTotal     = if ($total -gt 0) {
                        [math]::Round(100.0 * $senderRecipientCounts[$senderKey] / $total, 1)
                    } else {
                        0
                    }
                }
            }
        ) | Sort-Object ExternalRecipients -Descending | Select-Object -First $TopSenders

        $domainRanking = @(
            foreach ($domain in $domainCounts.Keys) {
                [pscustomobject]@{
                    RecipientDomain    = $domain
                    ExternalRecipients = $domainCounts[$domain]
                    PercentOfTotal     = if ($total -gt 0) {
                        [math]::Round(100.0 * $domainCounts[$domain] / $total, 1)
                    } else {
                        0
                    }
                }
            }
        ) | Sort-Object ExternalRecipients -Descending | Select-Object -First $TopSenders

        $exclusions = @(
            foreach ($reason in $exclusionCounts.Keys) {
                [pscustomobject]@{
                    Reason        = $reason
                    RecipientRows = $exclusionCounts[$reason]
                }
            }
        ) | Sort-Object RecipientRows -Descending

        [pscustomobject]@{
            TraceRows                  = $Rows.Count
            ExternalRecipientsCounted  = $total
            DistinctExternalRecipients = $distinctRecipientSet.Count
            DistinctOutboundMessages   = $distinctMessageSet.Count
            AcceptedRecipientRows      = $acceptedRows
            ExchangeOnlineJournalRows  = $exchangeOnlineJournalRows
            JournalRecipients          = @($journalSet)
            JournalReportSenders       = @($journalSenderSet)
            TopSenders                 = @($senderRanking)
            TopRecipientDomains        = @($domainRanking)
            Exclusions                 = @($exclusions)
        }
    }

    # ==================================================================================================
    # Live fetch: Get-MessageTraceV2 using its documented continuation values
    # ==================================================================================================

    function Get-TerrlTraceRows {
        <#
    .SYNOPSIS
        Pull all Get-MessageTraceV2 rows for [StartDate,EndDate] using the continuation method
        documented for Get-MessageTraceV2.
    .PARAMETER TraceCommand
        Scriptblock(StartDate,EndDate,PageSize,StartingRecipientAddress) returning rows. Defaults
        to Get-MessageTraceV2. Injectable so the fetcher can be unit-tested without a live tenant.
    #>
        [CmdletBinding()]
        [OutputType([object[]])]
        param(
            [Parameter(Mandatory)][datetime]$StartDate,
            [Parameter(Mandatory)][datetime]$EndDate,
            [ValidateRange(1, 5000)]
            [int]$PageSize = 5000,
            [ScriptBlock]$TraceCommand
        )

        if (-not $TraceCommand) {
            $TraceCommand = {
                param($s, $e, $size, $startingRecipientAddress)
                $p = @{ StartDate = $s; EndDate = $e; ResultSize = $size; ErrorAction = 'Stop' }
                if (-not [string]::IsNullOrWhiteSpace($startingRecipientAddress)) {
                    $p.StartingRecipientAddress = $startingRecipientAddress
                }
                Get-MessageTraceV2 @p -WarningAction SilentlyContinue
            }
        }

        $all = [System.Collections.Generic.List[object]]::new()
        $queryEndDate = $EndDate
        $startingRecipientAddress = $null
        $seenCursors = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        while ($true) {
            Write-Verbose (
                "Querying {0:u} -> {1:u}; starting recipient '{2}'" -f
                $StartDate,
                $queryEndDate,
                $startingRecipientAddress
            )
            $rows = @(
                & $TraceCommand $StartDate $queryEndDate $PageSize $startingRecipientAddress
            )

            [void]$all.AddRange([object[]]$rows)

            if ($rows.Count -lt $PageSize) {
                break
            }

            $lastRow = $rows[-1]
            $nextRecipient = [string]$lastRow.RecipientAddress
            if ([string]::IsNullOrWhiteSpace($nextRecipient) -or $null -eq $lastRow.Received) {
                throw 'A full message-trace page did not contain the continuation values Received and RecipientAddress.'
            }

            $nextEndDate = [datetime]$lastRow.Received
            $cursorKey = '{0:o}|{1}' -f $nextEndDate, $nextRecipient
            if (-not $seenCursors.Add($cursorKey)) {
                throw "Get-MessageTraceV2 returned the same continuation cursor more than once: $cursorKey"
            }

            $queryEndDate = $nextEndDate
            $startingRecipientAddress = $nextRecipient
        }

        Write-Verbose ("Fetched {0} rows." -f $all.Count)
        return $all.ToArray()
    }

    # ==================================================================================================
    # Orchestration (only runs when invoked as a script, not when dot-sourced for tests)
    # ==================================================================================================

    function Invoke-TerrlMeasurement {
        [CmdletBinding()]
        param()

        if (-not $StartDate) {
            $script:StartDate = $EndDate.AddDays(-1)
        }

        if ($StartDate -ge $EndDate) {
            throw 'StartDate must be earlier than EndDate.'
        }

        # The service allows 100 requests per rolling five minutes per tenant. Limit this script
        # to half of that shared budget, including every request made by the built-in fetcher.
        $originalGetMessageTraceV2 = Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue
        if ($originalGetMessageTraceV2) {
            $traceRequestLimit = 50
            $traceRequestWindow = [TimeSpan]::FromMinutes(5)
            $traceRequestTimes = [System.Collections.Generic.Queue[DateTime]]::new()

            function Get-MessageTraceV2 {
                [CmdletBinding()]
                param(
                    [Parameter()]
                    [DateTime]$StartDate,

                    [Parameter()]
                    [DateTime]$EndDate,

                    [Parameter()]
                    [string]$FromIP,

                    [Parameter()]
                    [string[]]$MessageId,

                    [Parameter()]
                    [guid]$MessageTraceId,

                    [Parameter()]
                    [string[]]$RecipientAddress,

                    [Parameter()]
                    [string[]]$SenderAddress,

                    [Parameter()]
                    [string[]]$Status,

                    [Parameter()]
                    [string]$Subject,

                    [Parameter()]
                    [string]$SubjectFilterType,

                    [Parameter()]
                    [string]$ToIP,

                    [Parameter()]
                    [ValidateRange(1, 5000)]
                    [int]$ResultSize,

                    [Parameter()]
                    [string]$StartingRecipientAddress
                )

                $now = [DateTime]::UtcNow
                while ($traceRequestTimes.Count -gt 0 -and
                    ($now - $traceRequestTimes.Peek()) -ge $traceRequestWindow) {
                    [void]$traceRequestTimes.Dequeue()
                }

                if ($traceRequestTimes.Count -ge $traceRequestLimit) {
                    $oldestRequest = $traceRequestTimes.Peek()
                    $wait = $traceRequestWindow - ($now - $oldestRequest)
                    $waitSeconds = [Math]::Max(1, [Math]::Ceiling($wait.TotalSeconds) + 1)
                    Write-Host (
                        "Trace request budget reached ($traceRequestLimit requests in five minutes). " +
                        "Waiting $waitSeconds seconds to preserve half of the tenant limit..."
                    ) -ForegroundColor Yellow
                    Start-Sleep -Seconds $waitSeconds

                    $now = [DateTime]::UtcNow
                    while ($traceRequestTimes.Count -gt 0 -and
                        ($now - $traceRequestTimes.Peek()) -ge $traceRequestWindow) {
                        [void]$traceRequestTimes.Dequeue()
                    }
                }

                $traceRequestTimes.Enqueue([DateTime]::UtcNow)
                Write-Verbose (
                    "Get-MessageTraceV2 request {0}/{1} in the current five-minute window." -f
                    $traceRequestTimes.Count,
                    $traceRequestLimit
                )

                $invokeParameters = @{}
                foreach ($key in $PSBoundParameters.Keys) {
                    if ($key -notin @(
                            'Verbose', 'Debug', 'ErrorAction', 'WarningAction',
                            'InformationAction', 'ErrorVariable', 'WarningVariable',
                            'InformationVariable', 'OutVariable', 'OutBuffer',
                            'PipelineVariable'
                        )) {
                        $invokeParameters[$key] = $PSBoundParameters[$key]
                    }
                }

                & $originalGetMessageTraceV2 @invokeParameters -ErrorAction Stop
            }
        }

        # 1. Acquire rows -------------------------------------------------------------------------------
        if ($pipelineWasConnected) {
            Write-Verbose "Using $($pipelineRows.Count) message-trace rows from the pipeline."
            $rows = $pipelineRows.ToArray()
        } elseif ($MessageTraceCsv) {
            if (-not (Test-Path -LiteralPath $MessageTraceCsv -PathType Leaf)) {
                throw "MessageTraceCsv not found: $MessageTraceCsv"
            }
            $rows = @(Import-Csv -LiteralPath $MessageTraceCsv -ErrorAction Stop)
        } else {
            if (-not (Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
                throw "Get-MessageTraceV2 is not available. Connect to Exchange Online, pipe trace rows in, or pass -MessageTraceCsv."
            }
            Write-Host (
                "Fetching message trace {0:u} -> {1:u} (PageSize {2}) ..." -f
                $StartDate.ToUniversalTime(),
                $EndDate.ToUniversalTime(),
                $PageSize
            ) -ForegroundColor Cyan
            $rows = @(Get-TerrlTraceRows -StartDate $StartDate -EndDate $EndDate -PageSize $PageSize)
        }

        $rows = @($rows)
        if ($rows.Count -eq 0) {
            Write-Warning (
                'No message-trace rows were returned for the requested window. ' +
                'The live TERRL counter can still be nonzero because message trace is delayed ' +
                'and Get-LimitsEnforcementStatus uses a separate rolling enforcement data source.'
            )

            if ($CompareToEnforcementStatus -and
                (Get-Command Get-LimitsEnforcementStatus -ErrorAction SilentlyContinue)) {
                Write-Host ''
                Write-Host 'Get-LimitsEnforcementStatus (live ground truth):' -ForegroundColor Cyan
                Get-LimitsEnforcementStatus -ErrorAction Stop |
                    Format-List Verdict, EnforcementEnabled, Threshold, ObservedValue |
                    Out-String |
                    Write-Host
            }

            return
        }

        # 2. Resolve accepted domains -------------------------------------------------------------------
        $accepted = $AcceptedDomain
        $acceptedDomainObjects = @()
        if (-not $accepted) {
            if (-not (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue)) {
                throw "No -AcceptedDomain supplied and Get-AcceptedDomain is unavailable. Pass -AcceptedDomain."
            }
            $acceptedDomainObjects = @(Get-AcceptedDomain -ErrorAction Stop)
            $accepted = @(
                $acceptedDomainObjects |
                    Select-Object -ExpandProperty DomainName |
                    ForEach-Object { $_.ToString() }
            )
        } elseif (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue) {
            try {
                $acceptedDomainObjects = @(Get-AcceptedDomain -ErrorAction Stop)
            } catch {
                Write-Verbose (
                    'Get-AcceptedDomain could not be queried for journal-sender discovery: ' +
                    $_.Exception.Message
                )
            }
        }

        $resolvedJournalRecipients = [System.Collections.Generic.List[string]]::new()
        foreach ($address in $JournalRecipient) {
            if (-not [string]::IsNullOrWhiteSpace($address)) {
                [void]$resolvedJournalRecipients.Add($address.Trim().Trim('<', '>'))
            }
        }

        if (Get-Command Get-JournalRule -ErrorAction SilentlyContinue) {
            try {
                foreach ($rule in @(Get-JournalRule -ErrorAction Stop)) {
                    $enabledProperty = $rule.PSObject.Properties['Enabled']
                    if ($enabledProperty) {
                        try {
                            if (-not [System.Convert]::ToBoolean($enabledProperty.Value)) {
                                continue
                            }
                        } catch {
                            Write-Verbose (
                                "Could not parse Enabled='$($enabledProperty.Value)' for journal " +
                                "rule '$($rule.Name)'; including its destination."
                            )
                        }
                    }

                    $addressProperty = $rule.PSObject.Properties['JournalEmailAddress']
                    if ($addressProperty -and
                        -not [string]::IsNullOrWhiteSpace([string]$addressProperty.Value)) {
                        [void]$resolvedJournalRecipients.Add(
                            ([string]$addressProperty.Value).Trim().Trim('<', '>')
                        )
                    }
                }
            } catch {
                Write-Verbose (
                    "Get-JournalRule failed; EXO journal destinations will not be auto-discovered: " +
                    $_.Exception.Message
                )
            }
        } else {
            Write-Verbose (
                'Get-JournalRule is unavailable; EXO journal destinations will not be auto-discovered.'
            )
        }

        $resolvedJournalRecipients = @(
            $resolvedJournalRecipients |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique
        )
        if ($resolvedJournalRecipients.Count -gt 0) {
            Write-Verbose (
                'EXO journal destinations: ' + ($resolvedJournalRecipients -join ', ')
            )
        }

        $resolvedJournalReportSenders = [System.Collections.Generic.List[string]]::new()
        foreach ($address in $JournalReportSender) {
            if (-not [string]::IsNullOrWhiteSpace($address)) {
                [void]$resolvedJournalReportSenders.Add($address.Trim().Trim('<', '>'))
            }
        }

        if (Get-Command Get-TransportConfig -ErrorAction SilentlyContinue) {
            try {
                $transportConfig = Get-TransportConfig -ErrorAction Stop
                $ndrProperty = $transportConfig.PSObject.Properties['JournalingReportNdrTo']
                if ($ndrProperty) {
                    $ndrAddress = ([string]$ndrProperty.Value).Trim().Trim('<', '>')
                    if (-not [string]::IsNullOrWhiteSpace($ndrAddress) -and
                        $ndrAddress.Contains('@')) {
                        [void]$resolvedJournalReportSenders.Add($ndrAddress)
                    }
                }
            } catch {
                Write-Verbose (
                    'Get-TransportConfig failed; the configured journal-report sender could not ' +
                    'be discovered: ' + $_.Exception.Message
                )
            }
        } else {
            Write-Verbose (
                'Get-TransportConfig is unavailable; the configured journal-report sender could ' +
                'not be discovered.'
            )
        }

        $defaultAcceptedDomain = $null
        foreach ($domainObject in $acceptedDomainObjects) {
            $defaultProperty = $domainObject.PSObject.Properties['Default']
            if ($defaultProperty) {
                try {
                    if ([System.Convert]::ToBoolean($defaultProperty.Value)) {
                        $defaultAcceptedDomain = [string]$domainObject.DomainName
                        break
                    }
                } catch {
                    Write-Verbose (
                        "Could not parse Default='$($defaultProperty.Value)' for accepted " +
                        "domain '$($domainObject.DomainName)'."
                    )
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($defaultAcceptedDomain)) {
            $defaultAcceptedDomain = @(
                $accepted |
                    Where-Object {
                        $_ -like '*.onmicrosoft.com' -and
                        $_ -notlike '*.mail.onmicrosoft.com'
                    }
                ) | Select-Object -First 1
            }

            if (-not [string]::IsNullOrWhiteSpace($defaultAcceptedDomain)) {
                [void]$resolvedJournalReportSenders.Add(
                    'MicrosoftExchange329e71ec88ae4615bbc36ab6ce41109e@{0}' -f
                    $defaultAcceptedDomain
                )
            } else {
                Write-Verbose (
                    'The tenant default accepted domain could not be determined, so the fallback ' +
                    'Microsoft Exchange Recipient journal sender was not constructed.'
                )
            }

            $resolvedJournalReportSenders = @(
                $resolvedJournalReportSenders |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Sort-Object -Unique
        )
        if ($resolvedJournalReportSenders.Count -gt 0) {
            Write-Verbose (
                'EXO journal-report senders: ' + ($resolvedJournalReportSenders -join ', ')
            )
        }

        # 3. Classify -----------------------------------------------------------------------------------
        $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain $accepted `
            -ExcludeNullSender $ExcludeNullSender `
            -JournalRecipient $resolvedJournalRecipients `
            -JournalReportSender $resolvedJournalReportSenders `
            -TopSenders $TopSenders

        # 4. Report -------------------------------------------------------------------------------------
        $acceptedSet = ConvertTo-TerrlDomainSet -Domain $accepted
        Write-Host ''
        Write-Host '==================== TERRL external-recipient estimate (Get-MessageTraceV2) ====================' -ForegroundColor Green
        Write-Host (
            "Window               : {0:u}  ->  {1:u}" -f
            $StartDate.ToUniversalTime(),
            $EndDate.ToUniversalTime()
        )
        Write-Host ("Accepted domains     : {0}" -f (($acceptedSet | Select-Object -First 8) -join ', '))
        Write-Host ("Journal destinations : {0}" -f $(if ($result.JournalRecipients.Count) { $result.JournalRecipients -join ', ' } else { '(none discovered)' }))
        Write-Host ("Journal senders      : {0}" -f $(if ($result.JournalReportSenders.Count) { $result.JournalReportSenders -join ', ' } else { '(none discovered)' }))
        Write-Host ("Trace rows evaluated : {0}" -f $result.TraceRows)
        Write-Host ''
        Write-Host ("External recipients counted toward limit : {0}" -f $result.ExternalRecipientsCounted) -ForegroundColor Yellow
        Write-Host ("  distinct external recipients           : {0}" -f $result.DistinctExternalRecipients)
        Write-Host ("  distinct outbound messages (>=1 ext)   : {0}" -f $result.DistinctOutboundMessages)
        Write-Host ("  internal-recipient rows (not counted)  : {0}" -f $result.AcceptedRecipientRows)
        Write-Host ("  EXO journal-report rows (not counted)  : {0}" -f $result.ExchangeOnlineJournalRows)
        Write-Host ''
        Write-Host 'Excluded (not counted) by reason:' -ForegroundColor Cyan
        $result.Exclusions | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host ("Top {0} senders contributing to the limit:" -f $TopSenders) -ForegroundColor Cyan
        $result.TopSenders | Format-Table Sender, ExternalRecipients, Messages, PercentOfTotal -AutoSize | Out-String | Write-Host
        Write-Host ("Top {0} external recipient domains:" -f $TopSenders) -ForegroundColor Cyan
        $result.TopRecipientDomains | Format-Table RecipientDomain, ExternalRecipients, PercentOfTotal -AutoSize | Out-String | Write-Host

        Write-Host 'NOTE: this is an APPROXIMATION and can run HIGH of the live counter. It detects EXO' -ForegroundColor DarkGray
        Write-Host '      journal reports from journal-rule destinations, but not on-prem journal reports,' -ForegroundColor DarkGray
        Write-Host '      cannot identify OOF, and only approximates NDRs from sender information.' -ForegroundColor DarkGray
        Write-Host '      Use Get-LimitsEnforcementStatus' -ForegroundColor DarkGray
        Write-Host '      for the exact live ObservedValue.' -ForegroundColor DarkGray

        # 5. Optional reconciliation with the live counter ---------------------------------------------
        if ($CompareToEnforcementStatus) {
            if (Get-Command Get-LimitsEnforcementStatus -ErrorAction SilentlyContinue) {
                try {
                    $les = Get-LimitsEnforcementStatus -ErrorAction Stop
                    Write-Host ''
                    Write-Host 'Get-LimitsEnforcementStatus (live ground truth):' -ForegroundColor Cyan
                    $les | Format-List Verdict, EnforcementEnabled, Threshold, ObservedValue | Out-String | Write-Host
                    if ($null -ne $les.ObservedValue) {
                        $delta = $result.ExternalRecipientsCounted - [double]$les.ObservedValue
                        Write-Host ("Script estimate {0} vs live ObservedValue {1} (delta {2:+0;-0;0})." -f `
                                $result.ExternalRecipientsCounted, $les.ObservedValue, $delta) -ForegroundColor Yellow
                    }
                } catch {
                    Write-Warning "Get-LimitsEnforcementStatus failed: $($_.Exception.Message)"
                }
            } else {
                Write-Warning 'Get-LimitsEnforcementStatus is not available in this session.'
            }
        }

        if ($CsvPath) {
            $result.TopSenders |
                Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "Top-sender table exported to $CsvPath" -ForegroundColor DarkGray
        }

        return $result
    }
}

process {
    if ($null -ne $InputObject) {
        [void]$pipelineRows.Add($InputObject)
    }
}

end {
    # Run the live report only when invoked as a script (skip when dot-sourced for tests).
    if (-not $DefineFunctionsOnly -and $MyInvocation.InvocationName -ne '.') {
        Invoke-TerrlMeasurement
    }
}
