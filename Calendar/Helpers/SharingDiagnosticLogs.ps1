# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing diagnostic log collection, freshness, and exception checks.

function Test-ReceiverSharingLogFreshness {
    if ($null -ne (Get-SharingRuleNotApplicableReason -RuleId "SHR404")) {
        foreach ($ruleId in @("SHR404", "SHR405", "SHR406", "SHR407")) {
            Add-SharingFinding -RuleId $ruleId -Status NotApplicable
        }
        return
    }
    $logChecks = @(
        @{ Key = "receiver_SharingSyncAssistantLog"; Component = "SharingSyncAssistant"; Collector = "ReceiverSharingSyncAssistantLog"; WarningRule = "SHR404"; ErrorRule = "SHR405" }
        @{ Key = "receiver_SharingLog"; Component = "Sharing"; Collector = "ReceiverSharingLog"; WarningRule = "SHR406"; ErrorRule = "SHR407" }
    )
    $nowUtc = (Get-Date).ToUniversalTime()
    foreach ($logCheck in $logChecks) {
        $component = $logCheck.Component
        $source = "Export-MailboxDiagnosticLogs -Identity $Receiver -ComponentName $component"
        $logEntry = [ordered]@{ source = $source; status = "NotCollected"; error = $null; omittedOlderThanOneYear = 0; data = $null }
        $script:SharingDiagnosticLogs[$logCheck.Key] = $logEntry

        Write-Host -ForegroundColor Cyan "Checking the receiver $component log: $source"
        try {
            $logOutput = Invoke-SharingCollector -Name $logCheck.Collector -Action {
                Export-MailboxDiagnosticLogs -Identity $Receiver -ComponentName $component
            } -AllowNull
        } catch {
            $logEntry.status = "Failed"
            $logEntry.error = (ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_).message
            Write-Warning "Unable to collect the $component log for [$Receiver]: $($logEntry.error)"
            continue
        }

        if ([string]::IsNullOrEmpty([string]$logOutput.MailboxLog)) {
            $script:CollectorStatuses[$logCheck.Collector] = [PSCustomObject]@{ status = "NoData"; error = $null }
            $logEntry.status = "NoData"
            Write-Host -ForegroundColor Yellow "The receiver $component log has no entries, so its freshness cannot be evaluated."
            continue
        }

        $logLines = @(([string]$logOutput.MailboxLog) -split "\r?\n")
        $recentLog = ConvertTo-SharingLogLines -Text ([string]$logOutput.MailboxLog) -ReferenceTimeUtc $nowUtc
        $logEntry.status = "Collected"
        $logEntry.data = $recentLog.Line
        $logEntry.omittedOlderThanOneYear = $recentLog.OmittedOlderThanOneYear
        $latestEntry = Get-CalendarDiagnosticLogLatestTimestamp -Line $logLines -ReferenceTimeUtc $nowUtc
        if ($null -eq $latestEntry) {
            Write-Host -ForegroundColor Yellow "No parseable timestamps were found in the receiver $component log, so its freshness cannot be evaluated."
            foreach ($ruleId in @($logCheck.WarningRule, $logCheck.ErrorRule)) {
                Add-SharingFinding -RuleId $ruleId -Status NotEvaluated -Evidence @{
                    reason = "No parseable timestamps were found in the log."
                }
            }
            continue
        }

        $age = $nowUtc - $latestEntry
        $ageText = "$([math]::Floor($age.TotalDays)) days $($age.Hours) hours"
        $evidence = @{
            latestEntryUtc = $latestEntry.ToString("o")
            ageHours       = [math]::Round($age.TotalHours, 1)
        }
        if ($age.TotalDays -gt 7) {
            Write-Host -ForegroundColor Red "Error: The latest receiver $component log entry is $latestEntry UTC ($ageText ago), more than 7 days old."
            Add-SharingFinding -RuleId $logCheck.ErrorRule -Status Detected -Area "Receiver $component log" -Evidence $evidence
            Add-SharingFinding -RuleId $logCheck.WarningRule -Status NotApplicable -Evidence @{
                reason = "Superseded by $($logCheck.ErrorRule): the latest entry is more than 7 days old."
            }
        } elseif ($age.TotalHours -gt 24) {
            Write-Host -ForegroundColor Yellow "Warning: The latest receiver $component log entry is $latestEntry UTC ($ageText ago), more than 24 hours old."
            Add-SharingFinding -RuleId $logCheck.WarningRule -Status Detected -Area "Receiver $component log" -Evidence $evidence
        } else {
            Write-Host -ForegroundColor Green "The latest receiver $component log entry is $latestEntry UTC ($ageText ago)."
        }
    }
}

function Get-SharingDiagnosticLogs {
    $logRequests = @(
        @{ Key = "receiver_SharingSyncAssistantLog"; Identity = $Receiver; Component = "SharingSyncAssistant"; Mailbox = $script:ReceiverMB; Collector = "ReceiverSharingSyncAssistantLog" }
        @{ Key = "receiver_SharingLog"; Identity = $Receiver; Component = "Sharing"; Mailbox = $script:ReceiverMB; Collector = "ReceiverSharingLog" }
    )
    foreach ($logRequest in $logRequests) {
        if ($script:SharingDiagnosticLogs.Contains($logRequest.Key)) {
            # The receiver logs are already collected by the freshness check.
            continue
        }

        $source = "Export-MailboxDiagnosticLogs -Identity $($logRequest.Identity) -ComponentName $($logRequest.Component)"
        $logEntry = [ordered]@{ source = $source; status = "NotCollected"; error = $null; omittedOlderThanOneYear = 0; data = $null }
        $script:SharingDiagnosticLogs[$logRequest.Key] = $logEntry
        if ($null -eq $logRequest.Mailbox) {
            $logEntry.error = "The mailbox was not resolved, so the log was not collected."
            continue
        }

        Write-Host -ForegroundColor Cyan "Collecting the $($logRequest.Component) log: $source"
        try {
            $logOutput = Invoke-SharingCollector -Name $logRequest.Collector -Action {
                Export-MailboxDiagnosticLogs -Identity $logRequest.Identity -ComponentName $logRequest.Component
            } -AllowNull
            if ([string]::IsNullOrEmpty([string]$logOutput.MailboxLog)) {
                $logEntry.status = "NoData"
                $script:CollectorStatuses[$logRequest.Collector] = [PSCustomObject]@{ status = "NoData"; error = $null }
            } else {
                $recentLog = ConvertTo-SharingLogLines -Text ([string]$logOutput.MailboxLog)
                $logEntry.status = "Collected"
                $logEntry.data = $recentLog.Line
                $logEntry.omittedOlderThanOneYear = $recentLog.OmittedOlderThanOneYear
            }
        } catch {
            $logEntry.status = "Failed"
            $logEntry.error = (ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_).message
            Write-Warning "Unable to collect the $($logRequest.Component) log for [$($logRequest.Identity)]: $($logEntry.error)"
        }
    }
}

function Test-SharingLogExceptions {
    $nowUtc = (Get-Date).ToUniversalTime()
    $scannedLogs = [System.Collections.Generic.List[object]]::new()
    $unavailableLogs = [System.Collections.Generic.List[string]]::new()
    foreach ($rawLog in @(
            @{ Label = "Owner CalendarSharingInvite"; Text = $script:OwnerInviteLogRaw; Collector = "OwnerInviteLog" }
            @{ Label = "Receiver AcceptCalendarSharingInvite"; Text = $script:ReceiverAcceptLogRaw; Collector = "ReceiverAcceptLog" }
        )) {
        if (-not [string]::IsNullOrEmpty($rawLog.Text)) {
            $recentLog = ConvertTo-SharingLogLines -Text $rawLog.Text -ReferenceTimeUtc $nowUtc
            $scannedLogs.Add(@{ Label = $rawLog.Label; Line = @($recentLog.Line) })
        } elseif ($script:CollectorStatuses[$rawLog.Collector].status -ne "NotApplicable") {
            $unavailableLogs.Add($rawLog.Label)
        }
    }
    foreach ($diagnosticLog in @(
            @{ Key = "receiver_SharingSyncAssistantLog"; Label = "Receiver SharingSyncAssistant" }
            @{ Key = "receiver_SharingLog"; Label = "Receiver Sharing" }
        )) {
        $logEntry = $script:SharingDiagnosticLogs[$diagnosticLog.Key]
        if (($null -ne $logEntry) -and ($null -ne $logEntry.data)) {
            $scannedLogs.Add(@{ Label = $diagnosticLog.Label; Line = @($logEntry.data) })
        } else {
            $unavailableLogs.Add($diagnosticLog.Label)
        }
    }
    $script:SharingLogScanPerformed = $scannedLogs.Count -gt 0
    if (-not $script:SharingLogScanPerformed) {
        Write-Host -ForegroundColor Yellow "No sharing logs were available, so the exception checks could not be evaluated."
        return
    }

    $quotaPattern = "NamedPropsQuotaExceeded"
    $exceptionPattern = "(?<Type>[A-Za-z][A-Za-z0-9_]*Exception)\b"
    $xtapFailurePattern = '\[XTAP(?:-[^\]]+)?\](?:\[[^\]]+\])*.*(?:\b(?:failure|failed|forbidden|denied|AuthError)\b|\b[A-Za-z][A-Za-z0-9_]*Exception\b|\berror\s*:)'
    $quotaLogs = [System.Collections.Generic.List[string]]::new()
    $exceptionLogs = [System.Collections.Generic.List[string]]::new()
    $xtapLogs = [System.Collections.Generic.List[string]]::new()
    $exceptionTypes = [System.Collections.Generic.HashSet[string]]::new()
    $quotaCount = 0
    $exceptionCount = 0
    $xtapFailureCount = 0
    $latestQuota = $null
    $latestException = $null
    $latestXtapFailure = $null
    foreach ($scannedLog in $scannedLogs) {
        $lineTimestamps = Get-CalendarDiagnosticLogLineTimestamp -Line $scannedLog.Line -ReferenceTimeUtc $nowUtc
        $currentTimestamp = $null
        for ($index = 0; $index -lt $scannedLog.Line.Count; $index++) {
            $logLine = [string]$scannedLog.Line[$index]
            if ($null -ne $lineTimestamps[$index]) {
                $currentTimestamp = $lineTimestamps[$index]
            }

            if ($logLine -match $xtapFailurePattern) {
                $xtapFailureCount++
                if (-not $xtapLogs.Contains($scannedLog.Label)) {
                    $xtapLogs.Add($scannedLog.Label)
                }
                if (($null -ne $currentTimestamp) -and
                    (($null -eq $latestXtapFailure) -or ($currentTimestamp -gt $latestXtapFailure))) {
                    $latestXtapFailure = $currentTimestamp
                }
            }

            if ($logLine -match $quotaPattern) {
                $quotaCount++
                if (-not $quotaLogs.Contains($scannedLog.Label)) {
                    $quotaLogs.Add($scannedLog.Label)
                }
                if (($null -ne $currentTimestamp) -and (($null -eq $latestQuota) -or ($currentTimestamp -gt $latestQuota))) {
                    $latestQuota = $currentTimestamp
                }
            } elseif (($logLine -match $exceptionPattern) -or
                ($logLine -match "\[EX, [^\];\s][^\]]*\]") -or
                ($logLine -match "numberOfFailures: [1-9]")) {
                $exceptionCount++
                if (-not $exceptionLogs.Contains($scannedLog.Label)) {
                    $exceptionLogs.Add($scannedLog.Label)
                }
                foreach ($exceptionMatch in [regex]::Matches($logLine, $exceptionPattern)) {
                    $null = $exceptionTypes.Add($exceptionMatch.Groups["Type"].Value)
                }
                if (($null -ne $currentTimestamp) -and (($null -eq $latestException) -or ($currentTimestamp -gt $latestException))) {
                    $latestException = $currentTimestamp
                }
            }
        }
    }
    if ($quotaCount -gt 0) {
        Write-Host -ForegroundColor Red "Error: The sharing logs contain [$quotaCount] named property quota exceptions (MapiExceptionNamedPropsQuotaExceeded) in: $($quotaLogs -join ', '). Escalate to Microsoft Support."
        Add-SharingFinding -RuleId "SHR408" -Status Detected -Area "Sharing logs" -Evidence @{
            quotaExceptionCount = $quotaCount
            affectedLogs        = @($quotaLogs)
            latestEntryUtc      = $(if ($null -ne $latestQuota) { $latestQuota.ToString("o") } else { $null })
        }
    }
    if ($exceptionCount -gt 0) {
        Write-Host -ForegroundColor Yellow "Warning: The sharing logs contain [$exceptionCount] exception entries in: $($exceptionLogs -join ', ')."
        Add-SharingFinding -RuleId "SHR409" -Status Detected -Area "Sharing logs" -Evidence @{
            exceptionCount = $exceptionCount
            exceptionTypes = @($exceptionTypes | Sort-Object)
            affectedLogs   = @($exceptionLogs)
            latestEntryUtc = $(if ($null -ne $latestException) { $latestException.ToString("o") } else { $null })
        }
    }
    if ($xtapFailureCount -gt 0) {
        Write-Host -ForegroundColor Yellow "Warning: The sharing logs contain [$xtapFailureCount] XTAP-related failure entries. Review the tenant administrator's public XTAP guidance in the recommended next steps."
        Add-SharingFinding -RuleId "SHR414" -Status Detected -Area "Sharing logs" -Evidence @{
            xtapFailureCount = $xtapFailureCount
            affectedLogs     = @($xtapLogs)
            latestEntryUtc   = $(if ($null -ne $latestXtapFailure) { $latestXtapFailure.ToString("o") } else { $null })
        }
    }
    if ($unavailableLogs.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "The sharing log exception scan is incomplete. Unavailable logs: $($unavailableLogs -join ', ')."
        foreach ($exceptionCheck in @(
                @{ RuleId = "SHR408"; Count = $quotaCount }
                @{ RuleId = "SHR409"; Count = $exceptionCount }
                @{ RuleId = "SHR414"; Count = $xtapFailureCount }
            )) {
            if ($exceptionCheck.Count -eq 0) {
                Add-SharingFinding -RuleId $exceptionCheck.RuleId -Status NotEvaluated -Area "Sharing logs" -Evidence @{
                    reason          = "Not all required sharing logs were available for the exception scan."
                    unavailableLogs = @($unavailableLogs)
                }
            }
        }
    } elseif (($quotaCount -eq 0) -and ($exceptionCount -eq 0) -and ($xtapFailureCount -eq 0)) {
        Write-Host -ForegroundColor Green "No exceptions were found in the sharing logs from the last year."
    }
}
