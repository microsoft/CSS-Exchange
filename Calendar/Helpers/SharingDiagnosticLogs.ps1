# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing diagnostic log collection, freshness, and exception checks.

function Test-ReceiverSharingLogFreshness {
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
        @{ Key = "receiver_SharingSyncAssistantLog"; Identity = $Receiver; Component = "SharingSyncAssistant"; Mailbox = $script:ReceiverMB }
        @{ Key = "receiver_SharingLog"; Identity = $Receiver; Component = "Sharing"; Mailbox = $script:ReceiverMB }
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
            $logOutput = Export-MailboxDiagnosticLogs -Identity $logRequest.Identity -ComponentName $logRequest.Component
            if ([string]::IsNullOrEmpty([string]$logOutput.MailboxLog)) {
                $logEntry.status = "NoData"
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
    foreach ($rawLog in @(
            @{ Label = "Owner CalendarSharingInvite"; Text = $script:OwnerInviteLogRaw }
            @{ Label = "Receiver AcceptCalendarSharingInvite"; Text = $script:ReceiverAcceptLogRaw }
        )) {
        if (-not [string]::IsNullOrEmpty($rawLog.Text)) {
            $recentLog = ConvertTo-SharingLogLines -Text $rawLog.Text -ReferenceTimeUtc $nowUtc
            $scannedLogs.Add(@{ Label = $rawLog.Label; Line = @($recentLog.Line) })
        }
    }
    foreach ($diagnosticLog in @(
            @{ Key = "receiver_SharingSyncAssistantLog"; Label = "Receiver SharingSyncAssistant" }
            @{ Key = "receiver_SharingLog"; Label = "Receiver Sharing" }
        )) {
        $logEntry = $script:SharingDiagnosticLogs[$diagnosticLog.Key]
        if (($null -ne $logEntry) -and ($null -ne $logEntry.data)) {
            $scannedLogs.Add(@{ Label = $diagnosticLog.Label; Line = @($logEntry.data) })
        }
    }

    $quotaPattern = "NamedPropsQuotaExceeded"
    $exceptionPattern = "(?<Type>[A-Za-z][A-Za-z0-9_]*Exception)\b"
    $quotaLogs = [System.Collections.Generic.List[string]]::new()
    $exceptionLogs = [System.Collections.Generic.List[string]]::new()
    $exceptionTypes = [System.Collections.Generic.HashSet[string]]::new()
    $quotaCount = 0
    $exceptionCount = 0
    $latestQuota = $null
    $latestException = $null
    foreach ($scannedLog in $scannedLogs) {
        $lineTimestamps = Get-CalendarDiagnosticLogLineTimestamp -Line $scannedLog.Line -ReferenceTimeUtc $nowUtc
        $currentTimestamp = $null
        for ($index = 0; $index -lt $scannedLog.Line.Count; $index++) {
            $logLine = [string]$scannedLog.Line[$index]
            if ($null -ne $lineTimestamps[$index]) {
                $currentTimestamp = $lineTimestamps[$index]
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
    $script:SharingLogScanPerformed = $true

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
    if (($quotaCount -eq 0) -and ($exceptionCount -eq 0)) {
        Write-Host -ForegroundColor Green "No exceptions were found in the sharing logs from the last year."
    }
}
