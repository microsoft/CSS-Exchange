# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$script:ExOPJournalCache = @{}

function Find-ExOPOperationEvidence {
    <#
        Locates the evidence that an interrupted migration saved before it changed the item:
        the before snapshot, the optional verified-target snapshot and the append-only journal.
    #>
    param (
        [string[]]
        $SearchDirectory,

        [string]
        $OperationId
    )
    if ($OperationId -cnotmatch '^[0-9a-f]{32}$') { throw 'The migration marker contains an invalid operation ID.' }
    $before = @(
        foreach ($directory in $SearchDirectory) {
            Get-ChildItem -LiteralPath $directory -Recurse -File -Filter "$OperationId-before.json" -ErrorAction Stop
        }
    )
    if ($before.Count -ne 1) {
        throw "Expected exactly one saved snapshot for operation $OperationId below the search directories; found $($before.Count)."
    }
    $folder = $before[0].DirectoryName
    $afterPath = Join-Path -Path $folder -ChildPath "$OperationId-after.json"
    $journalPath = Join-Path -Path $folder -ChildPath 'details.jsonl'
    # An interrupted Reconcile journals its rollback writes in its own run folder. Records of this operation are
    # therefore collected from every journal below the search directories and ordered by time.
    $journals = New-Object 'System.Collections.Generic.Dictionary[string,IO.FileInfo]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in $SearchDirectory) {
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -Recurse -File -Filter 'details.jsonl' -ErrorAction Stop)) {
            $journals[$file.FullName] = $file
        }
    }
    $entries = @(
        foreach ($file in $journals.Values) {
            $line = 0
            foreach ($record in (Read-ExOPJournalRecords -File $file)) {
                $line++
                if ($record.OperationId -cne $OperationId) { continue }
                $utc = $record.PSObject.Properties['Utc']
                # PowerShell 7 reads ISO timestamps from JSON as DateTime values, Windows PowerShell 5.1 as strings.
                $time = if ($null -eq $utc -or $null -eq $utc.Value) { [DateTimeOffset]::MinValue }
                elseif ($utc.Value -is [DateTime]) { [DateTimeOffset]$utc.Value }
                elseif ($utc.Value -is [DateTimeOffset]) { $utc.Value }
                else { ConvertTo-ExOPInstant -Value ([string]$utc.Value) }
                [PSCustomObject]@{
                    Utc = $time.UtcDateTime
                    Original = $file.FullName -eq $journalPath; File = $file.FullName; Line = $line; Record = $record
                }
            }
        }
    )
    $events = @($entries | Sort-Object -Property Utc, @{ Expression = 'Original'; Descending = $true }, File, Line | ForEach-Object { $_.Record })
    [PSCustomObject]@{
        BeforePath  = $before[0].FullName
        Before      = Get-Content -LiteralPath $before[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        AfterPath   = if (Test-Path -LiteralPath $afterPath -PathType Leaf) { $afterPath } else { '' }
        JournalPath = if (Test-Path -LiteralPath $journalPath -PathType Leaf) { $journalPath } else { '' }
        Events      = $events
    }
}

function Read-ExOPJournalRecords {
    <#
        Parses the complete records of one journal. Each record is appended with its line terminator; a process
        stopped during an append leaves an unterminated tail whose intent was never durable, so no request was
        sent for it. Parsed journals are cached until the file changes.
    #>
    param (
        [IO.FileInfo]
        $File
    )
    $stamp = '{0}|{1}' -f $File.Length, $File.LastWriteTimeUtc.Ticks
    $cached = $script:ExOPJournalCache[$File.FullName]
    if ($null -ne $cached -and $cached.Stamp -ceq $stamp) { return , $cached.Records }
    $lines = [IO.File]::ReadAllText($File.FullName, [Text.UTF8Encoding]::new($false)).Split("`n")
    $records = @(
        for ($index = 0; $index -lt $lines.Count - 1; $index++) {
            $line = $lines[$index].TrimEnd("`r")
            if ($line) { $line | ConvertFrom-Json }
        }
    )
    $script:ExOPJournalCache[$File.FullName] = [PSCustomObject]@{ Stamp = $stamp; Records = $records }
    , $records
}

function Get-ExOPJournalWriteState {
    <#
        Reconstructs the write tracking of the interrupted process from its journal. An intent without a
        later acknowledgement means the outcome of that request is unknown.
    #>
    param (
        [object[]]
        $Events
    )
    $state = [PSCustomObject]@{
        LastChangeKey = ''; AcknowledgedWrites = 0; WriteAttempted = $false; LastWriteUnknown = $false
        MetadataWritten = $false; DatesWritten = $false; NotificationAttempted = $false; NotificationRejected = $false; NotificationRejectionCode = ''; Plan = $null
        RollbackStarted = $false
    }
    # A definitive rejection resolves only its own send attempt. An earlier send that was acknowledged, or whose
    # outcome stayed unknown, may have reached attendees, so a later rejected resend never clears it.
    $pendingSend = $false
    $sentOrUnknown = $false
    foreach ($record in $Events) {
        switch ($record.Event) {
            'PlanValidated' { $state.Plan = $record.Data }
            'RollbackStarted' { $state.RollbackStarted = $true }
            'WriteIntent' {
                if ($pendingSend) { $sentOrUnknown = $true; $pendingSend = $false }
                $state.WriteAttempted = $true
                $state.LastWriteUnknown = $true
                if ($record.Phase -eq 'Notification' -or $record.Data.Send) {
                    $pendingSend = $true
                    $state.NotificationRejected = $false
                    $state.NotificationRejectionCode = ''
                }
            }
            'NotificationRejected' {
                if ($null -eq $record.Data -or $null -eq $record.Data.PSObject.Properties['Code'] -or
                    $record.Data.Code -notin $script:DefinitiveSendRejectionCodes) {
                    throw 'The journal does not contain a definitive notification rejection code.'
                }
                # Exchange rejected the submission with a definitive response; this attempt sent no update.
                $state.LastWriteUnknown = $false
                $pendingSend = $false
                $state.NotificationRejected = $true
                $state.NotificationRejectionCode = [string]$record.Data.Code
            }
            'WriteAcknowledged' {
                if ($pendingSend) { $sentOrUnknown = $true; $pendingSend = $false }
                $state.LastWriteUnknown = $false
                $state.AcknowledgedWrites++
                $state.LastChangeKey = [string]$record.Data.ChangeKey
                if ($record.Phase -eq 'TimezoneMetadata') { $state.MetadataWritten = $true }
                if ($record.Phase -eq 'MasterDates') { $state.DatesWritten = $true }
            }
        }
    }
    $state.NotificationAttempted = $sentOrUnknown -or $pendingSend
    if ($state.NotificationAttempted) {
        $state.NotificationRejected = $false
        $state.NotificationRejectionCode = ''
    }
    $state
}

function Invoke-ExOPCalendarMigrationReconcile {
    <#
    .SYNOPSIS
    Resolves items left with an in-progress migration marker, for example after the process was terminated.
    .DESCRIPTION
    Run in regular Windows PowerShell on a management/user computer, no local admin.
    Without -Apply the planned action is only reported.
    Before notification could have started, the original verified state is restored from the saved snapshot.
    If notification may have started, the item is never moved back: a verified target state is finalized,
    and anything that cannot be proven is reported as critical without changes. Meeting updates are resent
    only with -ResendNotification. A delegate needs Send on Behalf or Send As for a resend unless
    -SkipSendPermissionCheck is used.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High', DefaultParameterSetName='Rows')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        $Session,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName='Rows')]
        $InputObject,

        [Parameter(Mandatory, ParameterSetName='Csv')]
        [string]
        $CsvPath,

        [Parameter(Mandatory)]
        [string[]]
        $SearchDirectory,

        [Parameter(Mandatory)]
        [string]
        $LogDirectory,

        [switch]
        $Apply,

        [switch]
        $ResendNotification,

        [switch]
        $SkipSendPermissionCheck
    )
    begin {
        $inputRows = New-Object 'System.Collections.Generic.List[object]'
        if ($PSCmdlet.ParameterSetName -eq 'Csv') {
            foreach ($entry in @(Import-Csv -LiteralPath $CsvPath)) { $inputRows.Add($entry) }
        }
        foreach ($directory in $SearchDirectory) {
            if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Search directory not found: $directory" }
        }
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Rows') {
            foreach ($entry in @($InputObject)) { $inputRows.Add($entry) }
        }
    }
    end {
        if ($inputRows.Count -eq 0) { throw 'No input rows were supplied.' }
        $run = New-ExOPMigrationRun -Directory $LogDirectory -Rows @($inputRows.ToArray()) -Apply ([bool]$Apply) -EwsUrl $Session.EwsUrl.AbsoluteUri `
            -EwsUrlSource (Get-ExOPSessionEwsUrlSource -Session $Session)
        Update-ExOPMigrationSummary -Run $run
        $runAttachmentHashBytes = $script:MaxAttachmentHashBytes
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($row in $inputRows) {
            $mailbox = if ($null -ne $row.PSObject.Properties['Mailbox'] -and [string]$row.Mailbox) { [string]$row.Mailbox } else { '_invalid-input' }
            $itemId = if ($null -ne $row.PSObject.Properties['ItemId']) { [string]$row.ItemId } else { '' }
            $result = [PSCustomObject][ordered]@{
                RunId=$run.RunId; OperationId=''; Mailbox=$mailbox; ItemId=$itemId; UID=''; Subject=''
                Status='Failed'; Severity='Warning'; From=''; To=''; RecordType=''; Phase='Reconcile'
                Action=''; StartUtcBefore=''; StartUtcAfter=''; EndUtcBefore=''; EndUtcAfter=''
                HasRoom=$false; RoomNames=''; RoomSmtpAddresses=''; BackEndServer=''
                CalendarState='Unknown'; NotificationStatus='NotChecked'; RollbackStatus='NotNeeded'
                SnapshotPath=''; AfterSnapshotPath=''; RollbackSnapshotPath=''; O12Modes=''; ChangedFields=''
                Error=''; ErrorCode=''; RollbackError=''; RelatedOperationId=''; FinishedUtc=''
                ReportDirectory =$run.Directory
            }
            $Session.ActiveOperation = $null
            try {
                if ($run.LoggingFailed) { throw 'Audit storage is unavailable; no additional writes are allowed.' }
                if (-not $itemId -or $mailbox -eq '_invalid-input') { throw 'Mailbox and ItemId are required.' }
                if (-not $seen.Add($mailbox.ToLowerInvariant() + '|' + $itemId)) { throw 'The input contains a duplicate mailbox/item ID.' }
                if ($ResendNotification) {
                    try {
                        Assert-ExOPSendPermission -Session $Session -Mailbox $mailbox -SkipSendPermissionCheck:$SkipSendPermissionCheck
                    } catch {
                        $result.Status = 'NotAttempted'
                        throw
                    }
                }
                $item = Get-ExOPCalendarItem -Session $Session -Mailbox $mailbox -ItemId $itemId
                $ns = Get-ExOPNamespaceManager -Node $item
                $result.Subject = Get-ExOPText -Node $item -Path 't:Subject'
                $result.UID = Get-ExOPText -Node $item -Path 't:UID'
                $rooms = Get-ExOPRoomInfo -Item $item
                $result.HasRoom = $rooms.HasRoom
                $result.RoomNames = $rooms.RoomNames
                $result.RoomSmtpAddresses = $rooms.RoomSmtpAddresses
                $result.BackEndServer = $Session.LastBackEndServer
                $marker = Get-ExOPMigrationState -Item $item
                if ($null -eq $marker) {
                    $result.Status = 'NoAction'
                    $result.Severity = 'Information'
                    $result.CalendarState = 'NoIncompleteOperation'
                    $receipt = Get-ExOPMigrationReceipt -Item $item
                    if ($null -ne $receipt) { $result.RelatedOperationId = $receipt.OperationId }
                } else {
                    $result.OperationId = $marker.OperationId
                    $result.RelatedOperationId = $marker.OperationId
                    $result.From = $marker.FromZone
                    $result.To = $marker.ToZone
                    $evidence = Find-ExOPOperationEvidence -SearchDirectory $SearchDirectory -OperationId $marker.OperationId
                    $result.SnapshotPath = $evidence.BeforePath
                    $result.AfterSnapshotPath = $evidence.AfterPath
                    $saved = $evidence.Before
                    if ($saved.SchemaVersion -ne 4 -or $saved.OperationId -cne $marker.OperationId) {
                        throw 'The saved snapshot was written by an unsupported version or for another operation.'
                    }
                    if ($saved.Input.Mailbox -ne $mailbox -or $saved.Input.ItemId -cne $itemId) {
                        throw 'The saved snapshot belongs to a different mailbox or item.'
                    }
                    # Attachment descriptors are only comparable when hashed with the interrupted operation's size limit.
                    if ($null -ne $saved.PSObject.Properties['AttachmentHashLimitBytes']) {
                        $script:MaxAttachmentHashBytes = [long]$saved.AttachmentHashLimitBytes
                    }
                    $result.RecordType = $saved.Input.RecordType
                    $result.StartUtcBefore = $saved.Values.StartUtc
                    $result.EndUtcBefore = $saved.Values.EndUtc
                    $writes = Get-ExOPJournalWriteState -Events $evidence.Events
                    # The marker flag is set before the send; a definitive rejection recorded in the journal after the last send intent proves nothing was sent.
                    $notificationMayHaveStarted = $writes.NotificationAttempted -or ([bool]$marker.NotificationMayHaveStarted -and -not $writes.NotificationRejected)
                    $currentKey = $item.SelectSingleNode('t:ItemId', $ns).GetAttribute('ChangeKey')
                    $zone = $item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
                    if (-not $notificationMayHaveStarted) {
                        $result.Action = 'RestoreOriginal'
                        $result.NotificationStatus = 'NotSent'
                        $verifiedTargetHash = ''
                        if ($writes.NotificationRejected -and $evidence.AfterPath) {
                            $target = Get-Content -LiteralPath $evidence.AfterPath -Raw -Encoding UTF8 | ConvertFrom-Json
                            $verifiedTargetHash = Get-ExOPCalendarStateHash -Snapshot $target
                        }
                        $rollbackKey = if ($writes.NotificationRejected) { [string]$writes.LastChangeKey } else { $currentKey }
                        # Rejected sends may save a new key without changing the verified target. Retain the acknowledged
                        # key and target hash so rollback can distinguish that save from a concurrent edit.
                        $operation = [PSCustomObject]@{
                            Run=$run; OperationId=$marker.OperationId; Mailbox=$mailbox; ItemId=$itemId
                            Phase='Reconcile'; LastChangeKey=$rollbackKey; AcknowledgedWrites=[Math]::Max(1, $writes.AcknowledgedWrites)
                            WriteAttempted=$true; LastWriteUnknown=$writes.LastWriteUnknown
                            MetadataWritten=$writes.MetadataWritten; DatesWritten=$writes.DatesWritten; NotificationStarted=$false
                            RollingBack=$false; IsSeries=($saved.Input.RecordType -eq 'RecurringSeries'); Before=$saved.Snapshot
                            Values=$saved.Values; Prepared=$null; OriginalStateHash=(Get-ExOPCalendarStateHash -Snapshot $saved.Snapshot)
                            VerifiedTargetHash=$verifiedTargetHash; JournalChangeKey=[string]$writes.LastChangeKey
                            NotificationRejected =$writes.NotificationRejectionCode; RollbackInProgress=$writes.RollbackStarted
                        }
                        Write-ExOPMigrationAudit -Run $run -Mailbox $mailbox -OperationId $marker.OperationId -Phase 'Reconcile' `
                            -EventName 'ReconcileBaseline' -Data ([ordered]@{
                                InterruptedRunJournal=$evidence.JournalPath; BeforeSnapshot=$evidence.BeforePath
                                JournalLastChangeKey=$writes.LastChangeKey; CurrentChangeKey=$currentKey
                                AcknowledgedWrites=$writes.AcknowledgedWrites; LastWriteUnknown=$writes.LastWriteUnknown
                                MetadataWritten=$writes.MetadataWritten; DatesWritten=$writes.DatesWritten
                                NotificationRejected=$writes.NotificationRejectionCode; VerifiedTargetHash=$verifiedTargetHash; RollbackInProgress=$writes.RollbackStarted
                            })
                        if (-not $Apply) {
                            $result.Status = 'Preview'
                            $result.Severity = 'Information'
                        } elseif ($PSCmdlet.ShouldProcess("$($mailbox): $itemId", 'Restore the original state of an interrupted migration')) {
                            $Session.ActiveOperation = $operation
                            $result.RollbackStatus = 'Attempted'
                            try {
                                $result.RollbackSnapshotPath = Invoke-ExOPPreSendRollback -Session $Session -Operation $operation
                            } catch {
                                $result.RollbackStatus = 'Failed'
                                $result.RollbackError = $_.Exception.Message
                                $result.CalendarState = 'RequiresManualAttention'
                                $result.Status = 'Critical'
                                $result.Severity = 'Critical'
                                throw
                            }
                            $result.RollbackStatus = 'Verified'
                            $result.Status = 'RolledBack'
                            $result.Severity = 'Warning'
                            $result.CalendarState = 'OriginalVerified'
                        } else {
                            $result.Status = if ($WhatIfPreference) { 'WhatIf' } else { 'Skipped' }
                            $result.Severity = 'Information'
                        }
                    } else {
                        # After a possible notification the item is never moved back; only a proven target state is finalized.
                        $result.Action = 'FinalizeTarget'
                        $result.NotificationStatus = 'OutcomeUnknown'
                        $result.RollbackStatus = 'ProhibitedAfterNotification'
                        if (-not $evidence.AfterPath) { throw 'No verified target snapshot exists; the state after a possible notification cannot be proven.' }
                        $target = Get-Content -LiteralPath $evidence.AfterPath -Raw -Encoding UTF8 | ConvertFrom-Json
                        $targetHash = Get-ExOPCalendarStateHash -Snapshot $target
                        $current = Get-ExOPItemSnapshot -Session $Session -Mailbox $mailbox -Item $item -From $zone -To $zone
                        $currentHash = Get-ExOPCalendarStateHash -Snapshot $current
                        if ($currentHash -cne $targetHash) {
                            throw 'The item does not match its verified target state and notification may have been sent; it was not changed.'
                        }
                        $result.CalendarState = 'TargetVerified'
                        $result.StartUtcAfter = $saved.Values.NewStartUtc
                        $result.EndUtcAfter = $saved.Values.NewEndUtc
                        if (-not $Apply) {
                            $result.Status = 'Preview'
                            $result.Severity = 'Information'
                        } elseif ($PSCmdlet.ShouldProcess("$($mailbox): $itemId", 'Finalize an interrupted migration that is already in its verified target state')) {
                            $operation = [PSCustomObject]@{
                                Run=$run; OperationId=$marker.OperationId; Mailbox=$mailbox; ItemId=$itemId
                                Phase='ReconcileFinalize'; LastChangeKey=$currentKey; AcknowledgedWrites=0; WriteAttempted=$false
                                LastWriteUnknown=$false; NotificationStarted=$true
                            }
                            $Session.ActiveOperation = $operation
                            if ($ResendNotification -and (Test-ExOPNotificationRequired -Item $item)) {
                                $operation.Phase = 'Notification'
                                Send-ExOPSeriesUpdate -Session $Session -Mailbox $mailbox -Item $item
                                $result.NotificationStatus = 'SendAcknowledged'
                                $item = Get-ExOPCalendarItem -Session $Session -Mailbox $mailbox -ItemId $itemId
                            }
                            $plan = $writes.Plan
                            $receipt = [ordered]@{
                                SchemaVersion=1; OperationId=$marker.OperationId; RunId=$saved.RunId
                                InputHash=(Get-ExOPCanonicalHash -Value $saved.Input); StateHash=$targetHash; StateHashVersion=5
                                FromZone=$marker.FromZone; ToZone=$marker.ToZone; AttachmentHashLimitBytes=[long]$script:MaxAttachmentHashBytes
                                O12Modes       =$(if ($null -ne $plan) { $plan.O12Modes } else { $null })
                                ExceptionModes =$(if ($null -ne $plan) { $plan.ExceptionModes } else { $null })
                                CompletedUtc=[DateTimeOffset]::UtcNow.ToString('o'); Reconciled=$true
                            }
                            $operation.Phase = 'FinalizeReceipt'
                            # A notification may have been delivered, so attendee responses can still update the item.
                            Set-ExOPVerifiedFinalMigrationState -Session $Session -Mailbox $mailbox -ItemId $itemId -Item $item `
                                -Receipt $receipt -TargetHash $targetHash
                            $item = Get-ExOPCalendarItem -Session $Session -Mailbox $mailbox -ItemId $itemId
                            $zone = $item.SelectSingleNode('t:StartTimeZone', (Get-ExOPNamespaceManager -Node $item)).GetAttribute('Id')
                            $final = Get-ExOPItemSnapshot -Session $Session -Mailbox $mailbox -Item $item -From $zone -To $zone
                            if ($null -ne (Get-ExOPMigrationState -Item $item) -or
                                (Get-ExOPMigrationReceipt -Item $item).OperationId -cne $marker.OperationId -or
                                (Get-ExOPCalendarStateHash -Snapshot $final) -cne $targetHash) {
                                throw 'Final reconcile bookkeeping did not pass read-back verification.'
                            }
                            $result.Status = 'Applied'
                            $result.Severity = if ($result.NotificationStatus -eq 'SendAcknowledged') { 'Information' } else { 'Warning' }
                        } else {
                            $result.Status = if ($WhatIfPreference) { 'WhatIf' } else { 'Skipped' }
                            $result.Severity = 'Information'
                        }
                    }
                }
            } catch {
                $result.Error = $_.Exception.Message
                $result.ErrorCode = [string]$_.Exception.Data['EwsResponseCode']
                if ($result.Status -notin 'Critical', 'NoAction', 'NotAttempted') {
                    # Any item that still carries a marker after a failed reconcile needs manual attention.
                    $result.Status = if ($result.OperationId) { 'Critical' } else { 'Failed' }
                    $result.Severity = if ($result.OperationId) { 'Critical' } else { 'Warning' }
                    if ($result.OperationId -and $result.CalendarState -eq 'Unknown') { $result.CalendarState = 'RequiresManualAttention' }
                }
                if ($run.LoggingFailed) { $result.Error += ' Audit storage failed; processing stopped.' }
                Write-Warning ("{0}: {1}. {2}" -f $result.Severity.ToUpperInvariant(), $result.Status, $result.Error)
            } finally {
                $Session.ActiveOperation = $null
                $script:MaxAttachmentHashBytes = $runAttachmentHashBytes
            }
            Complete-ExOPMigrationResult -Run $run -Result $result
            Write-Output -InputObject $result
        }
        Update-ExOPFinalMigrationSummary -Run $run
    }
}
