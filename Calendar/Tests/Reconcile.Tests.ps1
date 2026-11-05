# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cspell:ignore Rehome Rehoming

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\EwsTransport.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\CalendarTimeZoneData.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\MigrationJournal.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Rehoming.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Reconcile.ps1

    $Script:operationId = '0123456789abcdef0123456789abcdef'
    $Script:mailbox = 'user@contoso.com'
    $Script:itemId = 'item-1'
    $Script:session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'

    # No test may reach Exchange; every writer is replaced by a mock whose calls are counted.
    Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
    Mock Set-ExOPCalendarFields { }
    Mock Send-ExOPSeriesUpdate { }
    Mock Set-ExOPFinalMigrationState { }

    function New-JournalRecord {
        param(
            [string]
            $EventName,

            [string]
            $Phase,

            $Data,

            [string]
            $OperationId = $Script:operationId
        )
        [PSCustomObject]@{ SchemaVersion = 1; Mailbox = $Script:mailbox; OperationId = $OperationId; Phase = $Phase; Event = $EventName; Data = $Data }
    }

    function New-InterruptedJournal {
        param(
            [switch]
            $PendingIntent,

            [switch]
            $NotificationIntent
        )
        @(
            New-JournalRecord -EventName 'PlanValidated' -Phase 'Plan' -Data ([PSCustomObject]@{ O12Modes = 'none' })
            New-JournalRecord -EventName 'WriteIntent' -Phase 'Marker' -Data ([PSCustomObject]@{ ChangeKey = 'CK-0'; Send = $false })
            New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'Marker' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1' })
            New-JournalRecord -EventName 'WriteIntent' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1'; Send = $false })
            New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2' })
            New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-other' }) -OperationId 'fedcba9876543210fedcba9876543210'
            New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-upper' }) -OperationId $Script:operationId.ToUpperInvariant()
            if ($PendingIntent) {
                New-JournalRecord -EventName 'WriteIntent' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $false })
            }
            if ($NotificationIntent) {
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $true })
            }
        )
    }

    function New-ReconcileSnapshot {
        param(
            [string]
            $Subject,

            [string]
            $BodyText = 'Agenda'
        )
        [PSCustomObject]@{
            Xml                = '<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:ItemId Id="item-1" ChangeKey="CK-0"/>' +
            '<t:Subject>' + $Subject + '</t:Subject><t:Body BodyType="HTML">&lt;p&gt;' + $BodyText + '&lt;/p&gt;</t:Body><t:ReminderIsSet>false</t:ReminderIsSet>' +
            '<t:Start>2026-11-09T18:00:00Z</t:Start><t:End>2026-11-09T19:00:00Z</t:End><t:UID>calendar-uid-1</t:UID>' +
            '<t:StartTimeZone Id="Pacific Standard Time"/><t:EndTimeZone Id="Pacific Standard Time"/></t:CalendarItem>'
            TimeZoneProperties = @()
            Attachments        = @()
            Deleted            = @()
            Modified           = @()
            Receipt            = $null
        }
    }

    function Write-OperationEvidence {
        param(
            [string]
            $Directory,

            [object[]]
            $Events,

            $After,

            [string]
            $Subject = 'Original',

            [string]
            $BodyText = 'Agenda',

            [long]
            $AttachmentHashLimitBytes = -1
        )
        $null = New-Item -ItemType Directory -Path $Directory -Force
        $before = [ordered]@{
            SchemaVersion = 4
            OperationId   = $Script:operationId
            RunId         = 'interrupted-run'
            Input         = [ordered]@{ Mailbox = $Script:mailbox; ItemId = $Script:itemId; RecordType = 'Single' }
            Values        = [ordered]@{
                StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; NewStartZone = 'Mountain Standard Time'; NewEndZone = 'Mountain Standard Time'
                StartUtc = '2026-11-09T18:00:00.0000000Z'; EndUtc = '2026-11-09T19:00:00.0000000Z'; NewStartUtc = '2026-11-09T17:00:00.0000000Z'; NewEndUtc = '2026-11-09T18:00:00.0000000Z'
            }
            Snapshot      = New-ReconcileSnapshot -Subject $Subject -BodyText $BodyText
        }
        if ($AttachmentHashLimitBytes -ge 0) { $before['AttachmentHashLimitBytes'] = $AttachmentHashLimitBytes }
        Write-ExOPDurableText -Path (Join-Path -Path $Directory -ChildPath "$($Script:operationId)-before.json") -Text (ConvertTo-Json -InputObject $before -Depth 35)
        if ($null -ne $After) {
            Write-ExOPDurableText -Path (Join-Path -Path $Directory -ChildPath "$($Script:operationId)-after.json") -Text (ConvertTo-Json -InputObject $After -Depth 35)
        }
        if ($Events.Count -gt 0) {
            $lines = @($Events | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 10 -Compress })
            Write-ExOPDurableText -Path (Join-Path -Path $Directory -ChildPath 'details.jsonl') -Text (($lines -join "`r`n") + "`r`n")
        }
    }

    function New-ReconcileItem {
        param(
            [string]
            $ChangeKey,

            [switch]
            $WithMarker,

            [bool]
            $NotificationMayHaveStarted,

            [switch]
            $WithAttendees,

            [string]
            $ReceiptOperationId
        )
        $marker = ''
        if ($WithMarker) {
            $state = ConvertTo-Json -Compress -InputObject ([ordered]@{
                    SchemaVersion              = 1
                    Status                     = 'InProgress'
                    OperationId                = $Script:operationId
                    FromZone                   = 'Pacific Standard Time'
                    ToZone                     = 'Mountain Standard Time'
                    NotificationMayHaveStarted = $NotificationMayHaveStarted
                })
            $marker = '<t:ExtendedProperty>' + $script:MigrationStateFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $state) + '</t:Value></t:ExtendedProperty>'
        }
        if ($ReceiptOperationId) {
            $receipt = ConvertTo-Json -Compress -InputObject ([ordered]@{ SchemaVersion = 1; OperationId = $ReceiptOperationId; StateHash = 'verified' })
            $marker += '<t:ExtendedProperty>' + $script:MigrationReceiptFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $receipt) + '</t:Value></t:ExtendedProperty>'
        }
        if ($WithAttendees) {
            $marker = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>attendee@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees>' + $marker
        }
        $document = New-Object Xml.XmlDocument
        $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:ItemId Id="' + $Script:itemId + '" ChangeKey="' + $ChangeKey + '"/>' +
            '<t:Subject>Weekly sync</t:Subject><t:UID>calendar-uid-1</t:UID><t:CalendarItemType>Single</t:CalendarItemType><t:IsMeeting>true</t:IsMeeting>' +
            '<t:StartTimeZone Id="Pacific Standard Time"/><t:EndTimeZone Id="Pacific Standard Time"/>' + $marker + '</t:CalendarItem>')
        Write-Output -InputObject $document.DocumentElement -NoEnumerate
    }

    function Invoke-TestReconcile {
        param(
            [string]
            $Name,

            [switch]
            $Apply,

            [switch]
            $ResendNotification
        )
        $Script:evidenceDirectory = Join-Path -Path $TestDrive -ChildPath "$Name-evidence"
        $Script:logDirectory = Join-Path -Path $TestDrive -ChildPath "$Name-logs"
        $null = New-Item -ItemType Directory -Path $Script:evidenceDirectory -Force
        $row = [PSCustomObject]@{ Mailbox = $Script:mailbox; ItemId = $Script:itemId; RecordType = 'Single' }
        Invoke-ExOPCalendarMigrationReconcile -Session $Script:session -InputObject $row -SearchDirectory $Script:evidenceDirectory `
            -LogDirectory $Script:logDirectory -Apply:$Apply -ResendNotification:$ResendNotification -Confirm:$false -WarningAction SilentlyContinue
    }

    function Get-RunJournal {
        param(
            [string]
            $Directory
        )
        foreach ($file in Get-ChildItem -LiteralPath $Directory -Recurse -Filter 'details.jsonl') {
            foreach ($line in [IO.File]::ReadAllLines($file.FullName)) {
                if ($line) { $line | ConvertFrom-Json }
            }
        }
    }
}

Describe 'Testing Reconcile.ps1' {
    BeforeAll {
        # Offline tests run as the mailbox owner; the delegate send-permission check has its own contexts.
        Mock Get-ExOPSendPermission { [PSCustomObject]@{ Mode = 'Owner'; Error = '' } }
    }
    Context 'Get-ExOPJournalWriteState' {
        It 'Returns defaults for an empty journal' {
            $state = Get-ExOPJournalWriteState -Events @()
            $state.LastChangeKey | Should -BeExactly ''
            $state.AcknowledgedWrites | Should -Be 0
            $state.WriteAttempted | Should -BeFalse
            $state.LastWriteUnknown | Should -BeFalse
            $state.NotificationAttempted | Should -BeFalse
            $state.Plan | Should -BeNullOrEmpty
            $state.RollbackStarted | Should -BeFalse
        }

        It 'Detects a rollback that an earlier run started' {
            $state = Get-ExOPJournalWriteState -Events @(
                New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2' })
                New-JournalRecord -EventName 'RollbackStarted' -Phase 'RollbackInspection' -Data $null
            )
            $state.RollbackStarted | Should -BeTrue
        }

        It 'Keeps an earlier <Outcome> send when a later resend is rejected' -ForEach @(
            @{ Outcome = 'acknowledged'; Acknowledged = $true }
            @{ Outcome = 'unknown'; Acknowledged = $false }
        ) {
            $events = @(
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $true })
                if ($Acknowledged) { New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-3' }) }
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-3'; Send = $true })
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ Code = 'ErrorSendAsDenied' })
            )
            $state = Get-ExOPJournalWriteState -Events $events
            $state.NotificationAttempted | Should -BeTrue
            $state.NotificationRejected | Should -BeFalse
        }

        It 'Tracks acknowledged writes by phase' {
            $events = @(
                New-JournalRecord -EventName 'PlanValidated' -Phase 'Plan' -Data ([PSCustomObject]@{ O12Modes = 'none' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Marker' -Data ([PSCustomObject]@{ ChangeKey = 'CK-0'; Send = $false })
                New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'Marker' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1'; Send = $false })
                New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $false })
                New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-3' })
            )
            $state = Get-ExOPJournalWriteState -Events $events
            $state.Plan.O12Modes | Should -BeExactly 'none'
            $state.AcknowledgedWrites | Should -Be 3
            $state.LastChangeKey | Should -BeExactly 'CK-3'
            $state.WriteAttempted | Should -BeTrue
            $state.LastWriteUnknown | Should -BeFalse
            $state.MetadataWritten | Should -BeTrue
            $state.DatesWritten | Should -BeTrue
            $state.NotificationAttempted | Should -BeFalse
        }

        It 'Treats a trailing intent without acknowledgement as unknown' {
            $events = @(
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Marker' -Data ([PSCustomObject]@{ ChangeKey = 'CK-0'; Send = $false })
                New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'Marker' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1'; Send = $false })
            )
            $state = Get-ExOPJournalWriteState -Events $events
            $state.LastWriteUnknown | Should -BeTrue
            $state.LastChangeKey | Should -BeExactly 'CK-1'
            $state.AcknowledgedWrites | Should -Be 1
            $state.MetadataWritten | Should -BeFalse
        }

        It 'Detects a notification attempt in the Notification phase' {
            $events = @(New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1' }))
            (Get-ExOPJournalWriteState -Events $events).NotificationAttempted | Should -BeTrue
        }

        It 'Detects a notification attempt from a write that sends' {
            $events = @(New-JournalRecord -EventName 'WriteIntent' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-1'; Send = $true }))
            (Get-ExOPJournalWriteState -Events $events).NotificationAttempted | Should -BeTrue
        }

        It 'Reports no rejected notification by default' {
            (Get-ExOPJournalWriteState -Events @()).NotificationRejected | Should -BeFalse
        }

        It 'Clears a notification attempt that Exchange rejected definitively' {
            $events = @(
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $true })
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ ItemId = 'item-1'; Code = 'ErrorSendAsDenied' })
            )
            $state = Get-ExOPJournalWriteState -Events $events
            $state.NotificationAttempted | Should -BeFalse
            $state.NotificationRejected | Should -BeTrue
            $state.NotificationRejectionCode | Should -BeExactly 'ErrorSendAsDenied'
            $state.LastWriteUnknown | Should -BeFalse
            $state.WriteAttempted | Should -BeTrue
        }

        It 'Treats a later sending write after a rejection as a new notification attempt' {
            $events = @(
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $true })
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ ItemId = 'item-1'; Code = 'ErrorSendAsDenied' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-3'; Send = $true })
            )
            $state = Get-ExOPJournalWriteState -Events $events
            $state.NotificationAttempted | Should -BeTrue
            $state.NotificationRejected | Should -BeFalse
            $state.NotificationRejectionCode | Should -BeExactly ''
            $state.LastWriteUnknown | Should -BeTrue
        }

        It 'Keeps the rejection across later writes that do not send' {
            $events = @(
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $true })
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ ItemId = 'item-1'; Code = 'ErrorInvalidRecipients' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-3'; Send = $false })
                New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-4' })
            )
            $state = Get-ExOPJournalWriteState -Events $events
            $state.NotificationAttempted | Should -BeFalse
            $state.NotificationRejected | Should -BeTrue
            $state.LastWriteUnknown | Should -BeFalse
            $state.LastChangeKey | Should -BeExactly 'CK-4'
            $state.NotificationRejectionCode | Should -BeExactly 'ErrorInvalidRecipients'
        }

        It 'Rejects journal entries that do not prove a definitive send rejection' {
            $events = @(New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ Code = 'ErrorInternalServerError' }))
            { Get-ExOPJournalWriteState -Events $events } | Should -Throw -ExpectedMessage '*definitive notification rejection code*'
        }

        It 'Keeps an attempt that was not rejected when an earlier one was' {
            $events = @(
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ ItemId = 'item-1'; Code = 'ErrorSendAsDenied' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-3'; Send = $true })
            )
            $state = Get-ExOPJournalWriteState -Events $events
            $state.NotificationAttempted | Should -BeTrue
            $state.NotificationRejected | Should -BeFalse
        }
    }

    Context 'Find-ExOPOperationEvidence' {
        It 'Rejects the operation ID <_>' -ForEach @('not-an-operation-id', '0123456789abcdef0123456789abcde', '0123456789abcdef0123456789abcdef0', '..\0123456789abcdef0123456789abcdef', '0123456789ABCDEF0123456789ABCDEF', '0123456789abcdef0123456789abcdeF') {
            { Find-ExOPOperationEvidence -SearchDirectory $TestDrive -OperationId $_ } | Should -Throw -ExpectedMessage '*invalid operation ID*'
        }

        It 'Requires a saved before snapshot' {
            $directory = Join-Path -Path $TestDrive -ChildPath 'find-none'
            $null = New-Item -ItemType Directory -Path $directory
            { Find-ExOPOperationEvidence -SearchDirectory $directory -OperationId $Script:operationId } | Should -Throw -ExpectedMessage '*found 0*'
        }

        It 'Rejects two saved before snapshots' {
            $directory = Join-Path -Path $TestDrive -ChildPath 'find-two'
            Write-OperationEvidence -Directory (Join-Path -Path $directory -ChildPath 'first') -Events @()
            Write-OperationEvidence -Directory (Join-Path -Path $directory -ChildPath 'second') -Events @()
            { Find-ExOPOperationEvidence -SearchDirectory $directory -OperationId $Script:operationId } | Should -Throw -ExpectedMessage '*found 2*'
        }

        It 'Treats the after snapshot and journal as optional' {
            $directory = Join-Path -Path $TestDrive -ChildPath 'find-minimal'
            Write-OperationEvidence -Directory $directory -Events @()
            $evidence = Find-ExOPOperationEvidence -SearchDirectory $directory -OperationId $Script:operationId
            $evidence.BeforePath | Should -BeLike "*$($Script:operationId)-before.json"
            $evidence.Before.OperationId | Should -BeExactly $Script:operationId
            $evidence.AfterPath | Should -BeExactly ''
            $evidence.JournalPath | Should -BeExactly ''
            @($evidence.Events) | Should -HaveCount 0
        }

        It 'Returns only journal events of the exact operation ID' {
            $directory = Join-Path -Path $TestDrive -ChildPath 'find-complete'
            Write-OperationEvidence -Directory $directory -Events (New-InterruptedJournal) -After (New-ReconcileSnapshot -Subject 'Target')
            $evidence = Find-ExOPOperationEvidence -SearchDirectory $directory -OperationId $Script:operationId
            $evidence.AfterPath | Should -BeLike "*$($Script:operationId)-after.json"
            $evidence.JournalPath | Should -BeLike '*details.jsonl'
            @($evidence.Events) | Should -HaveCount 5
            @($evidence.Events | Where-Object { $_.OperationId -cne $Script:operationId }) | Should -HaveCount 0
        }

        It 'Ignores an unterminated record left by an interrupted append of <Owner>' -ForEach @(
            @{ Owner = 'this operation'; OperationId = '0123456789abcdef0123456789abcdef' }
            @{ Owner = 'another operation'; OperationId = 'fedcba9876543210fedcba9876543210' }
        ) {
            $directory = Join-Path -Path $TestDrive -ChildPath "find-torn-$Owner"
            Write-OperationEvidence -Directory $directory -Events (New-InterruptedJournal) -After (New-ReconcileSnapshot -Subject 'Target')
            Write-ExOPDurableText -Path (Join-Path -Path $directory -ChildPath 'details.jsonl') -Append `
                -Text ('{"SchemaVersion":1,"OperationId":"' + $OperationId + '","Phase":"MasterDates","Event":"WriteInt')
            $evidence = Find-ExOPOperationEvidence -SearchDirectory $directory -OperationId $Script:operationId
            @($evidence.Events) | Should -HaveCount 5
            (Get-ExOPJournalWriteState -Events $evidence.Events).LastWriteUnknown | Should -BeFalse
        }

        It 'Still rejects a malformed complete journal record' {
            $directory = Join-Path -Path $TestDrive -ChildPath 'find-malformed'
            Write-OperationEvidence -Directory $directory -Events (New-InterruptedJournal)
            Write-ExOPDurableText -Path (Join-Path -Path $directory -ChildPath 'details.jsonl') -Append -Text ("{not json`r`n")
            { Find-ExOPOperationEvidence -SearchDirectory $directory -OperationId $Script:operationId } | Should -Throw
        }

        It 'Adds the records of an earlier reconcile run below the search directory in time order' {
            $directory = Join-Path -Path $TestDrive -ChildPath 'find-reconcile-runs'
            Write-OperationEvidence -Directory (Join-Path -Path $directory -ChildPath 'migration') -Events (New-InterruptedJournal)
            $records = @(
                [PSCustomObject]@{ SchemaVersion = 1; Utc = '2026-11-05T10:00:02.0000000+00:00'; Sequence = 3; OperationId = $Script:operationId; Phase = 'TimezoneMetadata'; Event = 'WriteAcknowledged'; Data = [PSCustomObject]@{ ChangeKey = 'CK-4' } }
                [PSCustomObject]@{ SchemaVersion = 1; Utc = '2026-11-05T10:00:01.0000000+00:00'; Sequence = 2; OperationId = $Script:operationId; Phase = 'RollbackInspection'; Event = 'RollbackStarted'; Data = $null }
                [PSCustomObject]@{ SchemaVersion = 1; Utc = '2026-11-05T10:00:00.5000000+00:00'; Sequence = 1; OperationId = 'fedcba9876543210fedcba9876543210'; Phase = 'Reconcile'; Event = 'RollbackStarted'; Data = $null }
            )
            $reconcileRun = Join-Path -Path $directory -ChildPath 'reconcile\user'
            $null = New-Item -ItemType Directory -Path $reconcileRun -Force
            Write-ExOPDurableText -Path (Join-Path -Path $reconcileRun -ChildPath 'details.jsonl') `
                -Text ((@($records | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 5 -Compress }) -join "`r`n") + "`r`n")
            $evidence = Find-ExOPOperationEvidence -SearchDirectory $directory -OperationId $Script:operationId
            @($evidence.Events) | Should -HaveCount 7
            $evidence.Events[5].Event | Should -BeExactly 'RollbackStarted'
            $evidence.Events[6].Data.ChangeKey | Should -BeExactly 'CK-4'
            $evidence.JournalPath | Should -BeLike '*\migration\details.jsonl'
            $state = Get-ExOPJournalWriteState -Events $evidence.Events
            $state.LastChangeKey | Should -BeExactly 'CK-4'
            $state.RollbackStarted | Should -BeTrue
        }
    }

    Context 'Reconcile records the EWS URL source of the session' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' }
            $Script:sourceText = 'Autodiscover DNS https://autodiscover.contoso.com/autodiscover/autodiscover.xml (EXPR)'
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx' -EwsUrlSource $Script:sourceText
            $searchDirectory = Join-Path -Path $TestDrive -ChildPath 'source-evidence'
            $Script:sourceLogDirectory = Join-Path -Path $TestDrive -ChildPath 'source-logs'
            $null = New-Item -ItemType Directory -Path $searchDirectory -Force
            $row = [PSCustomObject]@{ Mailbox = $Script:mailbox; ItemId = $Script:itemId; RecordType = 'Single' }
            $Script:result = Invoke-ExOPCalendarMigrationReconcile -Session $session -InputObject $row -SearchDirectory $searchDirectory `
                -LogDirectory $Script:sourceLogDirectory -Confirm:$false -WarningAction SilentlyContinue
        }

        It 'Writes the session EWS URL and source to run.json' {
            $Script:result.Status | Should -BeExactly 'NoAction'
            $manifestFile = @(Get-ChildItem -LiteralPath $Script:sourceLogDirectory -Recurse -Filter 'run.json')
            $manifestFile | Should -HaveCount 1
            $manifest = Get-Content -LiteralPath $manifestFile[0].FullName -Raw | ConvertFrom-Json
            $manifest.EwsUrl | Should -BeExactly 'https://mail.contoso.com/EWS/Exchange.asmx'
            $manifest.EwsUrlSource | Should -BeExactly $Script:sourceText
        }
    }

    Context 'Reconcile an item without a migration marker' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' }
            Mock Invoke-ExOPPreSendRollback { 'unexpected' }
            $Script:result = Invoke-TestReconcile -Name 'no-marker' -Apply
        }

        It 'Reports NoAction' {
            $Script:result.Status | Should -BeExactly 'NoAction'
            $Script:result.Severity | Should -BeExactly 'Information'
            $Script:result.CalendarState | Should -BeExactly 'NoIncompleteOperation'
        }

        It 'Counts the item as NoAction in the mailbox overview' {
            $overview = @(Get-ChildItem -LiteralPath $Script:logDirectory -Recurse -Filter 'mailboxes.csv' | ForEach-Object { Import-Csv -LiteralPath $_.FullName })
            $overview | Should -HaveCount 1
            $overview[0].NoAction | Should -BeExactly '1'
            $overview[0].NotAttempted | Should -BeExactly '0'
        }

        It 'Changes nothing' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPCalendarFields -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPFinalMigrationState -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Reconcile a marked item without saved evidence' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker }
            Mock Invoke-ExOPPreSendRollback { 'unexpected' }
            $Script:result = Invoke-TestReconcile -Name 'no-evidence' -Apply
        }

        It 'Reports a critical result' {
            $Script:result.Status | Should -BeExactly 'Critical'
            $Script:result.Severity | Should -BeExactly 'Critical'
            $Script:result.CalendarState | Should -BeExactly 'RequiresManualAttention'
            $Script:result.OperationId | Should -BeExactly $Script:operationId
            $Script:result.Error | Should -BeLike '*found 0*'
        }

        It 'Changes nothing' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPCalendarFields -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Preview of a pre-notification rollback' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker }
            Mock Invoke-ExOPPreSendRollback { 'unexpected' }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'preview-evidence') -Events (New-InterruptedJournal)
            $Script:result = Invoke-TestReconcile -Name 'preview'
            $Script:baseline = @(Get-RunJournal -Directory $Script:logDirectory | Where-Object { $_.Event -eq 'ReconcileBaseline' })
        }

        It 'Reports the planned restore without applying it' {
            $Script:result.Status | Should -BeExactly 'Preview'
            $Script:result.Action | Should -BeExactly 'RestoreOriginal'
            $Script:result.NotificationStatus | Should -BeExactly 'NotSent'
            $Script:result.SnapshotPath | Should -BeLike "*$($Script:operationId)-before.json"
        }

        It 'Records the reconcile baseline' {
            $Script:baseline | Should -HaveCount 1
            $Script:baseline[0].Data.JournalLastChangeKey | Should -BeExactly 'CK-2'
            $Script:baseline[0].Data.CurrentChangeKey | Should -BeExactly 'CK-current'
        }

        It 'Does not roll back or write' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPCalendarFields -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Applied pre-notification rollback' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker }
            Mock Invoke-ExOPPreSendRollback { 'rollback-verified.json' }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'rollback-evidence') -Events (New-InterruptedJournal)
            $Script:result = Invoke-TestReconcile -Name 'rollback' -Apply
            $Script:baseline = @(Get-RunJournal -Directory $Script:logDirectory | Where-Object { $_.Event -eq 'ReconcileBaseline' })
        }

        It 'Reports a verified rollback' {
            $Script:result.Status | Should -BeExactly 'RolledBack'
            $Script:result.CalendarState | Should -BeExactly 'OriginalVerified'
            $Script:result.RollbackStatus | Should -BeExactly 'Verified'
            $Script:result.RollbackSnapshotPath | Should -BeExactly 'rollback-verified.json'
        }

        It 'Rolls back once from the current ChangeKey with journal-derived write state' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times 1 -Exactly -Scope Context
            Should -Invoke Invoke-ExOPPreSendRollback -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Operation.OperationId -ceq $Script:operationId -and
                $Operation.LastChangeKey -ceq 'CK-current' -and
                $Operation.AcknowledgedWrites -eq 2 -and
                $Operation.MetadataWritten -eq $true -and
                $Operation.DatesWritten -eq $false -and
                $Operation.LastWriteUnknown -eq $false -and
                $Operation.NotificationStarted -eq $false
            }
        }

        It 'Records the journal and current ChangeKeys in the new run journal' {
            $Script:baseline | Should -HaveCount 1
            $data = $Script:baseline[0].Data
            $data.JournalLastChangeKey | Should -BeExactly 'CK-2'
            $data.CurrentChangeKey | Should -BeExactly 'CK-current'
            $data.AcknowledgedWrites | Should -Be 2
            $data.LastWriteUnknown | Should -BeFalse
            $data.MetadataWritten | Should -BeTrue
            $data.DatesWritten | Should -BeFalse
            $Script:baseline[0].OperationId | Should -BeExactly $Script:operationId
        }

        It 'Performs no other writes' {
            Should -Invoke Set-ExOPCalendarFields -Times 0 -Exactly -Scope Context
            Should -Invoke Send-ExOPSeriesUpdate -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Applied pre-notification rollback with an unacknowledged last write' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker }
            Mock Invoke-ExOPPreSendRollback { 'rollback-verified.json' }
            $events = @(New-JournalRecord -EventName 'WriteIntent' -Phase 'Marker' -Data ([PSCustomObject]@{ ChangeKey = 'CK-0'; Send = $false }))
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'unknown-evidence') -Events $events
            $Script:result = Invoke-TestReconcile -Name 'unknown' -Apply
        }

        It 'Treats at least one write as acknowledged and the last outcome as unknown' {
            $Script:result.Status | Should -BeExactly 'RolledBack'
            Should -Invoke Invoke-ExOPPreSendRollback -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Operation.LastChangeKey -ceq 'CK-current' -and $Operation.AcknowledgedWrites -eq 1 -and $Operation.LastWriteUnknown -eq $true
            }
        }
    }

    Context 'Failed pre-notification rollback' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker }
            Mock Invoke-ExOPPreSendRollback { throw 'Simulated rollback failure.' }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'failed-evidence') -Events (New-InterruptedJournal)
            $Script:result = Invoke-TestReconcile -Name 'failed' -Apply
        }

        It 'Reports a critical result with the rollback error' {
            $Script:result.Status | Should -BeExactly 'Critical'
            $Script:result.Severity | Should -BeExactly 'Critical'
            $Script:result.RollbackStatus | Should -BeExactly 'Failed'
            $Script:result.RollbackError | Should -BeExactly 'Simulated rollback failure.'
            $Script:result.CalendarState | Should -BeExactly 'RequiresManualAttention'
            Should -Invoke Invoke-ExOPPreSendRollback -Times 1 -Exactly -Scope Context
        }
    }

    Context 'Notification may have started according to <Source>' -ForEach @(
        @{ Source = 'the marker'; MarkerFlag = $true; NotificationIntent = $false }
        @{ Source = 'the journal'; MarkerFlag = $false; NotificationIntent = $true }
    ) {
        BeforeAll {
            $Script:markerFlag = $MarkerFlag
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $Script:markerFlag }
            Mock Invoke-ExOPPreSendRollback { 'unexpected' }
            Mock Get-ExOPItemSnapshot { New-ReconcileSnapshot -Subject 'Target' }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath "notification-$MarkerFlag-evidence") -Events (New-InterruptedJournal -NotificationIntent:$NotificationIntent)
            $Script:result = Invoke-TestReconcile -Name "notification-$MarkerFlag" -Apply
        }

        It 'Reports a critical result when no verified target snapshot exists' {
            $Script:result.Status | Should -BeExactly 'Critical'
            $Script:result.Action | Should -BeExactly 'FinalizeTarget'
            $Script:result.RollbackStatus | Should -BeExactly 'ProhibitedAfterNotification'
            $Script:result.Error | Should -BeLike '*No verified target snapshot*'
        }

        It 'Never moves the item back or writes' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPCalendarFields -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPFinalMigrationState -Times 0 -Exactly -Scope Context
            Should -Invoke Get-ExOPItemSnapshot -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Post-notification item that differs from its verified target' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true }
            Mock Invoke-ExOPPreSendRollback { 'unexpected' }
            Mock Get-ExOPItemSnapshot { New-ReconcileSnapshot -Subject 'Changed by the organizer' }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'mismatch-evidence') -Events (New-InterruptedJournal) -After (New-ReconcileSnapshot -Subject 'Target')
            $Script:result = Invoke-TestReconcile -Name 'mismatch' -Apply
        }

        It 'Reports a critical result' {
            $Script:result.Status | Should -BeExactly 'Critical'
            $Script:result.Error | Should -BeLike '*does not match its verified target state*'
            Should -Invoke Get-ExOPItemSnapshot -Times 1 -Exactly -Scope Context
        }

        It 'Changes nothing' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPCalendarFields -Times 0 -Exactly -Scope Context
            Should -Invoke Send-ExOPSeriesUpdate -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPFinalMigrationState -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Preview of a post-notification item in its verified target state' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true }
            Mock Get-ExOPItemSnapshot { New-ReconcileSnapshot -Subject 'Target' }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'target-evidence') -Events (New-InterruptedJournal) -After (New-ReconcileSnapshot -Subject 'Target')
            $Script:result = Invoke-TestReconcile -Name 'target'
        }

        It 'Reports the verified target state as a preview' {
            $Script:result.Status | Should -BeExactly 'Preview'
            $Script:result.CalendarState | Should -BeExactly 'TargetVerified'
        }

        It 'Changes nothing' {
            Should -Invoke Set-ExOPCalendarFields -Times 0 -Exactly -Scope Context
            Should -Invoke Set-ExOPFinalMigrationState -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Reconcile restore with the real rollback when <Name>' -ForEach @(
        @{ Name = 'the user changed only the times after the last acknowledged write'; Key = 'CK-user'; Pending = $false; Start = '2026-11-10T15:00:00Z'; End = '2026-11-10T16:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time'; Outcome = 'Acknowledged' }
        @{ Name = 'the key changed after the last acknowledged write although the state is fully intended'; Key = 'CK-other'; Pending = $false; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time'; Outcome = 'Acknowledged' }
        @{ Name = 'the journal key is proven and the times are the intended ones'; Key = 'CK-2'; Pending = $false; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time'; Outcome = 'Restored' }
        @{ Name = 'the journal key is proven and the times differ'; Key = 'CK-2'; Pending = $false; Start = '2026-11-10T15:00:00Z'; End = '2026-11-10T16:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time'; Outcome = 'Restored' }
        @{ Name = 'the last write is unknown and the state is fully original'; Key = 'CK-other'; Pending = $true; Start = '2026-11-09T18:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; Outcome = 'Restored' }
        @{ Name = 'the last write is unknown with original times and new zones'; Key = 'CK-other'; Pending = $true; Start = '2026-11-09T18:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time'; Outcome = 'Restored' }
        @{ Name = 'the last write is unknown with new times and new zones'; Key = 'CK-other'; Pending = $true; Start = '2026-11-09T09:00:00-08:00'; End = '2026-11-09T18:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time'; Outcome = 'Restored' }
        @{ Name = 'the last write is unknown with new times and original zones'; Key = 'CK-other'; Pending = $true; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; Outcome = 'Endpoints' }
        @{ Name = 'the user moved only the start to the intended value (review counterexample)'; Key = 'CK-user'; Pending = $true; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; Outcome = 'Endpoints' }
        @{ Name = 'the last write is unknown with an intended start, an original end and mixed zones'; Key = 'CK-other'; Pending = $true; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Pacific Standard Time'; Outcome = 'Endpoints' }
        @{ Name = 'the last write is unknown and only the end moved'; Key = 'CK-other'; Pending = $true; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:30:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time'; Outcome = 'Endpoints' }
        @{ Name = 'the last write is unknown and the start zone is foreign'; Key = 'CK-other'; Pending = $true; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'UTC'; EndZone = 'Mountain Standard Time'; Outcome = 'Endpoints' }
    ) {
        BeforeAll {
            $Script:restoreState = [PSCustomObject]@{ Key = $Key; Start = $Start; End = $End; StartZone = $StartZone; EndZone = $EndZone; Done = $false; MarkerCleared = $false }

            function New-RestoreItem {
                $marker = ''
                if (-not $Script:restoreState.MarkerCleared) {
                    $state = ConvertTo-Json -Compress -InputObject ([ordered]@{
                            SchemaVersion = 1; Status = 'InProgress'; OperationId = $Script:operationId
                            FromZone = 'Pacific Standard Time'; ToZone = 'Mountain Standard Time'; NotificationMayHaveStarted = $false
                        })
                    $marker = '<t:ExtendedProperty>' + $script:MigrationStateFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $state) + '</t:Value></t:ExtendedProperty>'
                }
                $document = New-Object Xml.XmlDocument
                $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:ItemId Id="' + $Script:itemId + '" ChangeKey="' + $Script:restoreState.Key + '"/>' +
                    '<t:Subject>Weekly sync</t:Subject><t:CalendarItemType>Single</t:CalendarItemType><t:Start>' + $Script:restoreState.Start + '</t:Start><t:End>' + $Script:restoreState.End + '</t:End>' +
                    '<t:StartTimeZone Id="' + $Script:restoreState.StartZone + '"/><t:EndTimeZone Id="' + $Script:restoreState.EndZone + '"/>' + $marker + '</t:CalendarItem>')
                Write-Output -InputObject $document.DocumentElement -NoEnumerate
            }

            Mock Get-ExOPCalendarItem { New-RestoreItem }
            Mock Get-ExOPItemSnapshot { if ($Script:restoreState.Done) { New-ReconcileSnapshot -Subject 'Original' } else { New-ReconcileSnapshot -Subject 'Intermediate' } }
            Mock Assert-ExOPPreservedItemData { }
            Mock Assert-ExOPRehomeResult { New-RestoreItem }
            Mock Set-ExOPSeriesTimeZoneState { $Script:restoreState.Done = $true }
            Mock Set-ExOPFinalMigrationState { $Script:restoreState.MarkerCleared = $true }
            $name = 'restore-' + [Guid]::NewGuid().ToString('N')
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath "$name-evidence") -Events (New-InterruptedJournal -PendingIntent:$Pending)
            $Script:result = Invoke-TestReconcile -Name $name -Apply
        }

        It 'Ends with the expected rollback outcome' {
            $expected = @{
                Restored     = @{ Status = 'RolledBack'; RollbackStatus = 'Verified'; CalendarState = 'OriginalVerified'; RollbackError = '' }
                Acknowledged = @{ Status = 'Critical'; RollbackStatus = 'Failed'; CalendarState = 'RequiresManualAttention'; RollbackError = 'The item changed after the last acknowledged write of this operation; it was not overwritten.' }
                Endpoints    = @{ Status = 'Critical'; RollbackStatus = 'Failed'; CalendarState = 'RequiresManualAttention'; RollbackError = 'The item times or time zones changed outside this operation; the item was not overwritten.' }
            }[$Outcome]
            $Script:result.Status | Should -BeExactly $expected.Status
            $Script:result.RollbackStatus | Should -BeExactly $expected.RollbackStatus
            $Script:result.CalendarState | Should -BeExactly $expected.CalendarState
            $Script:result.RollbackError | Should -BeExactly $expected.RollbackError
        }
        It 'Writes to the item only when restoring' {
            $writes = if ($Outcome -eq 'Restored') { 1 } else { 0 }
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times $writes -Exactly -Scope Context -ParameterFilter {
                # pwsh reads ISO strings from before.json as DateTime values, so the instants are compared.
                (ConvertTo-ExOPInstant -Value $StartUtc) -eq (ConvertTo-ExOPInstant -Value '2026-11-09T18:00:00Z') -and
                (ConvertTo-ExOPInstant -Value $EndUtc) -eq (ConvertTo-ExOPInstant -Value '2026-11-09T19:00:00Z')
            }
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times $writes -Exactly -Scope Context
            Should -Invoke Set-ExOPCalendarFields -Times $writes -Exactly -Scope Context
            Should -Invoke Set-ExOPFinalMigrationState -Times $writes -Exactly -Scope Context
        }

        It 'Records the journal and current ChangeKeys in the reconcile baseline' {
            $baseline = @(Get-RunJournal -Directory $Script:logDirectory | Where-Object { $_.Event -eq 'ReconcileBaseline' })
            $baseline | Should -HaveCount 1
            $baseline[0].Data.JournalLastChangeKey | Should -BeExactly 'CK-2'
            $baseline[0].Data.CurrentChangeKey | Should -BeExactly $Key
        }
    }

    Context 'Reconcile after an interrupted earlier reconcile rollback: <Name>' -ForEach @(
        @{ Name = 'the last rollback write was acknowledged'; Mode = 'Reconcile'; Key = 'CK-3'; RollbackJournal = $true; PendingRollbackWrite = $false; Outcome = 'Restored' }
        @{ Name = 'the last rollback write is unknown'; Mode = 'Reconcile'; Key = 'CK-unknown'; RollbackJournal = $true; PendingRollbackWrite = $true; Outcome = 'Restored' }
        @{ Name = 'no rollback was started (the same state is refused)'; Mode = 'Reconcile'; Key = 'CK-unknown'; RollbackJournal = $false; PendingRollbackWrite = $false; Outcome = 'Endpoints' }
        @{ Name = 'the rollback after a rejected send was interrupted'; Mode = 'RejectedSend'; Key = 'CK-unknown'; RollbackJournal = $true; PendingRollbackWrite = $true; Outcome = 'Restored' }
    ) {
        BeforeAll {
            # The earlier rollback restored the original zones; the original times were not yet written.
            $Script:secondRestore = [PSCustomObject]@{ Key = $Key; Done = $false; MarkerCleared = $false; MayHaveStarted = ($Mode -eq 'RejectedSend') }
            function New-SecondRestoreItem {
                $marker = ''
                if (-not $Script:secondRestore.MarkerCleared) {
                    $state = ConvertTo-Json -Compress -InputObject ([ordered]@{
                            SchemaVersion = 1; Status = 'InProgress'; OperationId = $Script:operationId
                            FromZone = 'Pacific Standard Time'; ToZone = 'Mountain Standard Time'; NotificationMayHaveStarted = $Script:secondRestore.MayHaveStarted
                        })
                    $marker = '<t:ExtendedProperty>' + $script:MigrationStateFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $state) + '</t:Value></t:ExtendedProperty>'
                }
                $document = New-Object Xml.XmlDocument
                $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:ItemId Id="' + $Script:itemId + '" ChangeKey="' + $Script:secondRestore.Key + '"/>' +
                    '<t:Subject>Weekly sync</t:Subject><t:CalendarItemType>Single</t:CalendarItemType><t:Start>2026-11-09T17:00:00Z</t:Start><t:End>2026-11-09T18:00:00Z</t:End>' +
                    '<t:StartTimeZone Id="Pacific Standard Time"/><t:EndTimeZone Id="Pacific Standard Time"/>' + $marker + '</t:CalendarItem>')
                Write-Output -InputObject $document.DocumentElement -NoEnumerate
            }

            Mock Get-ExOPCalendarItem { New-SecondRestoreItem }
            Mock Get-ExOPItemSnapshot { if ($Script:secondRestore.Done) { New-ReconcileSnapshot -Subject 'Original' } else { New-ReconcileSnapshot -Subject 'Intermediate' } }
            Mock Assert-ExOPPreservedItemData { }
            Mock Assert-ExOPRehomeResult { New-SecondRestoreItem }
            Mock Set-ExOPSeriesTimeZoneState { $Script:secondRestore.Done = $true }
            Mock Set-ExOPFinalMigrationState { $Script:secondRestore.MarkerCleared = $true }
            $name = 'second-reconcile-' + [Guid]::NewGuid().ToString('N')
            $evidence = Join-Path -Path $TestDrive -ChildPath "$name-evidence"
            if ($Mode -eq 'RejectedSend') {
                # The migration run itself rolled back after the rejection and stopped before the metadata write was acknowledged.
                $events = @(New-InterruptedJournal -NotificationIntent) + @(
                    New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ Code = 'ErrorSendAsDenied' })
                    New-JournalRecord -EventName 'RollbackStarted' -Phase 'RollbackInspection' -Data $null
                    New-JournalRecord -EventName 'WriteIntent' -Phase 'TimezoneMetadata' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $false })
                )
                Write-OperationEvidence -Directory (Join-Path -Path $evidence -ChildPath 'migration') -Events $events
            } else {
                Write-OperationEvidence -Directory (Join-Path -Path $evidence -ChildPath 'migration') -Events (New-InterruptedJournal)
            }
            if ($Mode -eq 'Reconcile' -and $RollbackJournal) {
                $records = @(
                    [PSCustomObject]@{ Utc = '2026-11-05T10:00:00.0000000+00:00'; OperationId = $Script:operationId; Phase = 'RollbackInspection'; Event = 'RollbackStarted'; Data = $null }
                    [PSCustomObject]@{ Utc = '2026-11-05T10:00:01.0000000+00:00'; OperationId = $Script:operationId; Phase = 'TimezoneMetadata'; Event = 'WriteIntent'; Data = [PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $false } }
                    [PSCustomObject]@{ Utc = '2026-11-05T10:00:02.0000000+00:00'; OperationId = $Script:operationId; Phase = 'TimezoneMetadata'; Event = 'WriteAcknowledged'; Data = [PSCustomObject]@{ ChangeKey = 'CK-3' } }
                    if ($PendingRollbackWrite) {
                        [PSCustomObject]@{ Utc = '2026-11-05T10:00:03.0000000+00:00'; OperationId = $Script:operationId; Phase = 'MasterDates'; Event = 'WriteIntent'; Data = [PSCustomObject]@{ ChangeKey = 'CK-3'; Send = $false } }
                    }
                )
                $reconcileRun = Join-Path -Path $evidence -ChildPath 'reconcile\user'
                $null = New-Item -ItemType Directory -Path $reconcileRun -Force
                Write-ExOPDurableText -Path (Join-Path -Path $reconcileRun -ChildPath 'details.jsonl') `
                    -Text ((@($records | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 5 -Compress }) -join "`r`n") + "`r`n")
            } elseif ($Mode -eq 'Reconcile') {
                Write-ExOPDurableText -Path (Join-Path -Path $evidence -ChildPath 'migration\details.jsonl') -Append -Text ((ConvertTo-Json -Compress -InputObject (
                            New-JournalRecord -EventName 'WriteIntent' -Phase 'MasterDates' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $false }))) + "`r`n")
            }
            $Script:result = Invoke-TestReconcile -Name $name -Apply
        }

        It 'Ends with <Outcome>' {
            if ($Outcome -eq 'Restored') {
                $Script:result.Status | Should -BeExactly 'RolledBack'
                $Script:result.CalendarState | Should -BeExactly 'OriginalVerified'
                Should -Invoke Set-ExOPSeriesTimeZoneState -Times 1 -Exactly -Scope Context
            } else {
                $Script:result.Status | Should -BeExactly 'Critical'
                $Script:result.RollbackError | Should -BeExactly 'The item times or time zones changed outside this operation; the item was not overwritten.'
                Should -Invoke Set-ExOPSeriesTimeZoneState -Times 0 -Exactly -Scope Context
            }
        }

        It 'Records the earlier rollback in the reconcile baseline' {
            $baseline = @(Get-RunJournal -Directory $Script:logDirectory | Where-Object Event -EQ 'ReconcileBaseline')
            $baseline[0].Data.RollbackInProgress | Should -Be $RollbackJournal
            if ($RollbackJournal -and $Mode -eq 'Reconcile') { $baseline[0].Data.JournalLastChangeKey | Should -BeExactly 'CK-3' }
            if ($Mode -eq 'RejectedSend') { $baseline[0].Data.NotificationRejected | Should -BeExactly 'ErrorSendAsDenied' }
        }
    }

    Context 'Reconcile after a delivered update whose resend was rejected (<Outcome> first send)' -ForEach @(
        @{ Outcome = 'acknowledged'; Acknowledged = $true }
        @{ Outcome = 'unknown'; Acknowledged = $false }
    ) {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true }
            Mock Get-ExOPItemSnapshot { New-ReconcileSnapshot -Subject 'Target' }
            $name = 'resend-rejected-' + [Guid]::NewGuid().ToString('N')
            $evidence = Join-Path -Path $TestDrive -ChildPath "$name-evidence"
            $events = @(New-InterruptedJournal -NotificationIntent)
            if ($Acknowledged) { $events += New-JournalRecord -EventName 'WriteAcknowledged' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-3' }) }
            Write-OperationEvidence -Directory (Join-Path -Path $evidence -ChildPath 'migration') -Events $events -After (New-ReconcileSnapshot -Subject 'Target')
            # The earlier Reconcile -ResendNotification run logged its own rejected resend in its run folder.
            $records = @(
                [PSCustomObject]@{ Utc = '2026-11-05T10:00:00.0000000+00:00'; OperationId = $Script:operationId; Phase = 'Notification'; Event = 'WriteIntent'; Data = [PSCustomObject]@{ ChangeKey = 'CK-3'; Send = $true } }
                [PSCustomObject]@{ Utc = '2026-11-05T10:00:01.0000000+00:00'; OperationId = $Script:operationId; Phase = 'Notification'; Event = 'NotificationRejected'; Data = [PSCustomObject]@{ Code = 'ErrorSendAsDenied' } }
            )
            $reconcileRun = Join-Path -Path $evidence -ChildPath 'reconcile\user'
            $null = New-Item -ItemType Directory -Path $reconcileRun -Force
            Write-ExOPDurableText -Path (Join-Path -Path $reconcileRun -ChildPath 'details.jsonl') `
                -Text ((@($records | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 5 -Compress }) -join "`r`n") + "`r`n")
            $Script:result = Invoke-TestReconcile -Name $name
        }

        It 'Never plans to move the item back' {
            $Script:result.Action | Should -BeExactly 'FinalizeTarget'
            $Script:result.RollbackStatus | Should -BeExactly 'ProhibitedAfterNotification'
            $Script:result.NotificationStatus | Should -BeExactly 'OutcomeUnknown'
        }
    }

    Context 'Reconcile after a send rejection recorded in the journal with <Mode>' -ForEach @(
        @{ Mode = 'preview'; Apply = $false; Status = 'Preview'; RollbackCalls = 0 }
        @{ Mode = 'apply'; Apply = $true; Status = 'RolledBack'; RollbackCalls = 1 }
    ) {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true }
            Mock Invoke-ExOPPreSendRollback { 'rollback-verified.json' }
            Mock Get-ExOPItemSnapshot { New-ReconcileSnapshot -Subject 'Target' }
            $events = @(New-InterruptedJournal -NotificationIntent) + @(
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ ItemId = $Script:itemId; Code = 'ErrorSendAsDenied' })
            )
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath "rejected-$Mode-evidence") -Events $events
            $Script:result = Invoke-TestReconcile -Name "rejected-$Mode" -Apply:$Apply
        }

        It 'Restores the original although the marker says notification may have started' {
            $Script:result.Action | Should -BeExactly 'RestoreOriginal'
            $Script:result.Status | Should -BeExactly $Status
            $Script:result.NotificationStatus | Should -BeExactly 'NotSent'
        }

        It 'Rolls back only with -Apply and never as a started notification' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times $RollbackCalls -Exactly -Scope Context -ParameterFilter {
                $Operation.NotificationStarted -eq $false -and $Operation.LastChangeKey -ceq 'CK-2' -and
                $Operation.NotificationRejected -ceq 'ErrorSendAsDenied'
            }
            Should -Invoke Get-ExOPItemSnapshot -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Reconcile when a notification was attempted again after a rejection' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true }
            Mock Invoke-ExOPPreSendRollback { 'unexpected' }
            $events = @(New-InterruptedJournal -NotificationIntent) + @(
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ ItemId = $Script:itemId; Code = 'ErrorSendAsDenied' })
                New-JournalRecord -EventName 'WriteIntent' -Phase 'Notification' -Data ([PSCustomObject]@{ ChangeKey = 'CK-2'; Send = $true })
            )
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'retried-evidence') -Events $events
            $Script:result = Invoke-TestReconcile -Name 'retried' -Apply
        }

        It 'Treats the item as possibly notified and does not move it back' {
            $Script:result.Action | Should -BeExactly 'FinalizeTarget'
            $Script:result.Status | Should -BeExactly 'Critical'
            $Script:result.RollbackStatus | Should -BeExactly 'ProhibitedAfterNotification'
            Should -Invoke Invoke-ExOPPreSendRollback -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Finalize with -ResendNotification for a meeting <Name>' -ForEach @(
        @{ Name = 'with attendees'; Attendees = $true; Sends = 1; NotificationStatus = 'SendAcknowledged'; Severity = 'Information' }
        @{ Name = 'without attendees'; Attendees = $false; Sends = 0; NotificationStatus = 'OutcomeUnknown'; Severity = 'Warning' }
    ) {
        BeforeAll {
            $Script:resendAttendees = $Attendees
            $Script:finalized = $false
            Mock Get-ExOPCalendarItem {
                if ($Script:finalized) {
                    New-ReconcileItem -ChangeKey 'CK-final' -WithAttendees:$Script:resendAttendees -ReceiptOperationId $Script:operationId
                } else {
                    New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true -WithAttendees:$Script:resendAttendees
                }
            }
            Mock Get-ExOPItemSnapshot { New-ReconcileSnapshot -Subject 'Target' }
            Mock Set-ExOPFinalMigrationState { $Script:finalized = $true }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath "resend-$Attendees-evidence") -Events (New-InterruptedJournal) -After (New-ReconcileSnapshot -Subject 'Target')
            $Script:result = Invoke-TestReconcile -Name "resend-$Attendees" -Apply -ResendNotification
        }

        It 'Finalizes the verified target state' {
            $Script:result.Status | Should -BeExactly 'Applied'
            $Script:result.CalendarState | Should -BeExactly 'TargetVerified'
            $Script:result.Severity | Should -BeExactly $Severity
            Should -Invoke Set-ExOPFinalMigrationState -Times 1 -Exactly -Scope Context
        }

        It 'Sends the meeting update again only when attendees exist' {
            $Script:result.NotificationStatus | Should -BeExactly $NotificationStatus
            Should -Invoke Send-ExOPSeriesUpdate -Times $Sends -Exactly -Scope Context
        }
    }

    Context 'BOM-less UTF-8 recovery evidence' {
        BeforeAll {
            $Script:internationalText = 'Meeting ' + [char]0x00E9 + [char]0x0416 + [char]0x6771
            $Script:internationalSnapshot = New-ReconcileSnapshot -Subject $Script:internationalText -BodyText $Script:internationalText
            $Script:internationalEvidence = Join-Path -Path $TestDrive -ChildPath 'international-evidence'
            Write-OperationEvidence -Directory $Script:internationalEvidence -Events (New-InterruptedJournal -NotificationIntent) `
                -After $Script:internationalSnapshot -Subject $Script:internationalText -BodyText $Script:internationalText
        }

        It 'Reads the original snapshot without changing non-ASCII subjects, bodies or hashes' {
            $evidence = Find-ExOPOperationEvidence -SearchDirectory $Script:internationalEvidence -OperationId $Script:operationId
            $bytes = [IO.File]::ReadAllBytes($evidence.BeforePath)
            $bytes[0..2] -join ',' | Should -Not -BeExactly '239,187,191'
            $evidence.Before.Snapshot.Xml | Should -BeExactly $Script:internationalSnapshot.Xml
            Get-ExOPCalendarStateHash -Snapshot $evidence.Before.Snapshot |
                Should -BeExactly (Get-ExOPCalendarStateHash -Snapshot $Script:internationalSnapshot)
        }

        It 'Finalizes an unchanged non-ASCII target after an interrupted notification' {
            $Script:internationalFinalized = $false
            Mock Get-ExOPCalendarItem {
                if ($Script:internationalFinalized) { New-ReconcileItem -ChangeKey 'CK-final' -ReceiptOperationId $Script:operationId }
                else { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true }
            }
            Mock Get-ExOPItemSnapshot { $Script:internationalSnapshot }
            Mock Set-ExOPFinalMigrationState { $Script:internationalFinalized = $true }
            $row = [PSCustomObject]@{ Mailbox = $Script:mailbox; ItemId = $Script:itemId; RecordType = 'Single' }
            $result = Invoke-ExOPCalendarMigrationReconcile -Session $Script:session -InputObject $row -SearchDirectory $Script:internationalEvidence `
                -LogDirectory (Join-Path -Path $TestDrive -ChildPath 'international-logs') -Apply -Confirm:$false -WarningAction SilentlyContinue
            $result.Status | Should -BeExactly 'Applied'
            $result.CalendarState | Should -BeExactly 'TargetVerified'
            Should -Invoke Set-ExOPFinalMigrationState -Times 1 -Exactly
            Should -Invoke Send-ExOPSeriesUpdate -Times 0 -Exactly
        }
    }

    Context 'Reconcile verifies attachments with the interrupted operation''s hash limit' {
        BeforeAll {
            $document = New-Object Xml.XmlDocument
            $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:Attachments><t:FileAttachment><t:AttachmentId Id="attachment-1"/>' +
                '<t:Name>notes.txt</t:Name><t:ContentType>text/plain</t:ContentType><t:Size>100</t:Size><t:IsInline>false</t:IsInline>' +
                '</t:FileAttachment></t:Attachments></t:CalendarItem>')
            $Script:attachmentItem = $document.DocumentElement
            $Script:runLimit = $script:MaxAttachmentHashBytes
            $script:MaxAttachmentHashBytes = 0
            try {
                $Script:attachmentTarget = New-ReconcileSnapshot -Subject 'Target'
                $Script:attachmentTarget.Attachments = @(Get-ExOPAttachmentSnapshot -Session $null -Mailbox $Script:mailbox -Item $Script:attachmentItem)
            } finally { $script:MaxAttachmentHashBytes = $Script:runLimit }
            $Script:attachmentTarget.Attachments[0].Sha256 | Should -BeExactly ''
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' -WithMarker -NotificationMayHaveStarted $true }
            Mock Get-ExOPItemSnapshot {
                $Script:observedLimit = $script:MaxAttachmentHashBytes
                $current = $Script:attachmentTarget.PSObject.Copy()
                # The real descriptor reader requests file content only for attachments within the active limit.
                $current.Attachments = @(Get-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $Script:attachmentItem)
                $current
            }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath 'attachment-limit-evidence') -Events (New-InterruptedJournal -NotificationIntent) `
                -After $Script:attachmentTarget -AttachmentHashLimitBytes 0
            $Script:result = Invoke-TestReconcile -Name 'attachment-limit'
        }

        It 'Uses the saved limit of 0 MB instead of the default 25 MB' {
            $Script:runLimit | Should -Be 25MB
            $Script:observedLimit | Should -Be 0
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope Context
        }

        It 'Verifies the unchanged target' {
            $Script:result.Status | Should -BeExactly 'Preview'
            $Script:result.CalendarState | Should -BeExactly 'TargetVerified'
        }

        It 'Restores the limit of the current run afterwards' {
            $script:MaxAttachmentHashBytes | Should -Be $Script:runLimit
        }
    }

    Context 'Reconcile continues with failure results after an audit storage failure' {
        BeforeAll {
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' }
            Mock Write-ExOPDurableText { throw 'The disk is full.' } -ParameterFilter { $Path -like '*details.jsonl' }
            $rows = @(
                [PSCustomObject]@{ Mailbox = $Script:mailbox; ItemId = 'item-1'; RecordType = 'Single' }
                [PSCustomObject]@{ Mailbox = $Script:mailbox; ItemId = 'item-2'; RecordType = 'Single' }
                [PSCustomObject]@{ Mailbox = $Script:mailbox; ItemId = 'item-3'; RecordType = 'Single' }
            )
            $Script:storageResults = @(Invoke-ExOPCalendarMigrationReconcile -Session $Script:session -InputObject $rows -SearchDirectory $TestDrive `
                    -LogDirectory (Join-Path -Path $TestDrive -ChildPath 'reconcile-storage-failure') -Apply -Confirm:$false -WarningAction SilentlyContinue)
        }

        It 'Returns a result for every row' {
            $Script:storageResults | Should -HaveCount 3
            $Script:storageResults[0].Error | Should -BeLike '*Audit storage failed: *The disk is full.*'
        }

        It 'Reports the remaining rows as failed without reading them' {
            @($Script:storageResults[1..2] | Where-Object { $_.Status -eq 'Failed' -and $_.Error -like 'Audit storage is unavailable*' }) | Should -HaveCount 2
            Should -Invoke Get-ExOPCalendarItem -Times 1 -Exactly -Scope Context
        }
    }

    Context 'Rejected-send recovery with the real rollback: <Name>' -ForEach @(
        @{ Name = 'SendAs rejection with an unchanged target'; Code = 'ErrorSendAsDenied'; Edited = $false; Recipients = $false; HasAfter = $true; Expected = 'RolledBack'; Writes = 1 }
        @{ Name = 'recipient rejection with an unchanged target'; Code = 'ErrorInvalidRecipients'; Edited = $false; Recipients = $false; HasAfter = $true; Expected = 'RolledBack'; Writes = 1 }
        @{ Name = 'a concurrent edit after the rejection'; Code = 'ErrorSendAsDenied'; Edited = $true; Recipients = $false; HasAfter = $true; Expected = 'Critical'; Writes = 0 }
        @{ Name = 'a recipient-only edit after the rejection'; Code = 'ErrorSendAsDenied'; Edited = $false; Recipients = $true; HasAfter = $true; Expected = 'Critical'; Writes = 0 }
        @{ Name = 'missing verified-target evidence'; Code = 'ErrorSendAsDenied'; Edited = $false; Recipients = $false; HasAfter = $false; Expected = 'Critical'; Writes = 0 }
    ) {
        BeforeAll {
            $Script:rejectedRestored = $false
            $Script:rejectedMarkerCleared = $false
            $text = 'Meeting ' + [char]0x00E9 + [char]0x0416 + [char]0x6771
            $Script:rejectedOriginal = New-ReconcileSnapshot -Subject $text -BodyText $text
            $target = New-ReconcileSnapshot -Subject $text -BodyText $text
            $target.Xml = $target.Xml.Replace('2026-11-09T18:00:00Z', '2026-11-09T17:00:00Z').
            Replace('2026-11-09T19:00:00Z', '2026-11-09T18:00:00Z').Replace('Pacific Standard Time', 'Mountain Standard Time')
            $Script:rejectedCurrent = $target.PSObject.Copy()
            if ($Edited) { $Script:rejectedCurrent.Xml = $Script:rejectedCurrent.Xml.Replace($text, 'Concurrent edit') }
            if ($Recipients) {
                $Script:rejectedCurrent.Xml = $Script:rejectedCurrent.Xml.Replace('<t:StartTimeZone',
                    '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>added@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees><t:StartTimeZone')
            }
            Mock Get-ExOPCalendarItem {
                New-ReconcileItem -ChangeKey 'CK-saved-before-rejection' -WithMarker:(-not $Script:rejectedMarkerCleared) -NotificationMayHaveStarted $true
            }
            Mock Get-ExOPItemSnapshot {
                if ($Script:rejectedRestored) { $Script:rejectedOriginal } else { $Script:rejectedCurrent }
            }
            Mock Assert-ExOPPreservedItemData { }
            Mock Assert-ExOPRehomeResult { New-ReconcileItem -ChangeKey 'CK-restored' -WithMarker }
            Mock Set-ExOPSeriesTimeZoneState { $Script:rejectedRestored = $true }
            Mock Set-ExOPFinalMigrationState { $Script:rejectedMarkerCleared = $true }
            $events = @(New-InterruptedJournal -NotificationIntent) + @(
                New-JournalRecord -EventName 'NotificationRejected' -Phase 'Notification' -Data ([PSCustomObject]@{ Code = $Code })
            )
            $name = 'real-rejected-' + [Guid]::NewGuid().ToString('N')
            $after = if ($HasAfter) { $target } else { $null }
            Write-OperationEvidence -Directory (Join-Path -Path $TestDrive -ChildPath "$name-evidence") -Events $events `
                -After $after -Subject $text -BodyText $text
            $Script:result = Invoke-TestReconcile -Name $name -Apply
        }

        It 'Returns <Expected> without sending another update' {
            $Script:result.Status | Should -BeExactly $Expected
            $Script:result.NotificationStatus | Should -BeExactly 'NotSent'
            Should -Invoke Send-ExOPSeriesUpdate -Times 0 -Exactly -Scope Context
        }

        It 'Restores only a verified unchanged target' {
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times $Writes -Exactly -Scope Context
            Should -Invoke Set-ExOPFinalMigrationState -Times $Writes -Exactly -Scope Context
            if ($Writes) {
                $Script:result.RollbackStatus | Should -BeExactly 'Verified'
                $Script:result.CalendarState | Should -BeExactly 'OriginalVerified'
            } else {
                $Script:result.RollbackError | Should -BeLike '*cannot be safely reconciled*'
            }
        }

        It 'Retains the rejection and acknowledged key in the recovery journal' {
            $baseline = @(Get-RunJournal -Directory $Script:logDirectory | Where-Object Event -EQ 'ReconcileBaseline')
            $baseline[0].Data.NotificationRejected | Should -BeExactly $Code
            $baseline[0].Data.JournalLastChangeKey | Should -BeExactly 'CK-2'
            if ($HasAfter) { $baseline[0].Data.VerifiedTargetHash | Should -Not -BeNullOrEmpty }
            else { $baseline[0].Data.VerifiedTargetHash | Should -BeNullOrEmpty }
        }
    }

    Context 'Reconcile send permission check for a delegate without Send on Behalf, resend <Resend>' -ForEach @(
        @{ Resend = $true; Skip = $false; Status = 'NotAttempted'; Checks = 1; Reads = 0 }
        @{ Resend = $true; Skip = $true; Status = 'NoAction'; Checks = 0; Reads = 1 }
        @{ Resend = $false; Skip = $false; Status = 'NoAction'; Checks = 0; Reads = 1 }
    ) {
        BeforeAll {
            Mock Get-ExOPSendPermission { [PSCustomObject]@{ Mode = 'None'; Error = '' } }
            Mock Get-ExOPCalendarItem { New-ReconcileItem -ChangeKey 'CK-current' }
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $searchDirectory = Join-Path -Path $TestDrive -ChildPath "permission-$Resend-$Skip-evidence"
            $null = New-Item -ItemType Directory -Path $searchDirectory -Force
            $row = [PSCustomObject]@{ Mailbox = $Script:mailbox; ItemId = $Script:itemId; RecordType = 'Single' }
            $Script:result = Invoke-ExOPCalendarMigrationReconcile -Session $session -InputObject $row -SearchDirectory $searchDirectory `
                -LogDirectory (Join-Path -Path $TestDrive -ChildPath "permission-$Resend-$Skip-logs") -Apply -ResendNotification:$Resend `
                -SkipSendPermissionCheck:$Skip -Confirm:$false -WarningAction SilentlyContinue
        }

        It 'Ends with status <Status>' {
            $Script:result.Status | Should -BeExactly $Status
            if ($Status -eq 'NotAttempted') { $Script:result.ErrorCode | Should -BeExactly 'SendPermissionMissing' }
        }

        It 'Checks the permission only for a resend without -SkipSendPermissionCheck' {
            Should -Invoke Get-ExOPSendPermission -Times $Checks -Exactly -Scope Context
            Should -Invoke Get-ExOPCalendarItem -Times $Reads -Exactly -Scope Context
        }
    }
}
