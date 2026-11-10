# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cspell:ignore Rehoming

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeDiscovery {
    $Script:cultureCases = @(
        @{ Culture = 'en-US' }
        @{ Culture = 'ru-RU' }
        @{ Culture = 'de-DE' }
        @{ Culture = 'th-TH' }
        @{ Culture = 'ar-SA' }
    )
    $Script:stateHashCases = @(
        @{ Name = 'with timezone properties'; WithProperties = $true; ExpectedHash = 'C6A13AF91A3BCBC8C41916DA082C122B0DB96CFEC136A02D4C8B6DF7743E2B92'; Version4Hash = '68765331DBA6CCA2EDDEC62A5522000E965774C698340F2E62240D1E8C1611CD' }
        @{ Name = 'without timezone properties'; WithProperties = $false; ExpectedHash = '01B96FF4C95C7B1B8AB9B8C4E0BBF6936FF7E2221FBDF18B751C687C0AF81993'; Version4Hash = '11FEF0A744365FA1B5B89D56830A4C1CB77408743C113B9DB61F38784A6F7DF8' }
    )
}

BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\EwsTransport.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\CalendarTimeZoneData.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\MigrationJournal.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Rehoming.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Reconcile.ps1

    function New-CanonicalTestValue {
        [ordered]@{
            Text    = 'a<b>&"c" ' + [char]0x00E9
            Count   = [long]9007199254740993
            Enabled = $true
            Missing = $null
            Nested  = @(1, 'two', @($false))
            Object  = [PSCustomObject]@{ Name = 'x'; Value = [long]-5 }
        }
    }

    function New-StateSnapshot {
        param(
            [bool]
            $WithProperties
        )
        $properties = @()
        if ($WithProperties) {
            $properties = @(
                ('<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33332" PropertyType="String"/><t:Value>Pacific Standard Time</t:Value></t:ExtendedProperty>'),
                ('<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33331" PropertyType="Binary"/><t:Value>AAAAAA==</t:Value></t:ExtendedProperty>')
            )
        }
        [PSCustomObject]@{
            Xml                = '<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:ItemId Id="item-1" ChangeKey="CK-1"/>' +
            '<t:Subject>Weekly sync &lt;team&gt; &amp; "guests"</t:Subject><t:Body BodyType="HTML">&lt;p&gt;Agenda &amp; notes&lt;/p&gt;</t:Body>' +
            '<t:ReminderIsSet>false</t:ReminderIsSet><t:Start>2026-11-09T18:00:00Z</t:Start><t:End>2026-11-09T19:00:00Z</t:End>' +
            '<t:UID>calendar-uid-1</t:UID><t:StartTimeZone Id="Pacific Standard Time"/><t:EndTimeZone Id="Pacific Standard Time"/></t:CalendarItem>'
            TimeZoneProperties = $properties
            Attachments        = @(
                [PSCustomObject]@{
                    Type        = 'FileAttachment'
                    Name        = 'agenda.txt'
                    ContentType = 'text/plain'
                    ContentId   = ''
                    IsInline    = 'false'
                    Size        = [long]11
                    Sha256      = 'B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9'
                }
            )
            Deleted            = @()
            Modified           = @()
        }
    }

    function New-ReminderItem {
        $document = New-Object Xml.XmlDocument
        $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '">' +
            '<t:ReminderIsSet>true</t:ReminderIsSet><t:Start>2026-11-09T02:00:00Z</t:Start>' +
            '<t:ExtendedProperty><t:ExtendedFieldURI DistinguishedPropertySetId="Common" PropertyId="34050" PropertyType="SystemTime"/>' +
            '<t:Value>2026-11-09T02:00:00Z</t:Value></t:ExtendedProperty>' +
            '<t:ExtendedProperty><t:ExtendedFieldURI DistinguishedPropertySetId="Common" PropertyId="34144" PropertyType="SystemTime"/>' +
            '<t:Value>2026-11-09T01:15:00Z</t:Value></t:ExtendedProperty></t:CalendarItem>')
        Write-Output -InputObject $document -NoEnumerate
    }
}

Describe 'Testing MigrationJournal.ps1' {
    Context 'Canonical serialization under culture <Culture>' -ForEach $Script:cultureCases {
        It 'Produces the same canonical text, hash and ordinal order' {
            $originalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
            $originalUICulture = [Threading.Thread]::CurrentThread.CurrentUICulture
            try {
                [Threading.Thread]::CurrentThread.CurrentCulture = New-Object Globalization.CultureInfo($Culture)
                [Threading.Thread]::CurrentThread.CurrentUICulture = New-Object Globalization.CultureInfo($Culture)
                [Globalization.CultureInfo]::CurrentCulture.Name | Should -BeExactly $Culture
                $value = New-CanonicalTestValue
                ConvertTo-ExOPCanonicalText -Value $value |
                    Should -BeExactly '{"Text":"a<b>&\u0022c\u0022 \u00e9","Count":9007199254740993,"Enabled":true,"Missing":null,"Nested":[1,"two",[false]],"Object":{"Name":"x","Value":-5}}'
                Get-ExOPCanonicalHash -Value $value | Should -BeExactly 'E705B8BF4C3DED3F65B03EC067F497EDA9ABE0571391AACCFE0AB2E507DAF5DF'
                (Get-ExOPOrdinalSorted -Values @('a', 'B', '_')) -join ',' | Should -BeExactly 'B,_,a'
            } finally {
                [Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
                [Threading.Thread]::CurrentThread.CurrentUICulture = $originalUICulture
            }
        }
    }

    Context 'Canonical serialization edge cases' {
        It 'Serializes null as null' {
            ConvertTo-ExOPCanonicalText -Value $null | Should -BeExactly 'null'
        }

        It 'Escapes control characters and backslashes' {
            ConvertTo-ExOPCanonicalText -Value ("a\b" + [char]10) | Should -BeExactly '"a\u005cb\u000a"'
        }

        It 'Returns an empty result for a null input' {
            @(Get-ExOPOrdinalSorted -Values $null) | Should -HaveCount 0
        }

        It 'Removes null values before an ordinal sort' {
            $sorted = @(Get-ExOPOrdinalSorted -Values @('b', $null, 'A', '_'))
            $sorted -join ',' | Should -BeExactly 'A,_,b'
            $sorted | Should -HaveCount 3
            $sorted | Should -Not -Contain ''
        }

        It 'Serializes a double as its IEEE bit pattern' {
            ConvertTo-ExOPCanonicalText -Value (1 / 3) | Should -BeExactly 'f3fd5555555555555'
        }

        It 'Serializes a single through its double bit pattern' {
            ConvertTo-ExOPCanonicalText -Value ([single]0.5) | Should -BeExactly 'f3fe0000000000000'
        }

        It 'Returns an empty result for an empty input' {
            @(Get-ExOPOrdinalSorted -Values @()) | Should -HaveCount 0
        }
    }

    Context 'Calendar state hash <Name>' -ForEach $Script:stateHashCases {
        It 'Is stable after a JSON round trip' {
            $snapshot = New-StateSnapshot -WithProperties $WithProperties
            $copy = ConvertTo-Json -InputObject $snapshot -Depth 35 | ConvertFrom-Json
            $original = Get-ExOPCalendarStateHash -Snapshot $snapshot
            $original | Should -BeExactly $ExpectedHash
            Get-ExOPCalendarStateHash -Snapshot $copy | Should -BeExactly $original
        }

        It 'Changes when a checked field changes' {
            $snapshot = New-StateSnapshot -WithProperties $WithProperties
            $snapshot.Xml = $snapshot.Xml.Replace('Weekly sync', 'Monthly sync')
            Get-ExOPCalendarStateHash -Snapshot $snapshot | Should -Not -BeExactly $ExpectedHash
        }

        It 'Keeps the version 4 hash of receipts written by earlier versions' {
            $snapshot = New-StateSnapshot -WithProperties $WithProperties
            Get-ExOPCalendarStateHash -Snapshot $snapshot -Version 4 | Should -BeExactly $Version4Hash
        }
    }

    Context 'Calendar state hash recipients' {
        BeforeAll {
            function New-RecipientSnapshot {
                param([string]$Recipients)
                $snapshot = New-StateSnapshot -WithProperties $true
                $snapshot.Xml = $snapshot.Xml.Replace('<t:StartTimeZone', $Recipients + '<t:StartTimeZone')
                $snapshot
            }
            $Script:attendee = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:Name>Ann</t:Name><t:EmailAddress>Ann@Contoso.com</t:EmailAddress></t:Mailbox>' +
            '<t:ResponseType>Unknown</t:ResponseType></t:Attendee></t:RequiredAttendees>'
            $Script:baseHash = Get-ExOPCalendarStateHash -Snapshot (New-RecipientSnapshot -Recipients $Script:attendee)
        }

        It 'Changes when <Name>' -ForEach @(
            @{ Name = 'an attendee is added'; Recipients = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>ann@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee><t:Attendee><t:Mailbox><t:EmailAddress>bob@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees>' }
            @{ Name = 'an attendee is removed'; Recipients = '' }
            @{ Name = 'an attendee becomes optional'; Recipients = '<t:OptionalAttendees><t:Attendee><t:Mailbox><t:EmailAddress>ann@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:OptionalAttendees>' }
            @{ Name = 'a room is added'; Recipients = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>ann@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees><t:Resources><t:Attendee><t:Mailbox><t:EmailAddress>room@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:Resources>' }
        ) {
            Get-ExOPCalendarStateHash -Snapshot (New-RecipientSnapshot -Recipients $Recipients) | Should -Not -BeExactly $Script:baseHash
        }

        It 'Ignores address case, display names and responses' {
            $same = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:Name>Ann Smith</t:Name><t:EmailAddress>ann@contoso.com</t:EmailAddress></t:Mailbox>' +
            '<t:ResponseType>Accept</t:ResponseType></t:Attendee></t:RequiredAttendees>'
            Get-ExOPCalendarStateHash -Snapshot (New-RecipientSnapshot -Recipients $same) | Should -BeExactly $Script:baseHash
        }

        It 'Checks the recipients of modified occurrences' {
            $snapshot = New-RecipientSnapshot -Recipients $Script:attendee
            $exception = '<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:Subject>Occurrence</t:Subject>' + $Script:attendee + '</t:CalendarItem>'
            $snapshot.Modified = @([PSCustomObject]@{ OriginalStartUtc = '2026-11-16T18:00:00Z'; Xml = $exception; Attachments = @() })
            $before = Get-ExOPCalendarStateHash -Snapshot $snapshot
            $snapshot.Modified[0].Xml = $exception.Replace('Ann@Contoso.com', 'bob@contoso.com')
            Get-ExOPCalendarStateHash -Snapshot $snapshot | Should -Not -BeExactly $before
        }

        It 'Ignores recipients in version 4' {
            Get-ExOPCalendarStateHash -Snapshot (New-RecipientSnapshot -Recipients '') -Version 4 |
                Should -BeExactly (Get-ExOPCalendarStateHash -Snapshot (New-RecipientSnapshot -Recipients $Script:attendee) -Version 4)
        }
    }

    Context 'Relative log directories' {
        It 'Resolves a relative directory against the current PowerShell location, not the process directory' {
            $location = Join-Path -Path $TestDrive -ChildPath 'operator-location'
            $null = New-Item -ItemType Directory -Path $location
            $processDirectory = [Environment]::CurrentDirectory
            Push-Location -LiteralPath $location
            try {
                [Environment]::CurrentDirectory = $env:SystemRoot
                $run = New-ExOPMigrationRun -Directory '.\Logs' -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $false
            } finally {
                [Environment]::CurrentDirectory = $processDirectory
                Pop-Location
            }
            Split-Path -Parent $run.Directory | Should -BeExactly (Join-Path -Path $location -ChildPath 'Logs')
            Test-Path -LiteralPath $run.Directory -PathType Container | Should -BeTrue
        }

        It 'Rejects a directory outside the file system' {
            { New-ExOPMigrationRun -Directory 'Env:\Logs' -Rows @() -Apply $false } | Should -Throw -ExpectedMessage '*not a file system path*'
        }
    }

    Context 'Calendar differences' {
        BeforeAll {
            $Script:beforeReminder = New-ReminderItem
            $Script:currentReminder = $Script:beforeReminder.CloneNode($true)
            $namespaces = Get-ExOPNamespaceManager -Node $Script:currentReminder
            $Script:currentReminder.SelectSingleNode("//t:ExtendedProperty[t:ExtendedFieldURI/@PropertyId='34050']/t:Value", $namespaces).InnerText = '2026-11-09T13:00:00Z'
            $Script:currentReminder.SelectSingleNode("//t:ExtendedProperty[t:ExtendedFieldURI/@PropertyId='34144']/t:Value", $namespaces).InnerText = '2026-11-09T12:15:00Z'
            $before = [PSCustomObject]@{ Xml = $Script:beforeReminder.DocumentElement.OuterXml; TimeZoneProperties = @(); RecurrenceBase64 = ''; Modified = @(); Deleted = @() }
            $after = [PSCustomObject]@{ Xml = $Script:currentReminder.DocumentElement.OuterXml; TimeZoneProperties = @(); RecurrenceBase64 = ''; Modified = @(); Deleted = @() }
            $Script:differences = @(Get-ExOPCalendarDifferences -Before $before -After $after)
        }

        It 'Includes raw reminder differences' {
            @($Script:differences | Where-Object { $_.Field -in 'Common/34050', 'Common/34144' }) | Should -HaveCount 2
        }

        It 'Does not label unchanged arrays as differences' {
            $Script:differences | Should -HaveCount 2
        }
    }

    Context 'Incremental report output for <Items> items across <Mailboxes> mailboxes' -ForEach @(
        @{ Items = 20; Mailboxes = 2 }
        @{ Items = 40; Mailboxes = 2 }
        @{ Items = 40; Mailboxes = 10 }
    ) {
        BeforeAll {
            $Script:serializedResultRows = 0
            $Script:summaryRefreshes = 0
            $Script:exportCsv = (Get-Command -Name Export-ExOPSafeResultsCsv).ScriptBlock
            $Script:updateSummary = (Get-Command -Name Update-ExOPMigrationSummary).ScriptBlock
            Mock Export-ExOPSafeResultsCsv {
                if ([IO.Path]::GetFileName($Path) -eq 'results.csv') { $Script:serializedResultRows += $Rows.Count }
                & $Script:exportCsv -Rows $Rows -Path $Path -Append:$Append
            }
            Mock Update-ExOPMigrationSummary {
                $Script:summaryRefreshes++
                & $Script:updateSummary -Run $Run
            }
            $rows = @(for ($index = 0; $index -lt $Items; $index++) {
                    [PSCustomObject]@{ Mailbox = "user$($index % $Mailboxes)@contoso.com"; RecordType = 'Single'; ItemId = "item-$index" }
                })
            $Script:incrementalRun = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath "incremental-$Items-$Mailboxes") -Rows $rows -Apply $true
            Update-ExOPMigrationSummary -Run $Script:incrementalRun
            for ($index = 0; $index -lt $Items; $index++) {
                $result = [PSCustomObject]@{
                    Mailbox = $rows[$index].Mailbox; OperationId = "item-$index"; RecordType = 'Single'; Status = 'Applied'; Severity = 'Information'
                    Subject = '=formula'; StartUtcBefore = ''; Phase = 'Completed'; CalendarState = 'TargetVerified'; NotificationStatus = 'NotRequired'
                    RollbackStatus = 'NotNeeded'; Error = ''; FinishedUtc = ''; From = 'Pacific Standard Time'; To = 'Mountain Standard Time'
                }
                Complete-ExOPMigrationResult -Run $Script:incrementalRun -Result $result
            }
            $Script:refreshesBeforeCompletion = $Script:summaryRefreshes
            $Script:rowsBeforeCompletion = $Script:serializedResultRows
            $Script:liveCsvCount = @(Get-ChildItem -LiteralPath $Script:incrementalRun.Directory -Recurse -Filter 'results.csv' |
                    ForEach-Object { Import-Csv -LiteralPath $_.FullName }).Count
            Update-ExOPMigrationSummary -Run $Script:incrementalRun
        }

        It 'Appends every result before the summaries are finalized' {
            $Script:liveCsvCount | Should -Be $Items
            $Script:rowsBeforeCompletion | Should -Be $Items
            $Script:refreshesBeforeCompletion | Should -Be 1
        }

        It 'Serializes every result exactly once without rewriting it at finalization' {
            $Script:serializedResultRows | Should -Be $Items
            $Script:summaryRefreshes | Should -Be 2
        }

        It 'Keeps exactly one header and UTF-8 marker in each result CSV' {
            foreach ($mailbox in $Script:incrementalRun.Mailboxes.Values) {
                $path = Join-Path -Path $mailbox.Directory -ChildPath 'results.csv'
                $bytes = [IO.File]::ReadAllBytes($path)
                $bytes[0..2] -join ',' | Should -BeExactly '239,187,191'
                $text = [Text.Encoding]::UTF8.GetString($bytes)
                @($text.ToCharArray() | Where-Object { $_ -eq [char]0xFEFF }) | Should -HaveCount 1
                @([IO.File]::ReadAllLines($path) | Where-Object { $_ -like '"Mailbox",*' }) | Should -HaveCount 1
                $csv = @(Import-Csv -LiteralPath $path)
                $csv | Should -HaveCount ($Items / $Mailboxes)
                $csv[0].Subject | Should -BeExactly "'=formula"
            }
        }

        It 'Keeps every result in the durable journal and final overview' {
            $events = @(Get-ChildItem -LiteralPath $Script:incrementalRun.Directory -Recurse -Filter 'details.jsonl' |
                    ForEach-Object { [IO.File]::ReadAllLines($_.FullName) } | ForEach-Object { $_ | ConvertFrom-Json })
            @($events | Where-Object Event -EQ 'ObjectResult') | Should -HaveCount $Items
            $overview = @(Import-Csv -LiteralPath (Join-Path -Path $Script:incrementalRun.Directory -ChildPath 'mailboxes.csv'))
            $overview | Should -HaveCount $Mailboxes
            ($overview | Measure-Object -Property Applied -Sum).Sum | Should -Be $Items
        }
    }

    Context 'Incremental result output failure' {
        It 'Marks audit storage as failed if the CSV append fails, retaining the journal event and the result' {
            $run = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath 'append-failure') `
                -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $true
            Mock Export-ExOPSafeResultsCsv { throw 'CSV disk failure' } -ParameterFilter { $Append }
            $result = [PSCustomObject]@{ Mailbox = 'user@contoso.com'; OperationId = 'result-1'; Phase = 'Completed'; FinishedUtc = ''; Error = '' }
            $warnings = @(Complete-ExOPMigrationResult -Run $run -Result $result 3>&1)
            $warnings | Should -HaveCount 1
            [string]$warnings[0] | Should -BeLike '*CSV disk failure*'
            $run.LoggingFailed | Should -BeTrue
            $result.Error | Should -BeLike 'Audit storage failed: *CSV disk failure*'
            $run.Results | Should -Contain $result
            $events = @([IO.File]::ReadAllLines((Join-Path -Path $run.Mailboxes['user@contoso.com'].Directory -ChildPath 'details.jsonl')) |
                    ForEach-Object { $_ | ConvertFrom-Json })
            $events | Should -HaveCount 1
            $events[0].Event | Should -BeExactly 'ObjectResult'
        }

        It 'Records later results only in memory after audit storage failed' {
            $run = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath 'after-failure') `
                -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $true
            $run.LoggingFailed = $true
            $result = [PSCustomObject]@{ Mailbox = 'user@contoso.com'; OperationId = 'result-2'; Phase = 'Preflight'; FinishedUtc = ''; Error = '' }
            Complete-ExOPMigrationResult -Run $run -Result $result
            $run.Results | Should -Contain $result
            Test-Path -LiteralPath (Join-Path -Path $run.Mailboxes['user@contoso.com'].Directory -ChildPath 'details.jsonl') | Should -BeFalse
        }

        It 'Warns instead of failing when the final summary cannot be written' {
            $run = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath 'summary-failure') `
                -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $true
            Mock Update-ExOPMigrationSummary { throw 'Summary disk failure' }
            $warnings = @(Update-ExOPFinalMigrationSummary -Run $run 3>&1)
            [string]$warnings[0] | Should -BeLike '*Summary disk failure*'
            $run.LoggingFailed | Should -BeTrue
        }
    }

    Context 'Migration run journal' {
        BeforeAll {
            $runtimeDirectory = Join-Path -Path $TestDrive -ChildPath 'runtime'
            $null = New-Item -ItemType Directory -Path $runtimeDirectory
            $alphaPath = Join-Path -Path $runtimeDirectory -ChildPath 'Alpha.ps1'
            $betaPath = Join-Path -Path $runtimeDirectory -ChildPath 'Beta.ps1'
            [IO.File]::WriteAllBytes($alphaPath, [Text.Encoding]::ASCII.GetBytes('abc'))
            [IO.File]::WriteAllBytes($betaPath, [byte[]]@())
            $script:ExOPRuntimeVersion = 'test-version-1'
            $script:ExOPRuntimeFiles = @($alphaPath, $betaPath)

            $Script:journalDirectory = Join-Path -Path $TestDrive -ChildPath 'journal'
            $Script:rows = @(
                [PSCustomObject]@{ Mailbox = 'first@contoso.com'; RecordType = 'Single'; ItemId = '+AAAA'; ChangeKey = '+key' },
                [PSCustomObject]@{ Mailbox = 'first@contoso.com'; RecordType = 'RecurringSeries' },
                [PSCustomObject]@{ Mailbox = 'first@contoso.com'; RecordType = 'Single' },
                [PSCustomObject]@{ Mailbox = 'first@contoso.com'; RecordType = 'RecurringSeries' },
                [PSCustomObject]@{ Mailbox = 'second@contoso.com'; RecordType = 'Single' },
                [PSCustomObject]@{ Mailbox = 'second@contoso.com'; RecordType = 'Single' },
                [PSCustomObject]@{ Mailbox = 'second@contoso.com'; RecordType = 'RecurringSeries' },
                [PSCustomObject]@{ Mailbox = 'second@contoso.com'; RecordType = 'Single' },
                [PSCustomObject]@{ Mailbox = 'second@contoso.com'; RecordType = 'Single' },
                [PSCustomObject]@{ Mailbox = 'unprocessed@contoso.com'; RecordType = 'Single' }
            )
            $Script:run = New-ExOPMigrationRun -Directory $Script:journalDirectory -Rows $Script:rows -Apply $true -ToWindowsTimeZoneId 'Morocco Standard Time'
            $statuses = @('Applied', 'RolledBack', 'Critical', 'NotAttempted', 'AlreadyMigrated', 'Failed', 'Preview', 'Skipped', 'NoAction')
            for ($index = 0; $index -lt $statuses.Count; $index++) {
                $result = [PSCustomObject]@{
                    Mailbox            = $Script:rows[$index].Mailbox
                    OperationId        = "item-$index"
                    RecordType         = $Script:rows[$index].RecordType
                    Status             = $statuses[$index]
                    Severity           = $(if ($statuses[$index] -eq 'Critical') { 'Critical' } else { 'Information' })
                    Subject            = '=dangerous formula'
                    StartUtcBefore     = '2026-11-09T09:00:00Z'
                    Phase              = 'Test'
                    CalendarState      = 'TestState'
                    NotificationStatus = 'NotSent'
                    RollbackStatus     = 'TestRollback'
                    Error              = "failure`r`n continued"
                    RollbackError      = 'explicit recovery failure'
                    FinishedUtc        = ''
                    From               = 'AUS Eastern Standard Time'
                    To                 = 'Morocco Standard Time'
                }
                Write-ExOPMigrationAudit -Run $Script:run -Mailbox $result.Mailbox -OperationId $result.OperationId -Phase 'Before' -EventName 'AttemptFailed' -Data @{ Value = 'old' }
                Write-ExOPMigrationAudit -Run $Script:run -Mailbox $result.Mailbox -OperationId $result.OperationId -Phase 'After' -EventName 'ReadBack' -Data @{ Value = 'new' }
                Complete-ExOPMigrationResult -Run $Script:run -Result $result
            }
            Update-ExOPMigrationSummary -Run $Script:run
            $Script:firstDirectory = $Script:run.Mailboxes['first@contoso.com'].Directory
            $Script:secondDirectory = $Script:run.Mailboxes['second@contoso.com'].Directory
            $Script:firstSummary = Get-Content -LiteralPath (Join-Path -Path $Script:firstDirectory -ChildPath 'summary.txt') -Raw
            $Script:mailboxes = @(Import-Csv -LiteralPath (Join-Path -Path $Script:run.Directory -ChildPath 'mailboxes.csv'))
        }

        It 'Writes all output below the requested directory' {
            $Script:run.Directory.StartsWith($Script:journalDirectory, [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
        }

        It 'Puts the critical count on the first summary line' {
            $Script:firstSummary.StartsWith('CRITICAL ITEMS: 1') | Should -BeTrue
        }

        It 'Reports a critical run outcome' {
            $Script:firstSummary | Should -BeLike '*CompletedWithCriticalErrors*'
        }

        It 'Counts verified rollbacks' {
            $Script:firstSummary | Should -BeLike '*rollback verified: 1*'
        }

        It 'Counts items that were not attempted' {
            $Script:firstSummary | Should -BeLike '*Not attempted: 1*'
        }

        It 'Escapes new lines in error text' {
            $Script:firstSummary.Contains('failure\r\n continued') | Should -BeTrue
        }

        It 'Shows rollback errors' {
            $Script:firstSummary | Should -BeLike '*explicit recovery failure*'
        }

        It 'Shows the migration direction' {
            $Script:firstSummary | Should -BeLike '*AUS Eastern Standard Time -> Morocco Standard Time*'
        }

        It 'Counts reconcile items without an incomplete operation separately' {
            $summary = Get-Content -LiteralPath (Join-Path -Path $Script:secondDirectory -ChildPath 'summary.txt') -Raw
            $summary | Should -BeLike '*No incomplete operation (reconcile): 1*'
            $Script:firstSummary | Should -BeLike '*No incomplete operation (reconcile): 0*'
        }

        It 'Writes one CSV row per result with formula-safe text' {
            $csv = @(Import-Csv -LiteralPath (Join-Path -Path $Script:firstDirectory -ChildPath 'results.csv'))
            $csv | Should -HaveCount 4
            $csv[0].Subject | Should -BeExactly "'=dangerous formula"
        }

        It 'Writes the results CSV with a UTF-8 byte order mark' {
            $bytes = [IO.File]::ReadAllBytes((Join-Path -Path $Script:firstDirectory -ChildPath 'results.csv'))
            $bytes[0..2] -join ',' | Should -BeExactly '239,187,191'
        }

        It 'Preserves technical identifiers in the selection' {
            $selection = @(Import-Csv -LiteralPath (Join-Path -Path $Script:run.Directory -ChildPath 'selection.csv'))
            $selection | Should -HaveCount $Script:rows.Count
            $selection[0].ItemId | Should -BeExactly '+AAAA'
            $selection[0].ChangeKey | Should -BeExactly '+key'
        }

        It 'Records the runtime version, destination and selection size' {
            $manifest = Get-Content -LiteralPath (Join-Path -Path $Script:run.Directory -ChildPath 'run.json') -Raw | ConvertFrom-Json
            $manifest.ModuleVersion | Should -BeExactly 'test-version-1'
            $manifest.ToWindowsTimeZoneId | Should -BeExactly 'Morocco Standard Time'
            $manifest.SelectedRows | Should -Be $Script:rows.Count
        }

        It 'Records Parameter as the default EWS URL source' {
            $manifest = Get-Content -LiteralPath (Join-Path -Path $Script:run.Directory -ChildPath 'run.json') -Raw | ConvertFrom-Json
            $manifest.EwsUrlSource | Should -BeExactly 'Parameter'
        }

        It 'Records the EWS URL and its Autodiscover source' {
            $source = 'Autodiscover SCP https://exch1.contoso.com/autodiscover/autodiscover.xml (EXCH)'
            $sourceRun = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath 'source') -Rows @($Script:rows[0]) -Apply $false `
                -EwsUrl 'https://exch1.contoso.com/EWS/Exchange.asmx' -EwsUrlSource $source
            $manifest = Get-Content -LiteralPath (Join-Path -Path $sourceRun.Directory -ChildPath 'run.json') -Raw | ConvertFrom-Json
            $manifest.EwsUrl | Should -BeExactly 'https://exch1.contoso.com/EWS/Exchange.asmx'
            $manifest.EwsUrlSource | Should -BeExactly $source
        }

        It 'Records hashes for exactly the runtime files' {
            $manifest = Get-Content -LiteralPath (Join-Path -Path $Script:run.Directory -ChildPath 'run.json') -Raw | ConvertFrom-Json
            $files = @($manifest.RuntimeFiles)
            $files | Should -HaveCount 2
            $files[0].File | Should -BeExactly 'Alpha.ps1'
            $files[0].SHA256 | Should -BeExactly 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'
            $files[1].File | Should -BeExactly 'Beta.ps1'
            $files[1].SHA256 | Should -BeExactly 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
        }

        It 'Keeps every journal event' {
            $journal = @(Get-Content -LiteralPath (Join-Path -Path $Script:firstDirectory -ChildPath 'details.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
            $journal | Should -HaveCount 12
            @($journal | Where-Object { $_.Event -eq 'AttemptFailed' }) | Should -HaveCount 4
            @($journal | ForEach-Object { $_.Sequence } | Sort-Object -Unique) | Should -HaveCount $journal.Count
        }

        It 'Writes one overview row per mailbox' {
            $Script:mailboxes | Should -HaveCount 3
        }

        It 'Accounts for every selected object in mailbox <_>' -ForEach @('first@contoso.com', 'second@contoso.com', 'unprocessed@contoso.com') {
            $mailbox = @($Script:mailboxes | Where-Object Mailbox -EQ $_)[0]
            $total = [int]$mailbox.Applied + [int]$mailbox.AlreadyMigrated + [int]$mailbox.RolledBack + [int]$mailbox.FailedUnchanged +
            [int]$mailbox.Critical + [int]$mailbox.Preview + [int]$mailbox.Skipped + [int]$mailbox.NoAction + [int]$mailbox.NotAttempted
            $total | Should -Be ([int]$mailbox.Selected)
        }

        It 'Reports the NoAction column' {
            $second = @($Script:mailboxes | Where-Object Mailbox -EQ 'second@contoso.com')[0]
            $second.NoAction | Should -BeExactly '1'
            $second.Selected | Should -BeExactly '5'
            $second.NotAttempted | Should -BeExactly '0'
        }

        It 'Does not report an unprocessed mailbox as successful' {
            $unprocessed = @($Script:mailboxes | Where-Object Mailbox -EQ 'unprocessed@contoso.com')[0]
            $unprocessed.NotAttempted | Should -BeExactly '1'
            $unprocessed.Outcome | Should -BeExactly 'CompletedWithErrors'
        }

        It 'Never overwrites a snapshot and makes the logging failure explicit' {
            $path = Save-ExOPMigrationSnapshot -Run $Script:run -Mailbox 'first@contoso.com' -OperationId 'snapshot-test' -Name 'before' -Snapshot @{ Value = 'preserved' }
            { Save-ExOPMigrationSnapshot -Run $Script:run -Mailbox 'first@contoso.com' -OperationId 'snapshot-test' -Name 'before' -Snapshot @{ Value = 'overwrite' } } |
                Should -Throw
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).Value | Should -BeExactly 'preserved'
            $Script:run.LoggingFailed | Should -BeTrue
        }

        It 'Creates the requested local audit even with WhatIf' {
            $whatIfRun = & {
                $WhatIfPreference = $true
                New-ExOPMigrationRun -Directory $Script:journalDirectory -Rows @($Script:rows[0]) -Apply $true
            }
            Join-Path -Path $whatIfRun.Directory -ChildPath 'run.json' | Should -Exist
            $whatIfRun.Mailboxes['first@contoso.com'].Directory | Should -Exist
        }
    }
}
