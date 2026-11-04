# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore Hmmssfff

function Write-ExOPDurableText {
    param (
        [string]
        $Path,

        [string]
        $Text,

        [switch]
        $Append,

        [switch]
        $CreateNew
    )
    $mode = if ($Append) { [IO.FileMode]::Append } elseif ($CreateNew) { [IO.FileMode]::CreateNew } else { [IO.FileMode]::Create }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [IO.FileStream]::new($Path, $mode, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function New-ExOPMigrationRun {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates explicitly requested local audit output; mailbox ShouldProcess is enforced separately.')]
    param (
        [string]
        $Directory,

        [object[]]
        $Rows,

        [bool]
        $Apply,

        [string]
        $EwsUrl,

        [string]
        $EwsUrlSource = 'Parameter',

        [string]
        $ToWindowsTimeZoneId
    )
    $id = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $path = if ($Directory) { Join-Path -Path (Resolve-ExOPFileSystemPath -Path $Directory) -ChildPath $id } else { '' }
    $run = [PSCustomObject]@{
        RunId = $id; Directory = $path; Apply = $Apply; Sequence = 0
        Mailboxes = @{}; Results = (New-Object 'System.Collections.Generic.List[object]')
        StartedUtc = [DateTimeOffset]::UtcNow.ToString('o'); LoggingFailed = $false
        ModuleVersion = [string]$script:ExOPRuntimeVersion
    }
    if ($path) { $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop -WhatIf:$false -Confirm:$false }
    foreach ($row in $Rows) {
        $mailbox = if ($null -ne $row.PSObject.Properties['Mailbox']) { [string]$row.Mailbox } else { '' }
        if (-not $mailbox) { $mailbox = '_invalid-input' }
        if (-not $run.Mailboxes.ContainsKey($mailbox)) {
            $safe = $mailbox
            foreach ($character in [IO.Path]::GetInvalidFileNameChars()) { $safe = $safe.Replace([string]$character, '_') }
            $suffix = (Get-ExOPByteHash -Bytes ([Text.Encoding]::UTF8.GetBytes($mailbox.ToLowerInvariant()))).Substring(0, 8)
            $folder = if ($path) { Join-Path -Path $path -ChildPath ($safe + '-' + $suffix) } else { '' }
            if ($folder) { $null = New-Item -ItemType Directory -Path $folder -ErrorAction Stop -WhatIf:$false -Confirm:$false }
            $run.Mailboxes[$mailbox] = [PSCustomObject]@{Directory = $folder; Selected = 0; Singles = 0; Series = 0 }
        }
        $entry = $run.Mailboxes[$mailbox]
        $entry.Selected++
        if ($null -ne $row.PSObject.Properties['RecordType'] -and $row.RecordType -eq 'RecurringSeries') { $entry.Series++ } else { $entry.Singles++ }
    }
    if ($path) {
        $hashes = @(
            foreach ($file in @($script:ExOPRuntimeFiles)) {
                if ($file -and (Test-Path -LiteralPath $file -PathType Leaf)) {
                    [PSCustomObject]@{File=[IO.Path]::GetFileName($file); SHA256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash }
                }
            }
        )
        $manifest = [ordered]@{
            SchemaVersion=1; RunId=$id; ModuleVersion=$run.ModuleVersion; StartedUtc=$run.StartedUtc
            PowerShellVersion=$PSVersionTable.PSVersion.ToString(); EwsUrl=$EwsUrl; EwsUrlSource=$EwsUrlSource; Apply=$Apply
            ToWindowsTimeZoneId =$ToWindowsTimeZoneId
            SelectedRows=$Rows.Count; RuntimeFiles=$hashes
        }
        Write-ExOPDurableText -Path (Join-Path $path 'run.json') -Text ((ConvertTo-Json -InputObject $manifest -Depth 8) + "`r`n") -CreateNew
        $selection = @($Rows | Select-Object SchemaVersion, Mailbox, ItemId, ChangeKey, RecordType, Subject,
            FromWindowsTimeZoneId, StartTimeZoneId, EndTimeZoneId, StartUtc, EndUtc, QueryStartUtc, QueryEndUtc, HasRoom, RoomNames, RoomSmtpAddresses)
        Export-ExOPSafeResultsCsv -Rows $selection -Path (Join-Path $path 'selection.csv')
    }
    $run
}

function Write-ExOPMigrationAudit {
    param (
        $Run,

        [string]
        $Mailbox,

        [string]
        $OperationId,

        [string]
        $Phase,

        [string]
        $EventName,

        $Data
    )
    if ($null -eq $Run -or -not $Run.Directory) { return }
    if (-not $Mailbox) { $Mailbox = '_invalid-input' }
    if (-not $Run.Mailboxes.ContainsKey($Mailbox)) { throw 'The audit mailbox was not registered for this run.' }
    $Run.Sequence++
    $record = [ordered]@{
        SchemaVersion = 1; RunId = $Run.RunId; Sequence = $Run.Sequence; Utc = [DateTimeOffset]::UtcNow.ToString('o')
        Mailbox = $Mailbox; OperationId = $OperationId; Phase = $Phase; Event = $EventName; Data = $Data
    }
    try {
        $text = ConvertTo-Json -InputObject $record -Depth 35 -Compress
        Write-ExOPDurableText -Path (Join-Path $Run.Mailboxes[$Mailbox].Directory 'details.jsonl') -Text ($text + "`r`n") -Append
    } catch {
        $Run.LoggingFailed = $true
        $_.Exception.Data['AuditStorageFailure'] = $true
        throw
    }
}

function Save-ExOPMigrationSnapshot {
    param (
        $Run,

        [string]
        $Mailbox,

        [string]
        $OperationId,

        [string]
        $Name,

        $Snapshot
    )
    if ($null -eq $Run -or -not $Run.Directory) { throw 'Durable audit output is required before calendar changes.' }
    $path = Join-Path $Run.Mailboxes[$Mailbox].Directory ($OperationId + '-' + $Name + '.json')
    try {
        Write-ExOPDurableText -Path $path -Text ((ConvertTo-Json -InputObject $Snapshot -Depth 35) + "`r`n") -CreateNew
    } catch {
        $Run.LoggingFailed = $true
        $_.Exception.Data['AuditStorageFailure'] = $true
        throw
    }
    $path
}

function ConvertTo-ExOPLogLine {
    param (
        [string]
        $Value
    )
    $Value.Replace("`r", '\r').Replace("`n", '\n')
}

function Export-ExOPSafeResultsCsv {
    param (
        [object[]]
        $Rows,

        [string]
        $Path,

        [switch]
        $Append
    )
    if ($Rows.Count -eq 0) { return }
    $safe = foreach ($row in $Rows) {
        $copy = $row | Select-Object *
        foreach ($property in $copy.PSObject.Properties) {
            if ($property.Value -is [string] -and $property.Name -notin 'ItemId', 'ChangeKey', 'OperationId', 'RunId', 'UID', 'Mailbox' -and
                $property.Value -match '^\s*[=+\-@]') { $property.Value = "'" + $property.Value }
        }
        $copy
    }
    $appendRows = $Append -and (Test-Path -LiteralPath $Path -PathType Leaf) -and (Get-Item -LiteralPath $Path).Length -gt 0
    $lines = @($safe | ConvertTo-Csv -NoTypeInformation)
    if ($appendRows) { $lines = @($lines | Select-Object -Skip 1) }
    $text = ($lines -join "`r`n") + "`r`n"
    if (-not $appendRows) { $text = [string][char]0xFEFF + $text }
    Write-ExOPDurableText -Path $Path -Text $text -Append:$appendRows
}

function Update-ExOPMigrationSummary {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Updates explicitly requested local summary files, never a mailbox.')]
    param (
        $Run
    )
    if ($null -eq $Run -or -not $Run.Directory) { return }
    $byMailbox = @{}
    foreach ($row in $Run.Results) {
        if (-not $byMailbox.ContainsKey($row.Mailbox)) {
            $byMailbox[$row.Mailbox] = New-Object 'System.Collections.Generic.List[object]'
        }
        $byMailbox[$row.Mailbox].Add($row)
    }
    $overview = @(
        foreach ($mailbox in @($Run.Mailboxes.Keys | Sort-Object)) {
            $entry = $Run.Mailboxes[$mailbox]
            $rows = @(if ($byMailbox.ContainsKey($mailbox)) { $byMailbox[$mailbox].ToArray() })
            $critical = @($rows | Where-Object Severity -EQ 'Critical')
            $failed = @($rows | Where-Object { $_.Status -in 'Failed', 'RolledBack' })
            $applied = @($rows | Where-Object Status -EQ 'Applied').Count
            $already = @($rows | Where-Object Status -EQ 'AlreadyMigrated').Count
            $rolledBack = @($rows | Where-Object Status -EQ 'RolledBack').Count
            $unchanged = @($rows | Where-Object Status -EQ 'Failed').Count
            $preview = @($rows | Where-Object { $_.Status -in 'Preview', 'WhatIf' }).Count
            $skipped = @($rows | Where-Object Status -EQ 'Skipped').Count
            $noAction = @($rows | Where-Object Status -EQ 'NoAction').Count
            $notAttempted = $entry.Selected - $rows.Count + @($rows | Where-Object Status -EQ 'NotAttempted').Count
            $outcome = if ($critical.Count -gt 0) { 'CompletedWithCriticalErrors' }
            elseif ($failed.Count -gt 0 -or $notAttempted -gt 0) { 'CompletedWithErrors' }
            elseif ($preview -eq $rows.Count -and $rows.Count -gt 0) {
                if (@($rows | Where-Object Status -EQ 'WhatIf').Count -eq $rows.Count) { 'WhatIf' } else { 'Preview' }
            } elseif ($Run.Apply) { 'Completed' } else { 'Preview' }
            $summary = @(
                "CRITICAL ITEMS: $($critical.Count)"
                "Mailbox: $mailbox"
                "RunId: $($Run.RunId)"
                "Script version: $($Run.ModuleVersion)"
                "Started UTC: $($Run.StartedUtc)"
                ('Direction(s): ' + (@($rows | ForEach-Object { $_.From + ' -> ' + $_.To } | Sort-Object -Unique) -join '; '))
                "Outcome: $outcome"
                "Selected objects: $($entry.Selected) (single items: $($entry.Singles); recurring masters: $($entry.Series))"
                "Migrated and locally verified: $applied"
                "Already migrated and verified: $already"
                "Not migrated; rollback verified: $rolledBack"
                "Not changed; rejected/failed: $unchanged"
                "Critical/manual attention: $($critical.Count)"
                "Preview/WhatIf: $preview"
                "Skipped by user: $skipped"
                "No incomplete operation (reconcile): $noAction"
                "Not attempted: $notAttempted"
                'Attendee/resource acceptance is not implied by local migration or successful send.'
                ''
                'CRITICAL OBJECTS'
            )
            foreach ($row in $critical) {
                $rollbackError = if ($null -ne $row.PSObject.Properties['RollbackError']) { [string]$row.RollbackError } else { '' }
                $summary += @($row.OperationId, $row.RecordType, $row.StartUtcBefore,
                    (ConvertTo-ExOPLogLine -Value $row.Subject), $row.Phase, $row.CalendarState,
                    $row.NotificationStatus, $row.RollbackStatus, (ConvertTo-ExOPLogLine -Value $row.Error),
                    (ConvertTo-ExOPLogLine -Value $rollbackError)) -join ' | '
            }
            $summary += @('', 'OTHER NON-MIGRATED OBJECTS')
            foreach ($row in @($failed) + @($rows | Where-Object Status -EQ 'NotAttempted')) {
                $summary += @($row.OperationId, $row.Status, $row.StartUtcBefore,
                    (ConvertTo-ExOPLogLine -Value $row.Subject), (ConvertTo-ExOPLogLine -Value $row.Error)) -join ' | '
            }
            Write-ExOPDurableText -Path (Join-Path $entry.Directory 'summary.txt') -Text (($summary -join "`r`n") + "`r`n")
            [PSCustomObject]@{
                Mailbox = $mailbox; Selected = $entry.Selected; Applied = $applied; AlreadyMigrated = $already
                RolledBack = $rolledBack; FailedUnchanged = $unchanged; Critical = $critical.Count
                Preview = $preview; Skipped = $skipped; NoAction = $noAction; NotAttempted = $notAttempted; Outcome = $outcome
            }
        }
    )
    Export-ExOPSafeResultsCsv -Rows $overview -Path (Join-Path $Run.Directory 'mailboxes.csv')
}

function Complete-ExOPMigrationResult {
    param (
        $Run,

        $Result
    )
    $Result.FinishedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $Run.Results.Add($Result)
    try {
        Write-ExOPMigrationAudit -Run $Run -Mailbox $Result.Mailbox -OperationId $Result.OperationId `
            -Phase $Result.Phase -EventName 'ObjectResult' -Data $Result
        if ($Run.Directory) {
            Export-ExOPSafeResultsCsv -Rows @($Result) -Path (Join-Path $Run.Mailboxes[$Result.Mailbox].Directory 'results.csv') -Append
        }
    } catch {
        $Run.LoggingFailed = $true
        $_.Exception.Data['AuditStorageFailure'] = $true
        throw
    }
}

function ConvertTo-ExOPCanonicalText {
    <#
        Deterministic JSON-like serialization used only for hashes. Unlike ConvertTo-Json it produces
        identical text in Windows PowerShell 5.1 and PowerShell 7 and under every culture.
    #>
    param (
        [AllowNull()]
        $Value
    )
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid]) {
        $builder = New-Object Text.StringBuilder
        $null = $builder.Append('"')
        foreach ($character in ([string]$Value).ToCharArray()) {
            $code = [int]$character
            if ($character -eq '"' -or $character -eq '\' -or $code -lt 32 -or $code -gt 126) {
                $null = $builder.Append('\u').Append($code.ToString('x4', [Globalization.CultureInfo]::InvariantCulture))
            } else { $null = $builder.Append($character) }
        }
        return $builder.Append('"').ToString()
    }
    if ($Value -is [DateTimeOffset]) { return ConvertTo-ExOPCanonicalText -Value (Format-ExOPInstant -Value $Value) }
    # Floating-point text differs between .NET Framework and .NET; the exact bit pattern does not.
    if ($Value -is [double] -or $Value -is [single]) { return 'f' + [BitConverter]::DoubleToInt64Bits([double]$Value).ToString('x16', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [ValueType]) { return ([IFormattable]$Value).ToString($null, [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [Collections.IDictionary]) {
        $parts = foreach ($key in $Value.Keys) { (ConvertTo-ExOPCanonicalText -Value ([string]$key)) + ':' + (ConvertTo-ExOPCanonicalText -Value $Value[$key]) }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $parts = foreach ($property in $Value.PSObject.Properties) { (ConvertTo-ExOPCanonicalText -Value $property.Name) + ':' + (ConvertTo-ExOPCanonicalText -Value $property.Value) }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($Value -is [Collections.IEnumerable]) {
        $parts = foreach ($entry in $Value) { ConvertTo-ExOPCanonicalText -Value $entry }
        return '[' + (@($parts) -join ',') + ']'
    }
    ConvertTo-ExOPCanonicalText -Value ([string]$Value)
}

function Get-ExOPCanonicalHash {
    param (
        [AllowNull()]
        $Value
    )
    Get-ExOPByteHash -Bytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-ExOPCanonicalText -Value $Value)))
}

function Get-ExOPOrdinalSorted {
    param (
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]
        $Values
    )
    $copy = [string[]]@($Values | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    [Array]::Sort($copy, [StringComparer]::Ordinal)
    $copy
}

function Get-ExOPRecipientIdentities {
    param (
        [Xml.XmlNode]
        $Item
    )
    $ns = Get-ExOPNamespaceManager -Node $Item
    $identities = foreach ($list in 'RequiredAttendees', 'OptionalAttendees', 'Resources') {
        foreach ($mailbox in $Item.SelectNodes("t:$list/t:Attendee/t:Mailbox", $ns)) {
            $address = Get-ExOPText -Node $mailbox -Path 't:EmailAddress'
            $identity = if ($address) { 'smtp:' + $address.ToLowerInvariant() } else { 'name:' + (Get-ExOPText -Node $mailbox -Path 't:Name') }
            $list + '=' + $identity
        }
    }
    @(Get-ExOPOrdinalSorted -Values @($identities))
}

function Get-ExOPCalendarStateHash {
    <#
        Hash version 5: checked calendar fields, attendee and resource identities, raw active reminder
        metadata, timezone properties, attachment descriptors, deletions and exceptions, serialized by
        ConvertTo-ExOPCanonicalText. Version 4 is the same without recipients; it only verifies receipts
        written by earlier versions.
    #>
    param (
        $Snapshot,

        [ValidateSet(4, 5)]
        [int]
        $Version = 5
    )
    $document = New-Object Xml.XmlDocument
    $document.XmlResolver = $null
    $document.LoadXml($Snapshot.Xml)
    $item = $document.DocumentElement
    $fields = [ordered]@{}
    foreach ($name in 'UID', 'Subject', 'Body', 'Location', 'Categories', 'Sensitivity', 'IsAllDayEvent',
        'LegacyFreeBusyStatus', 'ReminderIsSet', 'ReminderMinutesBeforeStart', 'Start', 'End') {
        $fields[$name] = Get-ExOPText -Node $item -Path ("t:" + $name)
    }
    if ((Get-ExOPText -Node $item -Path 't:ReminderIsSet') -eq 'true') {
        $fields.ReminderTime = Get-ExOPRawReminderValue -Item $item -PropertyId 34050
        $fields.ReminderSignal = Get-ExOPRawReminderValue -Item $item -PropertyId 34144
    }
    $ns = Get-ExOPNamespaceManager -Node $item
    if ($Version -ge 5) { $fields.Recipients = Get-ExOPRecipientIdentities -Item $item }
    $fields.StartZone = $item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
    $fields.EndZone = $item.SelectSingleNode('t:EndTimeZone', $ns).GetAttribute('Id')
    $fields.Recurrence = Get-ExOPRecurrenceLocalXml -Item $item
    $properties = Get-ExOPTimezonePropertyMap -Properties $Snapshot.TimeZoneProperties
    $fields.Timezones = @(Get-ExOPOrdinalSorted -Values @($properties.Keys) | ForEach-Object { $_ + '=' + $properties[$_].Value })
    $fields.Attachments = @(Get-ExOPOrdinalSorted -Values @($Snapshot.Attachments | ForEach-Object { ConvertTo-ExOPCanonicalText -Value $_ }))
    $fields.Deleted = @(Get-ExOPOrdinalSorted -Values @($Snapshot.Deleted))
    $exceptionsBySlot = @{}
    foreach ($entry in @($Snapshot.Modified)) { $exceptionsBySlot[[string]$entry.OriginalStartUtc] = $entry }
    $fields.Exceptions = @(
        foreach ($slot in (Get-ExOPOrdinalSorted -Values @($exceptionsBySlot.Keys))) {
            $entry = $exceptionsBySlot[$slot]
            $old = New-Object Xml.XmlDocument
            $old.XmlResolver = $null
            $old.LoadXml($entry.Xml)
            $values = [ordered]@{OriginalSlot = $entry.OriginalStartUtc }
            foreach ($name in 'Subject', 'Body', 'Location', 'Categories', 'Sensitivity', 'IsAllDayEvent',
                'LegacyFreeBusyStatus', 'ReminderIsSet', 'ReminderMinutesBeforeStart', 'Start', 'End') {
                $values[$name] = Get-ExOPText -Node $old.DocumentElement -Path ("t:" + $name)
            }
            if ((Get-ExOPText -Node $old.DocumentElement -Path 't:ReminderIsSet') -eq 'true') {
                $values.ReminderTime = Get-ExOPRawReminderValue -Item $old.DocumentElement -PropertyId 34050
                $values.ReminderSignal = Get-ExOPRawReminderValue -Item $old.DocumentElement -PropertyId 34144
            }
            $values.Attachments = @(Get-ExOPOrdinalSorted -Values @($entry.Attachments | ForEach-Object { ConvertTo-ExOPCanonicalText -Value $_ }))
            if ($Version -ge 5) { $values.Recipients = Get-ExOPRecipientIdentities -Item $old.DocumentElement }
            if ($null -ne $entry.PSObject.Properties['TimeZoneProperties']) {
                $exceptionProperties = Get-ExOPTimezonePropertyMap -Properties $entry.TimeZoneProperties
                $values.Timezones = @(Get-ExOPOrdinalSorted -Values @($exceptionProperties.Keys) | ForEach-Object { $_ + '=' + $exceptionProperties[$_].Value })
            }
            $values
        }
    )
    Get-ExOPCanonicalHash -Value $fields
}

function Get-ExOPCalendarDifferences {
    param (
        $Before,

        $After
    )
    $beforeXml = New-Object Xml.XmlDocument
    $beforeXml.XmlResolver = $null
    $beforeXml.LoadXml($Before.Xml)
    $afterXml = New-Object Xml.XmlDocument
    $afterXml.XmlResolver = $null
    $afterXml.LoadXml($After.Xml)
    foreach ($name in 'Start', 'End', 'Subject', 'Body', 'Location', 'Categories', 'Sensitivity',
        'IsAllDayEvent', 'LegacyFreeBusyStatus', 'ReminderIsSet', 'ReminderMinutesBeforeStart', 'ReminderDueBy', 'UID') {
        $old = Get-ExOPText -Node $beforeXml.DocumentElement -Path ("t:" + $name)
        $new = Get-ExOPText -Node $afterXml.DocumentElement -Path ("t:" + $name)
        if ($old -cne $new) { [PSCustomObject]@{Field = $name; Before = $old; After = $new } }
    }
    foreach ($propertyId in 34050, 34144) {
        $old = Get-ExOPRawReminderValue -Item $beforeXml.DocumentElement -PropertyId $propertyId
        $new = Get-ExOPRawReminderValue -Item $afterXml.DocumentElement -PropertyId $propertyId
        if ($old -cne $new) { [PSCustomObject]@{Field = 'Common/' + $propertyId; Before = $old; After = $new } }
    }
    $oldProperties = Get-ExOPTimezonePropertyMap -Properties $Before.TimeZoneProperties
    $newProperties = Get-ExOPTimezonePropertyMap -Properties $After.TimeZoneProperties
    foreach ($key in @(@($oldProperties.Keys) + @($newProperties.Keys) | Sort-Object -Unique)) {
        $old = if ($oldProperties.ContainsKey($key)) { $oldProperties[$key].Value } else { $null }
        $new = if ($newProperties.ContainsKey($key)) { $newProperties[$key].Value } else { $null }
        if ($old -cne $new) { [PSCustomObject]@{Field = 'Appointment/' + $key; Before = $old; After = $new } }
    }
    if ($Before.RecurrenceBase64 -cne $After.RecurrenceBase64) {
        [PSCustomObject]@{Field = 'Appointment/33302'; Before = $Before.RecurrenceBase64; After = $After.RecurrenceBase64 }
    }
    foreach ($name in 'Modified', 'Deleted') {
        $old = @($Before.$name)
        $new = @($After.$name)
        if ((ConvertTo-Json -InputObject $old -Depth 30 -Compress) -cne (ConvertTo-Json -InputObject $new -Depth 30 -Compress)) {
            [PSCustomObject]@{Field = $name + 'Occurrences'; Before = $old; After = $new }
        }
    }
}
