# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore Rehome Rehoming OXOCAL journaled

# Files larger than this are verified by metadata only, so large files are not downloaded during migration.
$script:MaxAttachmentHashBytes = 25MB

function Get-ExOPDefaultCalendarId {
    param (
        $Session,

        [string]
        $Mailbox
    )
    $body='<m:GetFolder><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape><m:FolderIds>' +
    '<t:DistinguishedFolderId Id="calendar"><t:Mailbox><t:EmailAddress>'+(ConvertTo-ExOPXmlText $Mailbox)+
    '</t:EmailAddress></t:Mailbox></t:DistinguishedFolderId></m:FolderIds></m:GetFolder>'
    $xml=Invoke-ExOPEwsRequest $Session $body -Mailbox $Mailbox -ReadOnly
    $node=$xml.SelectSingleNode('//t:CalendarFolder/t:FolderId', (Get-ExOPNamespaceManager $xml))
    if ($null -eq $node) { throw 'The target default calendar could not be resolved.' }
    $node.GetAttribute('Id')
}

function Convert-ExOPWallClockZone {
    param (
        [string]
        $Utc,

        [string]
        $From,

        [string]
        $To
    )
    $instant=ConvertTo-ExOPInstant $Utc
    if ($From -eq $To) { return Format-ExOPInstant $instant }
    $source=[TimeZoneInfo]::FindSystemTimeZoneById($From)
    $target=[TimeZoneInfo]::FindSystemTimeZoneById($To)
    $local=[DateTime]::SpecifyKind([TimeZoneInfo]::ConvertTimeFromUtc($instant.UtcDateTime, $source), [DateTimeKind]::Unspecified)
    if ($target.IsInvalidTime($local) -or $target.IsAmbiguousTime($local)) {
        throw "The target zone has an invalid or ambiguous local time at $($local.ToString('s'))."
    }
    Format-ExOPInstant ([DateTimeOffset][TimeZoneInfo]::ConvertTimeToUtc($local, $target))
}

function Get-ExOPRehomeValues {
    param (
        [Xml.XmlNode]
        $Item,

        [string]
        $From,

        [string]
        $To
    )
    $ns=Get-ExOPNamespaceManager $Item
    $startZoneNode=$Item.SelectSingleNode('t:StartTimeZone', $ns)
    $endZoneNode=$Item.SelectSingleNode('t:EndTimeZone', $ns)
    if ($null -eq $startZoneNode -or $null -eq $endZoneNode) { throw 'An endpoint timezone is missing.' }
    $startZone=$startZoneNode.GetAttribute('Id'); $endZone=$endZoneNode.GetAttribute('Id')
    $newStartZone=if ($startZone -eq $From) { $To }else { $startZone }
    $newEndZone=if ($endZone -eq $From) { $To }else { $endZone }
    $start=Get-ExOPText $Item 't:Start'; $end=Get-ExOPText $Item 't:End'
    $newStart=Convert-ExOPWallClockZone -Utc $start -From $startZone -To $newStartZone
    $newEnd=Convert-ExOPWallClockZone -Utc $end -From $endZone -To $newEndZone
    $newStartInstant = ConvertTo-ExOPInstant $newStart
    $newEndInstant = ConvertTo-ExOPInstant $newEnd
    # Zero-duration items (start = end) are valid and stay zero-duration; any other collapse or inversion is rejected.
    $zeroDuration = (ConvertTo-ExOPInstant $end) -eq (ConvertTo-ExOPInstant $start)
    if ($newEndInstant -lt $newStartInstant -or ($newEndInstant -eq $newStartInstant -and -not $zeroDuration)) {
        throw 'Rehoming would make the end time less than or equal to the start time.'
    }
    [PSCustomObject]@{
        StartZone=$startZone; EndZone=$endZone; NewStartZone=$newStartZone; NewEndZone=$newEndZone
        StartUtc=(Format-ExOPInstant (ConvertTo-ExOPInstant $start)); EndUtc=(Format-ExOPInstant (ConvertTo-ExOPInstant $end))
        NewStartUtc=$newStart; NewEndUtc=$newEnd
    }
}

function New-ExOPSetField {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an XML string without changing state.')]
    param (
        [string]
        $FieldUri,

        [string]
        $ValueXml
    )
    '<t:SetItemField><t:FieldURI FieldURI="'+$FieldUri+'"/><t:CalendarItem>'+$ValueXml+'</t:CalendarItem></t:SetItemField>'
}

function Set-ExOPCalendarFields {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private writer called inside the public migration ShouldProcess boundary.')]
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        [string[]]
        $Updates,

        [switch]
        $Send,

        [switch]
        $PassThru
    )
    if ($Updates.Count -eq 0) { throw 'An update must contain at least one field.' }
    $id=$Item.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager $Item))
    if (-not $id.GetAttribute('ChangeKey')) { throw 'A current ChangeKey is required before writing.' }
    $operation = $Session.ActiveOperation
    if ($null -ne $operation) {
        if ($id.GetAttribute('ChangeKey') -cne $operation.LastChangeKey) {
            $concurrentError = New-Object InvalidOperationException('The item changed concurrently; no automatic overwrite is permitted.')
            $concurrentError.Data['ConcurrentChange'] = $true
            throw $concurrentError
        }
        Write-ExOPMigrationAudit -Run $operation.Run -Mailbox $Mailbox -OperationId $operation.OperationId `
            -Phase $operation.Phase -EventName 'WriteIntent' -Data ([ordered]@{
                ItemId = $id.GetAttribute('Id'); ChangeKey = $id.GetAttribute('ChangeKey')
                Send = [bool]$Send; Updates = $Updates
            })
        if ($Send) { $operation.NotificationStarted = $true }
        $operation.WriteAttempted = $true
        $operation.LastWriteUnknown = $false
    }
    $mode=if ($Send) { 'SendToAllAndSaveCopy' }else { 'SendToNone' }
    $body='<m:UpdateItem ConflictResolution="NeverOverwrite" SendMeetingInvitationsOrCancellations="'+$mode+'">' +
    '<m:ItemChanges><t:ItemChange>'+$id.OuterXml+'<t:Updates>'+($Updates-join '')+
    '</t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>'
    try {
        $response = Invoke-ExOPEwsRequest -Session $Session -Body $body -Mailbox $Mailbox
        $updatedId = $response.SelectSingleNode('//m:UpdateItemResponseMessage/m:Items/t:*/t:ItemId', (Get-ExOPNamespaceManager -Node $response))
        if ($null -eq $updatedId -or -not $updatedId.GetAttribute('ChangeKey')) {
            throw 'The update succeeded without a usable response ChangeKey; its outcome must be reconciled.'
        }
        $written = [PSCustomObject]@{
            ItemId    = $updatedId.GetAttribute('Id')
            ChangeKey = $updatedId.GetAttribute('ChangeKey')
        }
        if ($null -ne $operation) {
            $operation.LastChangeKey = $written.ChangeKey
            $operation.AcknowledgedWrites++
            Write-ExOPMigrationAudit -Run $operation.Run -Mailbox $Mailbox -OperationId $operation.OperationId `
                -Phase $operation.Phase -EventName 'WriteAcknowledged' -Data ([ordered]@{
                    ItemId = $written.ItemId; ChangeKey = $written.ChangeKey
                    FrontEndServer = $Session.LastFrontEndServer; BackEndServer = $Session.LastBackEndServer
                })
        }
        if ($PassThru) { $written }
    } catch {
        if ($null -ne $operation -and -not $_.Exception.Data['AuditStorageFailure']) {
            $operation.LastWriteUnknown = -not [bool]$_.Exception.Data['EwsResponseCode']
            # These response codes reject the submission before any message is sent, so the
            # update is known not to have been sent and the pre-send rollback remains safe.
            if ($Send -and [string]$_.Exception.Data['EwsResponseCode'] -in $script:DefinitiveSendRejectionCodes) {
                $operation.NotificationStarted = $false
                $operation | Add-Member -NotePropertyName NotificationRejected -NotePropertyValue ([string]$_.Exception.Data['EwsResponseCode']) -Force
                $rejection = $_
                Write-ExOPMigrationAudit -Run $operation.Run -Mailbox $Mailbox -OperationId $operation.OperationId `
                    -Phase $operation.Phase -EventName 'NotificationRejected' -Data ([ordered]@{
                        ItemId = $id.GetAttribute('Id'); Code = [string]$rejection.Exception.Data['EwsResponseCode']
                    })
                throw $rejection
            }
        }
        throw
    }
}

$script:DefinitiveSendRejectionCodes = @('ErrorSendAsDenied', 'ErrorInvalidRecipients')

function Get-ExOPMigrationState {
    param (
        [Xml.XmlNode]
        $Item
    )
    $value = $Item.SelectSingleNode("t:ExtendedProperty[t:ExtendedFieldURI[@PropertyName='CalendarTimeZoneMigrationState']]/t:Value", (Get-ExOPNamespaceManager -Node $Item))
    if ($null -eq $value) { return $null }
    $state = $value.InnerText | ConvertFrom-Json -ErrorAction Stop
    if ($state.SchemaVersion -ne 1 -or -not $state.OperationId -or $state.Status -ne 'InProgress') {
        throw 'The item contains an unrecognized migration-state marker; no automatic changes are allowed.'
    }
    $state
}

function Set-ExOPMigrationState {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private writer called inside the public migration ShouldProcess boundary.')]
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        $State,

        [switch]
        $Clear
    )
    $update = if ($Clear) {
        '<t:DeleteItemField>' + $script:MigrationStateFieldUri + '</t:DeleteItemField>'
    } else {
        $json = $State | ConvertTo-Json -Compress
        '<t:SetItemField>' + $script:MigrationStateFieldUri + '<t:CalendarItem><t:ExtendedProperty>' +
        $script:MigrationStateFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $json) +
        '</t:Value></t:ExtendedProperty></t:CalendarItem></t:SetItemField>'
    }
    Set-ExOPCalendarFields -Session $Session -Mailbox $Mailbox -Item $Item -Updates @($update) -PassThru
}

function Get-ExOPTimeZoneProperties {
    param (
        $Session,

        [string]
        $Mailbox,

        [string]
        $ItemId,

        [switch]
        $Single,

        [switch]
        $Instance
    )
    $definitions = @(
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33302" PropertyType="Binary"/>',
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33331" PropertyType="Binary"/>',
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33332" PropertyType="String"/>',
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33374" PropertyType="Binary"/>',
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33375" PropertyType="Binary"/>',
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33376" PropertyType="Binary"/>',
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyName="StartTimeZoneIanaName" PropertyType="String"/>',
        '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyName="EndTimeZoneIanaName" PropertyType="String"/>'
    )
    if ($Instance) {
        $definitions = @($definitions | Where-Object { $_ -match 'PropertyId="3337[45]"|PropertyName=' })
    }
    $body = '<m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties>' +
    ($definitions -join '') + '</t:AdditionalProperties></m:ItemShape><m:ItemIds><t:ItemId Id="' +
    (ConvertTo-ExOPXmlText -Value $ItemId) + '"/></m:ItemIds></m:GetItem>'
    $response = Invoke-ExOPEwsRequest -Session $Session -Body $body -Mailbox $Mailbox -ReadOnly
    $ns = Get-ExOPNamespaceManager -Node $response
    $item = $response.SelectSingleNode('//m:GetItemResponseMessage/m:Items/t:CalendarItem', $ns)
    if ($null -eq $item) { throw 'Timezone-property lookup did not return a calendar item.' }
    $identifier = $item.SelectSingleNode('t:ItemId', $ns)
    $properties = @($item.SelectNodes('t:ExtendedProperty[not(t:ExtendedFieldURI/@PropertyId="33302")]', $ns) | ForEach-Object { $_.OuterXml })
    $recurrence = $item.SelectSingleNode('t:ExtendedProperty[t:ExtendedFieldURI/@PropertyId="33302"]/t:Value', $ns)
    $propertyIds = @($item.SelectNodes('t:ExtendedProperty/t:ExtendedFieldURI[@PropertyId]', $ns) | ForEach-Object { [int]$_.GetAttribute('PropertyId') })
    $required = if ($Single -or $Instance) { @(33374, 33375) } else { @(33302, 33331, 33332, 33374, 33375, 33376) }
    foreach ($requiredId in $required) {
        if ($propertyIds -notcontains $requiredId) { throw "Required timezone property $requiredId is missing." }
    }
    [PSCustomObject]@{
        ItemId           = $identifier.GetAttribute('Id')
        ChangeKey        = $identifier.GetAttribute('ChangeKey')
        Properties       = $properties
        HasIanaNames     = $item.SelectNodes('t:ExtendedProperty/t:ExtendedFieldURI[@PropertyName]', $ns).Count -gt 0
        RecurrenceBase64 = if ($null -ne $recurrence) { $recurrence.InnerText } else { '' }
    }
}

function Get-ExOPRecurrenceBlobLayout {
    param (
        [byte[]]
        $Bytes
    )
    # MS-OXOCAL 2.2.1.44: locate fields without rebuilding strings, flags or opaque blocks.
    function Step-RecurrenceBytes {
        param (
            [IO.BinaryReader]
            $Reader,

            [long]
            $Count
        )
        if ($Count -lt 0 -or $Count -gt $Reader.BaseStream.Length - $Reader.BaseStream.Position) {
            throw 'Truncated recurrence data.'
        }
        $Reader.BaseStream.Position += $Count
    }

    $stream = New-Object IO.MemoryStream(, $Bytes)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x3004 -or $reader.ReadUInt16() -ne 0x3004) {
            throw 'Unsupported recurrence reader/writer version.'
        }
        $frequency = $reader.ReadUInt16()
        $pattern = $reader.ReadUInt16()
        $calendar = $reader.ReadUInt16()
        if ($frequency -notin 0x200A, 0x200B, 0x200C, 0x200D -or $calendar -notin 0, 1) {
            throw 'Only ordinary Gregorian recurrence data is supported.'
        }
        $null = $reader.ReadUInt32()
        $period = $reader.ReadUInt32()
        if ($period -eq 0 -or $reader.ReadUInt32() -ne 0) { throw 'Invalid recurrence period or sliding flag.' }
        switch ($pattern) {
            0 { }
            1 { Step-RecurrenceBytes -Reader $reader -Count 4 }
            2 { Step-RecurrenceBytes -Reader $reader -Count 4 }
            3 { Step-RecurrenceBytes -Reader $reader -Count 8 }
            default { throw "Unsupported binary recurrence pattern: $pattern." }
        }
        Step-RecurrenceBytes -Reader $reader -Count 12
        $deletedCount = $reader.ReadUInt32()
        if ($deletedCount -gt ($stream.Length - $stream.Position) / 4) { throw 'Truncated deleted-instance array.' }
        $deletedDates = New-Object 'System.Collections.Generic.List[uint32]'
        for ($index = 0; $index -lt $deletedCount; $index++) { $deletedDates.Add($reader.ReadUInt32()) }
        $modifiedCount = $reader.ReadUInt32()
        if ($modifiedCount -gt $deletedCount -or $modifiedCount -gt [uint16]::MaxValue -or
            $modifiedCount -gt ($stream.Length - $stream.Position) / 4) {
            throw 'Invalid modified-instance count.'
        }
        $modifiedOffsets = New-Object 'System.Collections.Generic.List[int]'
        $modifiedDates = New-Object 'System.Collections.Generic.List[uint32]'
        for ($index = 0; $index -lt $modifiedCount; $index++) {
            $modifiedOffsets.Add([int]$stream.Position)
            $modifiedDates.Add($reader.ReadUInt32())
        }
        Step-RecurrenceBytes -Reader $reader -Count 8
        $readerVersion = $reader.ReadUInt32()
        $writerVersion = $reader.ReadUInt32()
        if ($readerVersion -ne 0x3006 -or $writerVersion -notin 0x3008, 0x3009) {
            throw 'Unsupported appointment recurrence reader/writer version.'
        }
        Step-RecurrenceBytes -Reader $reader -Count 8
        $exceptionCount = $reader.ReadUInt16()
        if ($exceptionCount -ne $modifiedCount) { throw 'Recurrence exception counts disagree.' }
        $exceptions = New-Object 'System.Collections.Generic.List[object]'
        for ($index = 0; $index -lt $exceptionCount; $index++) {
            $offset = [int]$stream.Position
            $start = $reader.ReadUInt32()
            $end = $reader.ReadUInt32()
            $original = $reader.ReadUInt32()
            $flags = $reader.ReadUInt16()
            if (($flags -band 0xFC00) -ne 0 -or $end -le $start) {
                throw 'Unsupported exception flags or invalid exception duration.'
            }
            foreach ($flag in 1, 2, 4, 8, 16, 32, 64, 128, 256) {
                if (($flags -band $flag) -eq 0) { continue }
                if ($flag -in 1, 16) {
                    $lengthWithNull = $reader.ReadUInt16()
                    $length = $reader.ReadUInt16()
                    if ($lengthWithNull -ne $length + 1) { throw 'Invalid recurrence string lengths.' }
                    Step-RecurrenceBytes -Reader $reader -Count $length
                } else { Step-RecurrenceBytes -Reader $reader -Count 4 }
            }
            $exceptions.Add([PSCustomObject]@{
                    Offset = $offset; ExtendedOffset = -1; Start = $start; End = $end
                    Original = $original; Flags = $flags
                })
        }
        if ($reader.ReadUInt32() -ne 0) { throw 'Unsupported recurrence ReservedBlock1.' }
        foreach ($exception in $exceptions) {
            if ($writerVersion -eq 0x3009) {
                $highlightSize = $reader.ReadUInt32()
                if ($highlightSize -lt 4) { throw 'Invalid recurrence ChangeHighlight length.' }
                Step-RecurrenceBytes -Reader $reader -Count $highlightSize
            }
            if ($reader.ReadUInt32() -ne 0) { throw 'Unsupported recurrence ReservedBlockEE1.' }
            if (($exception.Flags -band 0x11) -ne 0) {
                $exception.ExtendedOffset = [int]$stream.Position
                if ($reader.ReadUInt32() -ne $exception.Start -or $reader.ReadUInt32() -ne $exception.End -or
                    $reader.ReadUInt32() -ne $exception.Original) {
                    throw 'Primary and extended exception dates disagree.'
                }
                foreach ($flag in 1, 16) {
                    if (($exception.Flags -band $flag) -ne 0) {
                        Step-RecurrenceBytes -Reader $reader -Count (2L * $reader.ReadUInt16())
                    }
                }
                $reservedSize = $reader.ReadUInt32()
                Step-RecurrenceBytes -Reader $reader -Count $reservedSize
            }
        }
        if ($reader.ReadUInt32() -ne 0) { throw 'Unsupported recurrence ReservedBlock2.' }
        # Exchange (InternalRecurrence.ParseExceptionInfo) and Outlook stop reading after ReservedBlock2.
        # Outlook can leave stale bytes there, for example remnants of exceptions that were removed later.
        # The blob is patched in place, so anything after ReservedBlock2 is preserved unchanged.
        $actualDates = @($exceptions | ForEach-Object { [uint32]($_.Start - ($_.Start % 1440)) } | Sort-Object)
        $listedDates = @($modifiedDates | Sort-Object)
        if (($actualDates -join ',') -cne ($listedDates -join ',')) {
            throw 'Modified-instance dates do not match exception records.'
        }
        $originalDates = @{}
        foreach ($exception in $exceptions) {
            $originalDate = [uint32]($exception.Original - ($exception.Original % 1440))
            if ($originalDates.ContainsKey($originalDate) -or $deletedDates -notcontains $originalDate) {
                throw 'Invalid or duplicate original exception slot.'
            }
            $originalDates[$originalDate] = $true
        }
        [PSCustomObject]@{
            Pattern             = $pattern
            Exceptions          = $exceptions.ToArray()
            ModifiedDateOffsets = $modifiedOffsets.ToArray()
        }
    } catch [IO.EndOfStreamException] {
        throw 'Truncated recurrence data.'
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function ConvertTo-ExOPRecurrenceMinutes {
    param (
        [DateTime]
        $Local
    )
    $epoch = New-Object DateTime(1601, 1, 1)
    $ticks = $Local.Ticks - $epoch.Ticks
    if ($ticks -lt 0 -or $ticks % [TimeSpan]::TicksPerMinute -ne 0 -or
        $ticks / [TimeSpan]::TicksPerMinute -gt [uint32]::MaxValue) {
        throw 'The recurrence bridge requires representable whole-minute local times.'
    }
    [uint32]($ticks / [TimeSpan]::TicksPerMinute)
}

function New-ExOPExceptionTimeBridge {
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory recurrence value; performs no I/O.')]
    param (
        $Snapshot,

        [string]
        $From,

        [string]
        $To
    )
    if (-not $Snapshot.RecurrenceBase64) { throw 'The original recurrence data is missing.' }
    $bytes = [Convert]::FromBase64String($Snapshot.RecurrenceBase64)
    $layout = Get-ExOPRecurrenceBlobLayout -Bytes $bytes
    if (@($layout.Exceptions).Count -ne @($Snapshot.Modified).Count) {
        throw 'The EWS and binary exception counts disagree.'
    }
    $sourceZone = [TimeZoneInfo]::FindSystemTimeZoneById($From)
    $targetZone = [TimeZoneInfo]::FindSystemTimeZoneById($To)
    $byDate = @{}
    foreach ($entry in $Snapshot.Modified) {
        $local = [TimeZoneInfo]::ConvertTimeFromUtc((ConvertTo-ExOPInstant -Value $entry.OriginalStartUtc).UtcDateTime, $sourceZone)
        $date = ConvertTo-ExOPRecurrenceMinutes -Local $local.Date
        if ($byDate.ContainsKey($date)) { throw 'Duplicate EWS exception slot.' }
        $byDate[$date] = $entry
    }
    $replacements = New-Object 'System.Collections.Generic.List[object]'
    $newDates = New-Object 'System.Collections.Generic.List[uint32]'
    foreach ($record in $layout.Exceptions) {
        $date = [uint32]($record.Original - ($record.Original % 1440))
        if (-not $byDate.ContainsKey($date)) { throw 'An EWS exception could not be matched to the recurrence data.' }
        $entry = $byDate[$date]
        $newTimes = @{}
        foreach ($endpoint in 'Start', 'End') {
            $value = if ($endpoint -eq 'Start') { $entry.Values.StartUtc } else { $entry.Values.EndUtc }
            $utc = (ConvertTo-ExOPInstant -Value $value).UtcDateTime
            $sourceLocal = [TimeZoneInfo]::ConvertTimeFromUtc($utc, $sourceZone)
            if ((ConvertTo-ExOPRecurrenceMinutes -Local $sourceLocal) -ne $record.$endpoint) {
                throw 'EWS exception times disagree with the recurrence data.'
            }
            $targetLocal = [TimeZoneInfo]::ConvertTimeFromUtc($utc, $targetZone)
            if ($targetZone.IsAmbiguousTime($targetLocal) -or $targetZone.IsInvalidTime($targetLocal)) {
                throw 'The intermediate exception bridge would use an invalid or ambiguous local time.'
            }
            $newTimes[$endpoint] = ConvertTo-ExOPRecurrenceMinutes -Local $targetLocal
        }
        if ($newTimes.End -le $newTimes.Start) { throw 'The intermediate exception bridge has an invalid local duration.' }
        $newDates.Add([uint32]($newTimes.Start - ($newTimes.Start % 1440)))
        foreach ($offset in @($record.Offset, $record.ExtendedOffset)) {
            if ($offset -lt 0) { continue }
            $replacements.Add([PSCustomObject]@{Offset = $offset; Value = $newTimes.Start })
            $replacements.Add([PSCustomObject]@{Offset = $offset + 4; Value = $newTimes.End })
        }
    }
    $sortedDates = @($newDates | Sort-Object)
    for ($index = 0; $index -lt $sortedDates.Count; $index++) {
        $replacements.Add([PSCustomObject]@{Offset = $layout.ModifiedDateOffsets[$index]; Value = $sortedDates[$index] })
    }
    # Keep embedded exception messages addressable by their existing UTC endpoints.
    # Normal occurrence updates subsequently move both the message and its recurrence record.
    foreach ($replacement in $replacements) {
        [Array]::Copy([BitConverter]::GetBytes([uint32]$replacement.Value), 0, $bytes, $replacement.Offset, 4)
    }
    $null = Get-ExOPRecurrenceBlobLayout -Bytes $bytes
    [Convert]::ToBase64String($bytes)
}

function Get-ExOPAttachmentSnapshot {
    <#
        Returns verifiable attachment descriptors. File content is represented only by a SHA256 hash and
        never stored. Embedded items, reference attachments and files above the hash limit are verified
        by type, name, size and inline state, because the migration never rewrites attachments.
    #>
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item
    )
    $ns = Get-ExOPNamespaceManager -Node $Item
    foreach ($attachment in $Item.SelectNodes('t:Attachments/*', $ns)) {
        $size = [long]0
        $null = [long]::TryParse((Get-ExOPText -Node $attachment -Path 't:Size'), [ref]$size)
        $descriptor = [ordered]@{
            Type        = $attachment.LocalName
            Name        = Get-ExOPText -Node $attachment -Path 't:Name'
            ContentType = Get-ExOPText -Node $attachment -Path 't:ContentType'
            ContentId   = Get-ExOPText -Node $attachment -Path 't:ContentId'
            IsInline    = Get-ExOPText -Node $attachment -Path 't:IsInline'
            Size        = $size
            Sha256      = ''
        }
        if ($attachment.LocalName -eq 'FileAttachment' -and $size -le $script:MaxAttachmentHashBytes) {
            $id = $attachment.SelectSingleNode('t:AttachmentId', $ns).GetAttribute('Id')
            $request = '<m:GetAttachment><m:AttachmentIds><t:AttachmentId Id="' +
            (ConvertTo-ExOPXmlText -Value $id) + '"/></m:AttachmentIds></m:GetAttachment>'
            $response = Invoke-ExOPEwsRequest -Session $Session -Mailbox $Mailbox -Body $request -ReadOnly
            $file = $response.SelectSingleNode('//t:FileAttachment', (Get-ExOPNamespaceManager -Node $response))
            if ($null -eq $file) { throw 'The attachment lookup returned no file.' }
            $contentNode = $file.SelectSingleNode('t:Content', (Get-ExOPNamespaceManager -Node $file))
            if ($null -eq $contentNode) { throw 'The attachment response omitted file content.' }
            $descriptor.Sha256 = Get-ExOPByteHash -Bytes ([Convert]::FromBase64String($contentNode.InnerText))
        }
        [PSCustomObject]$descriptor
    }
}

function Assert-ExOPAttachmentSnapshot {
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        [object[]]
        $Expected
    )
    $actual = @(Get-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $Item)
    $before = @($Expected | ForEach-Object { $_ | ConvertTo-Json -Compress } | Sort-Object)
    $after = @($actual | ForEach-Object { $_ | ConvertTo-Json -Compress } | Sort-Object)
    if (($before -join "`n") -cne ($after -join "`n")) { throw 'File attachment content or metadata was not preserved.' }
}

function Get-ExOPRecurrenceLocalXml {
    param (
        [Xml.XmlNode]
        $Item
    )
    $recurrence = $Item.SelectSingleNode('t:Recurrence', (Get-ExOPNamespaceManager -Node $Item))
    if ($null -eq $recurrence) { return '' }
    $copy = $recurrence.CloneNode($true)
    foreach ($date in $copy.SelectNodes('t:*/t:StartDate|t:*/t:EndDate', (Get-ExOPNamespaceManager -Node $copy))) {
        if ($date.InnerText -notmatch '^\d{4}-\d{2}-\d{2}(Z|[+-]\d{2}:\d{2})?$') {
            throw 'Unexpected recurrence date representation.'
        }
        # Recurrence range boundaries are local calendar dates, not UTC instants.
        $localDate = [DateTime]::ParseExact($date.InnerText.Substring(0, 10), 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        $date.InnerText = $localDate.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
    $copy.OuterXml
}

function New-ExOPRawEndpointUpdates {
    <#
        Sets PidLidAppointmentStartWhole/EndWhole and PR_START_DATE/PR_END_DATE directly. Unlike calendar:Start
        and calendar:End, these values are stored exactly as given: Exchange does not re-snap all-day items to
        midnight or reschedule one endpoint before the other.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds request XML in memory; performs no I/O.')]
    param (
        [string]
        $StartUtc,

        [string]
        $EndUtc,

        # Single items also carry PidLidClipStart/ClipEnd, which equal the endpoints (MS-OXOCAL).
        [switch]
        $IncludeClip
    )
    $named = @(@(33293, $StartUtc), @(33294, $EndUtc))
    if ($IncludeClip) { $named += @(, @(33333, $StartUtc)); $named += @(, @(33334, $EndUtc)) }
    foreach ($endpoint in $named) {
        $field = '<t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="' + $endpoint[0] + '" PropertyType="SystemTime"/>'
        '<t:SetItemField>' + $field + '<t:CalendarItem><t:ExtendedProperty>' + $field +
        '<t:Value>' + $endpoint[1] + '</t:Value></t:ExtendedProperty></t:CalendarItem></t:SetItemField>'
    }
    foreach ($endpoint in @(@('0x0060', $StartUtc), @('0x0061', $EndUtc))) {
        $field = '<t:ExtendedFieldURI PropertyTag="' + $endpoint[0] + '" PropertyType="SystemTime"/>'
        '<t:SetItemField>' + $field + '<t:CalendarItem><t:ExtendedProperty>' + $field +
        '<t:Value>' + $endpoint[1] + '</t:Value></t:ExtendedProperty></t:CalendarItem></t:SetItemField>'
    }
}

function Set-ExOPSeriesTimeZoneState {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private writer called inside the public migration ShouldProcess boundary.')]
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        [string[]]
        $Properties,

        [string]
        $StartUtc,

        [string]
        $EndUtc
    )
    $updates = foreach ($propertyXml in $Properties) {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.LoadXml($propertyXml)
        $property = $document.DocumentElement
        $field = $property.SelectSingleNode('t:ExtendedFieldURI', (Get-ExOPNamespaceManager -Node $property))
        '<t:SetItemField>' + $field.OuterXml + '<t:CalendarItem>' + $property.OuterXml + '</t:CalendarItem></t:SetItemField>'
    }
    $metadataWritten = $false
    try {
        if ($null -ne $Session.ActiveOperation) { $Session.ActiveOperation.Phase = 'TimezoneMetadata' }
        $first = Set-ExOPCalendarFields -Session $Session -Mailbox $Mailbox -Item $Item -Updates @($updates) -PassThru
        $metadataWritten = $true
        if ($null -ne $Session.ActiveOperation) { $Session.ActiveOperation.MetadataWritten = $true }
        # A separate request is necessary: the first request retains the source recurrence cache.
        $nextItem = $Item.CloneNode($true)
        $nextId = $nextItem.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager -Node $nextItem))
        $nextId.SetAttribute('ChangeKey', $first.ChangeKey)
        $dateUpdates = if ((Get-ExOPText $Item 't:CalendarItemType') -eq 'Single') {
            # For single items the exact endpoint properties are written. EWS calendar:Start/End re-snap
            # all-day items depending on the request time zone context (moving the start by a day east of
            # UTC), and treat an unchanged UTC value as a no-op after the time zone rewrite, which lets
            # Exchange keep a recalculated end. Single items have no recurrence to regenerate.
            @(New-ExOPRawEndpointUpdates -StartUtc $StartUtc -EndUtc $EndUtc -IncludeClip)
        } else {
            @(
                (New-ExOPSetField -FieldUri 'calendar:Start' -ValueXml ('<t:Start>' + $StartUtc + '</t:Start>')),
                (New-ExOPSetField -FieldUri 'calendar:End' -ValueXml ('<t:End>' + $EndUtc + '</t:End>'))
            )
        }
        if ($null -ne $Session.ActiveOperation) { $Session.ActiveOperation.Phase = 'MasterDates' }
        $written = Set-ExOPCalendarFields -Session $Session -Mailbox $Mailbox -Item $nextItem -Updates $dateUpdates -PassThru
        if ($null -ne $Session.ActiveOperation) { $Session.ActiveOperation.DatesWritten = $true }
        $written
    } catch {
        $_.Exception.Data['OriginalItemModified'] = $metadataWritten
        $_.Exception.Data['MutationPhase'] = if ($metadataWritten) { 'Dates' } else { 'TimezoneMetadata' }
        throw
    }
}

function Set-ExOPItemZones {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private writer called inside the public migration ShouldProcess boundary.')]
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        [string]
        $StartZone,

        [string]
        $EndZone,

        [switch]
        $Send
    )
    $ns=Get-ExOPNamespaceManager $Item
    $updates=@()
    if ($Item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id') -ne $StartZone) {
        $updates+=New-ExOPSetField 'calendar:StartTimeZone' ('<t:StartTimeZone Id="'+(ConvertTo-ExOPXmlText $StartZone)+'"/>')
    }
    if ($Item.SelectSingleNode('t:EndTimeZone', $ns).GetAttribute('Id') -ne $EndZone) {
        $updates+=New-ExOPSetField 'calendar:EndTimeZone' ('<t:EndTimeZone Id="'+(ConvertTo-ExOPXmlText $EndZone)+'"/>')
    }
    if ($updates.Count -gt 0) { Set-ExOPCalendarFields -Session $Session -Mailbox $Mailbox -Item $Item -Updates $updates -Send:$Send }
}

function Get-ExOPSeriesSnapshot {
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        [string]
        $From,

        [string]
        $To
    )
    $ns=Get-ExOPNamespaceManager $Item
    $modified=@()
    foreach ($entry in $Item.SelectNodes('t:ModifiedOccurrences/t:Occurrence', $ns)) {
        $id=$entry.SelectSingleNode('t:ItemId', $ns).GetAttribute('Id')
        $exception=Get-ExOPCalendarItem $Session $Mailbox $id
        $exceptionNs=Get-ExOPNamespaceManager $exception
        $body=$exception.SelectSingleNode('t:Body', $exceptionNs)
        if ($null -ne $body -and $body.GetAttribute('IsTruncated') -eq 'true') {
            throw 'An exception body was truncated; no changes were made.'
        }
        $values=Get-ExOPRehomeValues -Item $exception -From $From -To $To
        $exceptionProperties = Get-ExOPTimeZoneProperties -Session $Session -Mailbox $Mailbox -ItemId $id -Instance
        $modified+= [PSCustomObject]@{
            OriginalStartUtc   =(Format-ExOPInstant (ConvertTo-ExOPInstant (Get-ExOPText $entry 't:OriginalStart')))
            Xml                =$exception.OuterXml
            Values             =$values
            Attachments        =@(Get-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $exception)
            TimeZoneProperties = $exceptionProperties.Properties
            PreparedProperties = @()
            O12Modes           = @{}
        }
    }
    $deleted=@($Item.SelectNodes('t:DeletedOccurrences/t:DeletedOccurrence', $ns) | ForEach-Object {
            Format-ExOPInstant (ConvertTo-ExOPInstant (Get-ExOPText $_ 't:Start'))
        })
    $itemId = $Item.SelectSingleNode('t:ItemId', $ns)
    $properties = Get-ExOPTimeZoneProperties -Session $Session -Mailbox $Mailbox -ItemId $itemId.GetAttribute('Id')
    if ($properties.ChangeKey -cne $itemId.GetAttribute('ChangeKey')) {
        throw 'The series changed while its snapshot was being read. Create a fresh report.'
    }
    [PSCustomObject]@{
        Xml                = $Item.OuterXml
        Modified           = $modified
        Deleted            = $deleted
        TimeZoneProperties = $properties.Properties
        HasIanaNames       = $properties.HasIanaNames
        RecurrenceBase64   = $properties.RecurrenceBase64
        Attachments        = @(Get-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $Item)
    }
}

function Get-ExOPExceptionUpdateOrder {
    <#
        Exchange rejects a modified occurrence that lands on the same local date as another occurrence.
        Exceptions are moved one at a time, so an exception moving later is updated after the later
        exceptions have already moved (descending order), and one moving earlier after the earlier ones
        (ascending order). A moved exception therefore never meets a neighbor that has not moved yet.
    #>
    param (
        [object[]]
        $Modified,

        [switch]
        $Original
    )
    $entries = foreach ($entry in $Modified) {
        $from = if ($Original) { $entry.Values.NewStartUtc } else { $entry.Values.StartUtc }
        $to = if ($Original) { $entry.Values.StartUtc } else { $entry.Values.NewStartUtc }
        [PSCustomObject]@{
            Entry = $entry
            Slot  = (ConvertTo-ExOPInstant -Value $entry.OriginalStartUtc).UtcTicks
            Delta = (ConvertTo-ExOPInstant -Value $to).UtcTicks - (ConvertTo-ExOPInstant -Value $from).UtcTicks
        }
    }
    @($entries | Where-Object { $_.Delta -le 0 } | Sort-Object -Property Slot | ForEach-Object { $_.Entry })
    @($entries | Where-Object { $_.Delta -gt 0 } | Sort-Object -Property Slot -Descending | ForEach-Object { $_.Entry })
}

function Update-ExOPPreservedExceptions {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private writer called inside the public migration ShouldProcess boundary.')]
    param (
        $Session,

        [string]
        $Mailbox,

        [string]
        $MasterId,

        $Snapshot,

        [string]
        $OldSeriesZone,

        [string]
        $NewSeriesZone,

        [switch]
        $Original
    )
    $master=Get-ExOPCalendarItem $Session $Mailbox $MasterId
    $ns=Get-ExOPNamespaceManager $master
    $modified=@($master.SelectNodes('t:ModifiedOccurrences/t:Occurrence', $ns))
    $deleted=@($master.SelectNodes('t:DeletedOccurrences/t:DeletedOccurrence', $ns))
    if ($modified.Count -ne @($Snapshot.Modified).Count -or $deleted.Count -ne @($Snapshot.Deleted).Count) {
        throw 'The server did not retain the exception objects. Reconstructing exceptions is not supported.'
    }
    foreach ($entry in @(Get-ExOPExceptionUpdateOrder -Modified @($Snapshot.Modified) -Original:$Original)) {
        if ($null -ne $Session.ActiveOperation) { $Session.ActiveOperation.Phase = 'Exception:' + $entry.OriginalStartUtc }
        $slot=Convert-ExOPWallClockZone -Utc $entry.OriginalStartUtc -From $OldSeriesZone -To $NewSeriesZone
        $matchingOccurrences=@($modified | Where-Object { (ConvertTo-ExOPInstant (Get-ExOPText $_ 't:OriginalStart')) -eq (ConvertTo-ExOPInstant $slot) })
        if ($matchingOccurrences.Count -ne 1) { throw "The preserved exception at original slot $slot could not be resolved." }
        $id=$matchingOccurrences[0].SelectSingleNode('t:ItemId', $ns).GetAttribute('Id')
        $current=Get-ExOPCalendarItem $Session $Mailbox $id
        if ($null -ne $entry.PSObject.Properties['Attachments']) {
            Assert-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $current -Expected @($entry.Attachments)
        }
        $values=$entry.Values
        $startZone=if ($Original) { $values.StartZone }else { $values.NewStartZone }
        $endZone=if ($Original) { $values.EndZone }else { $values.NewEndZone }
        $start=if ($Original) { $values.StartUtc }else { $values.NewStartUtc }
        $end=if ($Original) { $values.EndUtc }else { $values.NewEndUtc }
        $currentStart = Format-ExOPInstant -Value (ConvertTo-ExOPInstant -Value (Get-ExOPText -Node $current -Path 't:Start'))
        $currentEnd = Format-ExOPInstant -Value (ConvertTo-ExOPInstant -Value (Get-ExOPText -Node $current -Path 't:End'))
        if ($currentStart -notin @($values.StartUtc, $values.NewStartUtc) -or
            $currentEnd -notin @($values.EndUtc, $values.NewEndUtc)) {
            throw 'An exception changed concurrently. Its current times were not overwritten.'
        }
        $properties = @()
        if ($Original -and $null -ne $entry.PSObject.Properties['TimeZoneProperties']) { $properties = @($entry.TimeZoneProperties) }
        elseif (-not $Original -and $null -ne $entry.PSObject.Properties['PreparedProperties']) { $properties = @($entry.PreparedProperties) }
        if ($properties.Count -gt 0) {
            # Logical timezone setters reschedule one endpoint before the other. Write the absolute pair
            # with the prepared timezone data so a valid overnight exception has no transient long span.
            $updates = @(New-ExOPRawEndpointUpdates -StartUtc $start -EndUtc $end)
            $updates += @(ConvertTo-ExOPTimezoneUpdates -Properties $properties)
        } else {
            $updates=@(
                (New-ExOPSetField 'calendar:StartTimeZone' ('<t:StartTimeZone Id="'+(ConvertTo-ExOPXmlText $startZone)+'"/>')),
                (New-ExOPSetField 'calendar:EndTimeZone' ('<t:EndTimeZone Id="'+(ConvertTo-ExOPXmlText $endZone)+'"/>')),
                (New-ExOPSetField 'calendar:Start' ('<t:Start>'+$start+'</t:Start>')),
                (New-ExOPSetField 'calendar:End' ('<t:End>'+$end+'</t:End>'))
            )
        }
        $oldItem = New-Object Xml.XmlDocument
        $oldItem.XmlResolver = $null
        $oldItem.LoadXml($entry.Xml)
        $updates += @(Get-ExOPReminderTimeUpdate -OriginalItem $oldItem.DocumentElement -NewStartUtc $start -NewStartZone $startZone)
        Set-ExOPCalendarFields -Session $Session -Mailbox $Mailbox -Item $current -Updates $updates
    }
}

function Assert-ExOPRehomeResult {
    param (
        $Session,

        [string]
        $Mailbox,

        [string]
        $ItemId,

        $Values,

        $Snapshot,

        [switch]
        $Original
    )
    $item=Get-ExOPCalendarItem $Session $Mailbox $ItemId
    $ns=Get-ExOPNamespaceManager $item
    $expectedStart=if ($Original) { $Values.StartUtc }else { $Values.NewStartUtc }
    $expectedEnd=if ($Original) { $Values.EndUtc }else { $Values.NewEndUtc }
    $expectedStartZone=if ($Original) { $Values.StartZone }else { $Values.NewStartZone }
    $expectedEndZone=if ($Original) { $Values.EndZone }else { $Values.NewEndZone }
    $actualStart = Get-ExOPText $item 't:Start'; $actualEnd = Get-ExOPText $item 't:End'
    $actualStartZone = $item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
    $actualEndZone = $item.SelectSingleNode('t:EndTimeZone', $ns).GetAttribute('Id')
    if ((ConvertTo-ExOPInstant $actualStart) -ne (ConvertTo-ExOPInstant $expectedStart) -or
        (ConvertTo-ExOPInstant $actualEnd) -ne (ConvertTo-ExOPInstant $expectedEnd) -or
        $actualStartZone -ne $expectedStartZone -or $actualEndZone -ne $expectedEndZone) {
        throw ("Read-back verification failed for endpoint times/timezones. Expected {0} [{1}] - {2} [{3}], found {4} [{5}] - {6} [{7}]." -f
            $expectedStart, $expectedStartZone, $expectedEnd, $expectedEndZone, $actualStart, $actualStartZone, $actualEnd, $actualEndZone)
    }
    if ($null -ne $Snapshot) {
        $originalMaster = New-Object Xml.XmlDocument
        $originalMaster.XmlResolver = $null
        $originalMaster.LoadXml($Snapshot.Xml)
        if ((Get-ExOPRecurrenceLocalXml -Item $item) -cne (Get-ExOPRecurrenceLocalXml -Item $originalMaster.DocumentElement)) {
            throw 'The recurrence pattern or local range dates changed.'
        }
        $rangeZone = [TimeZoneInfo]::FindSystemTimeZoneById($expectedStartZone)
        foreach ($date in $item.SelectNodes('t:Recurrence/t:*/t:StartDate|t:Recurrence/t:*/t:EndDate', $ns)) {
            if ($date.InnerText.Length -eq 10) { continue }
            $localDate = [DateTime]::ParseExact($date.InnerText.Substring(0, 10), 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            $offset = $rangeZone.GetUtcOffset($localDate)
            $suffix = '{0}{1:00}:{2:00}' -f $(if ($offset.Ticks -lt 0) { '-' } else { '+' }),
            [Math]::Abs($offset.Hours), [Math]::Abs($offset.Minutes)
            $actualSuffix = $date.InnerText.Substring(10)
            if ($actualSuffix -eq 'Z' -and $offset.Ticks -eq 0) { continue }
            if ($actualSuffix -cne $suffix) { throw 'A recurrence range date has an unexpected timezone offset.' }
        }
        if ($null -ne $Snapshot.PSObject.Properties['Attachments']) {
            Assert-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $item -Expected @($Snapshot.Attachments)
        }
        $modified=@($item.SelectNodes('t:ModifiedOccurrences/t:Occurrence', $ns))
        $deleted=@($item.SelectNodes('t:DeletedOccurrences/t:DeletedOccurrence', $ns))
        if ($modified.Count -ne @($Snapshot.Modified).Count -or $deleted.Count -ne @($Snapshot.Deleted).Count) {
            throw 'Read-back verification failed for recurrence exception counts.'
        }
        foreach ($entry in $Snapshot.Modified) {
            $slot=Convert-ExOPWallClockZone -Utc $entry.OriginalStartUtc -From $Values.StartZone -To $expectedStartZone
            $match=@($modified | Where-Object { (ConvertTo-ExOPInstant (Get-ExOPText $_ 't:OriginalStart')) -eq (ConvertTo-ExOPInstant $slot) })
            if ($match.Count -ne 1) { throw 'A preserved modified occurrence could not be verified.' }
            $id=$match[0].SelectSingleNode('t:ItemId', $ns).GetAttribute('Id')
            $exception=Get-ExOPCalendarItem $Session $Mailbox $id
            if ($null -ne $entry.PSObject.Properties['Attachments']) {
                Assert-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $exception -Expected @($entry.Attachments)
            }
            $old=New-Object Xml.XmlDocument; $old.XmlResolver=$null; $old.LoadXml($entry.Xml)
            foreach ($name in 'Subject', 'Location', 'Body', 'Categories', 'Sensitivity', 'IsAllDayEvent', 'LegacyFreeBusyStatus', 'ReminderIsSet', 'ReminderMinutesBeforeStart') {
                if ((Get-ExOPText $exception "t:$name") -cne (Get-ExOPText $old.DocumentElement "t:$name")) {
                    throw "A preserved exception failed verification for $name."
                }
            }
            $start=if ($Original) { $entry.Values.StartUtc }else { $entry.Values.NewStartUtc }
            $end=if ($Original) { $entry.Values.EndUtc }else { $entry.Values.NewEndUtc }
            if ((ConvertTo-ExOPInstant (Get-ExOPText $exception 't:Start')) -ne (ConvertTo-ExOPInstant $start) -or
                (ConvertTo-ExOPInstant (Get-ExOPText $exception 't:End')) -ne (ConvertTo-ExOPInstant $end)) {
                throw 'A preserved exception failed time verification.'
            }
            $reminderZone = if ($Original) { $entry.Values.StartZone } else { $entry.Values.NewStartZone }
            Assert-ExOPReminderTime -OriginalItem $old.DocumentElement -CurrentItem $exception -NewStartUtc $start -NewStartZone $reminderZone
        }
        $actualDeleted=@($deleted | ForEach-Object { Format-ExOPInstant (ConvertTo-ExOPInstant (Get-ExOPText $_ 't:Start')) } | Sort-Object)
        $expectedDeleted=@($Snapshot.Deleted | ForEach-Object { Convert-ExOPWallClockZone -Utc $_ -From $Values.StartZone -To $expectedStartZone } | Sort-Object)
        if (($actualDeleted-join '|') -cne ($expectedDeleted-join '|')) { throw 'Deleted recurrence slots were not preserved.' }
    }
    return , $item
}

function Test-ExOPNotificationRequired {
    <#
        A meeting update is sent only for meetings that still have attendees or resources.
        Exchange rejects a meeting update without recipients (ErrorInvalidRecipients).
    #>
    param (
        [Xml.XmlNode]
        $Item
    )
    if ((Get-ExOPText $Item 't:IsMeeting') -ne 'true') { return $false }
    $ns = Get-ExOPNamespaceManager $Item
    $Item.SelectNodes('t:RequiredAttendees/t:Attendee|t:OptionalAttendees/t:Attendee|t:Resources/t:Attendee', $ns).Count -gt 0
}

function Send-ExOPSeriesUpdate {
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item
    )
    if (Test-ExOPNotificationRequired -Item $Item) {
        $subject='<t:Subject>'+(ConvertTo-ExOPXmlText (Get-ExOPText $Item 't:Subject'))+'</t:Subject>'
        Set-ExOPCalendarFields -Session $Session -Mailbox $Mailbox -Item $Item -Updates @((New-ExOPSetField -FieldUri 'item:Subject' -ValueXml $subject)) -Send
    }
}

function Get-ExOPRoomInfo {
    param (
        [Xml.XmlNode]
        $Item
    )
    $ns = Get-ExOPNamespaceManager -Node $Item
    $resources = @($Item.SelectNodes('t:Resources/t:Attendee/t:Mailbox', $ns))
    [PSCustomObject]@{
        HasRoom           = $resources.Count -gt 0
        RoomNames         = @($resources | ForEach-Object {
                $name = Get-ExOPText -Node $_ -Path 't:Name'
                if ($name) { $name } else { Get-ExOPText -Node $_ -Path 't:EmailAddress' }
            }) -join '; '
        RoomSmtpAddresses = @($resources | ForEach-Object { Get-ExOPText -Node $_ -Path 't:EmailAddress' }) -join '; '
    }
}

function ConvertTo-ExOPTimezoneUpdates {
    param (
        [string[]]
        $Properties
    )
    foreach ($text in $Properties) {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.LoadXml($text)
        $property = $document.DocumentElement
        $field = $property.SelectSingleNode('t:ExtendedFieldURI', (Get-ExOPNamespaceManager -Node $property))
        if ($null -eq $field) { throw 'A timezone update has no property identity.' }
        '<t:SetItemField>' + $field.OuterXml + '<t:CalendarItem>' + $property.OuterXml + '</t:CalendarItem></t:SetItemField>'
    }
}

function Get-ExOPRawReminderValue {
    param (
        [Xml.XmlNode]
        $Item,

        [int]
        $PropertyId
    )
    Get-ExOPText -Node $Item -Path ("t:ExtendedProperty[t:ExtendedFieldURI/@PropertyId='" + $PropertyId + "']/t:Value")
}

function Get-ExOPReminderTimeUpdate {
    param (
        [Xml.XmlNode]
        $OriginalItem,

        [string]
        $NewStartUtc,

        [string]
        $NewStartZone
    )
    if ((Get-ExOPText -Node $OriginalItem -Path 't:ReminderIsSet') -ne 'true') { return }
    $oldStart = ConvertTo-ExOPInstant -Value (Get-ExOPText -Node $OriginalItem -Path 't:Start')
    $difference = (ConvertTo-ExOPInstant -Value $NewStartUtc) - $oldStart
    $type = Get-ExOPText -Node $OriginalItem -Path 't:CalendarItemType'
    $series = $type -eq 'RecurringMaster'
    # The occurrence's ReminderTime is inherited from the master; only its signal is instance-specific.
    $ids = if ($type -in 'Occurrence', 'Exception') { @(34144) } else { @(34050, 34144) }
    foreach ($id in $ids) {
        $value = Get-ExOPRawReminderValue -Item $OriginalItem -PropertyId $id
        if (-not $value) { throw "An enabled reminder has no readable original raw property $id." }
        $original = ConvertTo-ExOPInstant -Value $value
        if ($original.Year -ge 4500) { $target = $original }
        elseif ($series) {
            $zone = $OriginalItem.SelectSingleNode('t:StartTimeZone', (Get-ExOPNamespaceManager -Node $OriginalItem)).GetAttribute('Id')
            if (-not $NewStartZone) { throw 'A destination zone is required for a recurring reminder.' }
            $target = ConvertTo-ExOPInstant -Value (Convert-ExOPWallClockZone -Utc $value -From $zone -To $NewStartZone)
        } else { $target = $original.Add($difference) }
        $field = '<t:ExtendedFieldURI DistinguishedPropertySetId="Common" PropertyId="' + $id + '" PropertyType="SystemTime"/>'
        '<t:SetItemField>' + $field + '<t:CalendarItem><t:ExtendedProperty>' + $field +
        '<t:Value>' + (Format-ExOPInstant -Value $target) + '</t:Value></t:ExtendedProperty></t:CalendarItem></t:SetItemField>'
    }
}

function Assert-ExOPReminderTime {
    param (
        [Xml.XmlNode]
        $OriginalItem,

        [Xml.XmlNode]
        $CurrentItem,

        [string]
        $NewStartUtc,

        [string]
        $NewStartZone
    )
    foreach ($update in @(Get-ExOPReminderTimeUpdate -OriginalItem $OriginalItem -NewStartUtc $NewStartUtc -NewStartZone $NewStartZone)) {
        [xml]$document = '<root xmlns:t="' + $script:TypesNamespace + '">' + $update + '</root>'
        $ns = Get-ExOPNamespaceManager -Node $document
        $id = [int]$document.SelectSingleNode('//t:ExtendedFieldURI', $ns).GetAttribute('PropertyId')
        $expected = Get-ExOPText -Node $document -Path '//t:ExtendedProperty/t:Value'
        $actual = Get-ExOPRawReminderValue -Item $CurrentItem -PropertyId $id
        if (-not $actual -or (ConvertTo-ExOPInstant -Value $actual) -ne (ConvertTo-ExOPInstant -Value $expected)) {
            throw "The reminder raw time/signal $id did not follow the intended migration."
        }
    }
}

function Get-ExOPItemSnapshot {
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        [string]
        $From,

        [string]
        $To,

        # Hash limit of the operation that produced the hash being compared; -1 uses the limit of this run.
        [long]
        $AttachmentHashLimitBytes = -1
    )
    $runLimit = $script:MaxAttachmentHashBytes
    if ($AttachmentHashLimitBytes -ge 0) { $script:MaxAttachmentHashBytes = $AttachmentHashLimitBytes }
    try {
        if ((Get-ExOPText -Node $Item -Path 't:CalendarItemType') -eq 'RecurringMaster') {
            $snapshot = Get-ExOPSeriesSnapshot -Session $Session -Mailbox $Mailbox -Item $Item -From $From -To $To
        } else {
            $ns = Get-ExOPNamespaceManager -Node $Item
            $body = $Item.SelectSingleNode('t:Body', $ns)
            if ($null -ne $body -and $body.GetAttribute('IsTruncated') -eq 'true') { throw 'A truncated body prevents a reliable snapshot.' }
            $identifier = $Item.SelectSingleNode('t:ItemId', $ns)
            $properties = Get-ExOPTimeZoneProperties -Session $Session -Mailbox $Mailbox -ItemId $identifier.GetAttribute('Id') -Single
            if ($properties.ChangeKey -cne $identifier.GetAttribute('ChangeKey')) { throw 'The item changed while reading its snapshot.' }
            $snapshot = [PSCustomObject]@{
                Xml = $Item.OuterXml; Modified = @(); Deleted = @(); TimeZoneProperties = $properties.Properties
                HasIanaNames = $properties.HasIanaNames; RecurrenceBase64 = ''
                Attachments = @(Get-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $Item)
            }
        }
    } finally { $script:MaxAttachmentHashBytes = $runLimit }
    $snapshot | Add-Member -MemberType NoteProperty -Name Receipt -Value (Get-ExOPMigrationReceipt -Item $Item)
    $snapshot
}

function Assert-ExOPRollbackEndpoints {
    <#
        Without a proven ChangeKey, a rollback may only overwrite times and zones that this operation could have
        produced: the original or the intended values. Anything else may be a user's change and is never overwritten.
    #>
    param (
        [Xml.XmlNode]
        $Item,

        $Values,

        [switch]
        $AllowRollbackIntermediate
    )
    $ns = Get-ExOPNamespaceManager $Item
    $start = ConvertTo-ExOPInstant (Get-ExOPText $Item 't:Start')
    $end = ConvertTo-ExOPInstant (Get-ExOPText $Item 't:End')
    $startZone = $Item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
    $endZone = $Item.SelectSingleNode('t:EndTimeZone', $ns).GetAttribute('Id')
    # Each write sets both times together and both zones together, and the time zone metadata is written before
    # the dates. Valid states are therefore: original times and zones, original times with new zones, or new times
    # and zones. A rollback that was itself interrupted can also leave new times with the original zones.
    # A partial or other combination may be a user's change.
    $originalTimes = $start -eq (ConvertTo-ExOPInstant $Values.StartUtc) -and $end -eq (ConvertTo-ExOPInstant $Values.EndUtc)
    $newTimes = $start -eq (ConvertTo-ExOPInstant $Values.NewStartUtc) -and $end -eq (ConvertTo-ExOPInstant $Values.NewEndUtc)
    $originalZones = $startZone -eq $Values.StartZone -and $endZone -eq $Values.EndZone
    $newZones = $startZone -eq $Values.NewStartZone -and $endZone -eq $Values.NewEndZone
    if (-not (($originalTimes -and ($originalZones -or $newZones)) -or ($newTimes -and $newZones) -or
            ($AllowRollbackIntermediate -and $newTimes -and $originalZones))) {
        throw 'The item times or time zones changed outside this operation; the item was not overwritten.'
    }
}

function Assert-ExOPPreservedItemData {
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        $Snapshot
    )
    $before = New-Object Xml.XmlDocument
    $before.XmlResolver = $null
    $before.LoadXml($Snapshot.Xml)
    foreach ($name in 'UID', 'Subject', 'Body', 'Location', 'Categories', 'Sensitivity', 'IsAllDayEvent',
        'LegacyFreeBusyStatus', 'ReminderIsSet', 'ReminderMinutesBeforeStart') {
        if ((Get-ExOPText -Node $Item -Path ("t:" + $name)) -cne
            (Get-ExOPText -Node $before.DocumentElement -Path ("t:" + $name))) {
            throw "The item changed unexpectedly in $name."
        }
    }
    # An organizer may change only the attendees and send an update; such an item must never be moved back.
    if ((@(Get-ExOPRecipientIdentities -Item $Item) -join "`n") -cne (@(Get-ExOPRecipientIdentities -Item $before.DocumentElement) -join "`n")) {
        throw 'The item changed unexpectedly in its attendees or resources.'
    }
    # The migration preserves the local recurrence, so any difference is an organizer change such as a new interval.
    if ((Get-ExOPRecurrenceLocalXml -Item $Item) -cne (Get-ExOPRecurrenceLocalXml -Item $before.DocumentElement)) {
        throw 'The recurrence pattern or local range dates changed.'
    }
    Assert-ExOPAttachmentSnapshot -Session $Session -Mailbox $Mailbox -Item $Item -Expected @($Snapshot.Attachments)
}

function Assert-ExOPPreservedExceptionData {
    <#
        Compares a modified occurrence with its original snapshot without reading it again, so that a series
        rollback can refuse an organizer's occurrence change before any write.
    #>
    param (
        $Current,

        $Original
    )
    $currentXml = New-Object Xml.XmlDocument
    $currentXml.XmlResolver = $null
    $currentXml.LoadXml($Current.Xml)
    $originalXml = New-Object Xml.XmlDocument
    $originalXml.XmlResolver = $null
    $originalXml.LoadXml($Original.Xml)
    foreach ($name in 'Subject', 'Body', 'Location', 'Categories', 'Sensitivity', 'IsAllDayEvent',
        'LegacyFreeBusyStatus', 'ReminderIsSet', 'ReminderMinutesBeforeStart') {
        if ((Get-ExOPText -Node $currentXml.DocumentElement -Path ("t:" + $name)) -cne
            (Get-ExOPText -Node $originalXml.DocumentElement -Path ("t:" + $name))) {
            throw "An exception changed unexpectedly in $name."
        }
    }
    if ((@(Get-ExOPRecipientIdentities -Item $currentXml.DocumentElement) -join "`n") -cne
        (@(Get-ExOPRecipientIdentities -Item $originalXml.DocumentElement) -join "`n")) {
        throw 'An exception changed unexpectedly in its attendees or resources.'
    }
    $before = @(@($Original.Attachments) | Where-Object { $null -ne $_ } | ForEach-Object { $_ | ConvertTo-Json -Compress } | Sort-Object)
    $after = @(@($Current.Attachments) | Where-Object { $null -ne $_ } | ForEach-Object { $_ | ConvertTo-Json -Compress } | Sort-Object)
    if (($before -join "`n") -cne ($after -join "`n")) { throw 'An exception changed unexpectedly in its attachments.' }
}

function Set-ExOPFinalMigrationState {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private writer within the public migration ShouldProcess boundary.')]
    param (
        $Session,

        [string]
        $Mailbox,

        [Xml.XmlNode]
        $Item,

        $Receipt
    )
    $updates = @()
    if ($null -ne (Get-ExOPMigrationState -Item $Item)) {
        $updates += '<t:DeleteItemField>' + $script:MigrationStateFieldUri + '</t:DeleteItemField>'
    }
    if ($null -ne $Receipt) {
        $updates += '<t:SetItemField>' + $script:MigrationReceiptFieldUri + '<t:CalendarItem><t:ExtendedProperty>' +
        $script:MigrationReceiptFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value (
                ConvertTo-Json -InputObject $Receipt -Depth 20 -Compress)) + '</t:Value></t:ExtendedProperty></t:CalendarItem></t:SetItemField>'
    } elseif ($null -ne (Get-ExOPMigrationReceipt -Item $Item)) {
        $updates += '<t:DeleteItemField>' + $script:MigrationReceiptFieldUri + '</t:DeleteItemField>'
    }
    if ($updates.Count -gt 0) {
        $null = Set-ExOPCalendarFields -Session $Session -Mailbox $Mailbox -Item $Item -Updates $updates -PassThru
    }
}

function Set-ExOPVerifiedFinalMigrationState {
    <#
        Writes the final bookkeeping after a meeting update was sent. Attendee responses, for example a room's
        automatic acceptance, update the organizer's item and its ChangeKey without changing the calendar data.
        A newer key is accepted only while the state hash still proves the verified target state.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private writer within the public migration ShouldProcess boundary.')]
    param (
        $Session,

        [string]
        $Mailbox,

        [string]
        $ItemId,

        [Xml.XmlNode]
        $Item,

        $Receipt,

        [string]
        $TargetHash,

        [int]
        $MaxAttempts = 3
    )
    $operation = $Session.ActiveOperation
    for ($attempt = 1; ; $attempt++) {
        $ns = Get-ExOPNamespaceManager -Node $Item
        $key = $Item.SelectSingleNode('t:ItemId', $ns).GetAttribute('ChangeKey')
        if ($key -cne $operation.LastChangeKey) {
            $zone = $Item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
            $current = Get-ExOPItemSnapshot -Session $Session -Mailbox $Mailbox -Item $Item -From $zone -To $zone
            if ((Get-ExOPCalendarStateHash -Snapshot $current) -cne $TargetHash) { throw 'The verified state changed before finalization.' }
            Write-ExOPMigrationAudit -Run $operation.Run -Mailbox $Mailbox -OperationId $operation.OperationId -Phase $operation.Phase `
                -EventName 'VerifiedTargetKeyAccepted' -Data ([ordered]@{ PreviousChangeKey = $operation.LastChangeKey; ChangeKey = $key })
            $operation.LastChangeKey = $key
        }
        try {
            Set-ExOPFinalMigrationState -Session $Session -Mailbox $Mailbox -Item $Item -Receipt $Receipt
            return
        } catch {
            # A response processed between the read and the write makes Exchange reject the stale key.
            if ($attempt -ge $MaxAttempts -or [string]$_.Exception.Data['EwsResponseCode'] -ne 'ErrorIrresolvableConflict') { throw }
            $Item = Get-ExOPCalendarItem -Session $Session -Mailbox $Mailbox -ItemId $ItemId
        }
    }
}

function Get-ExOPOriginalSlotKey {
    param (
        [string]
        $Utc,

        [string]
        $Zone
    )
    [TimeZoneInfo]::ConvertTimeFromUtc((ConvertTo-ExOPInstant -Value $Utc).UtcDateTime,
        [TimeZoneInfo]::FindSystemTimeZoneById($Zone)).ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
}

function Test-ExOPExceptionEndpointPair {
    <#
        Each exception write sets both endpoints together, so only the complete original or intended pair can be
        produced by this operation. A mixed pair, such as an intended start with the original end, is a user's change.
    #>
    param (
        $Entry,

        $Original
    )
    $start = ConvertTo-ExOPInstant -Value $Entry.Values.StartUtc
    $end = ConvertTo-ExOPInstant -Value $Entry.Values.EndUtc
    $expected = $Original.Values
    ($start -eq (ConvertTo-ExOPInstant -Value $expected.StartUtc) -and $end -eq (ConvertTo-ExOPInstant -Value $expected.EndUtc)) -or
    ($start -eq (ConvertTo-ExOPInstant -Value $expected.NewStartUtc) -and $end -eq (ConvertTo-ExOPInstant -Value $expected.NewEndUtc))
}

function Invoke-ExOPPreSendRollback {
    [CmdletBinding()]
    param (
        $Session,

        $Operation
    )
    if ($Operation.NotificationStarted) { throw 'Automatic rollback is prohibited after notification sending may have started.' }
    if ($Operation.Run.LoggingFailed) { throw 'Audit storage is unavailable; further automatic writes are unsafe.' }
    $Operation.RollingBack = $true
    $Operation.Phase = 'RollbackInspection'
    Write-ExOPMigrationAudit -Run $Operation.Run -Mailbox $Operation.Mailbox -OperationId $Operation.OperationId `
        -Phase $Operation.Phase -EventName 'RollbackStarted' -Data $null
    $item = Get-ExOPCalendarItem -Session $Session -Mailbox $Operation.Mailbox -ItemId $Operation.ItemId
    $ns = Get-ExOPNamespaceManager -Node $item
    $key = $item.SelectSingleNode('t:ItemId', $ns).GetAttribute('ChangeKey')
    $marker = Get-ExOPMigrationState -Item $item
    $receipt = Get-ExOPMigrationReceipt -Item $item
    $owned = ($null -ne $marker -and $marker.OperationId -ceq $Operation.OperationId) -or
    ($null -ne $receipt -and $receipt.OperationId -ceq $Operation.OperationId)
    if (-not $owned -and $Operation.AcknowledgedWrites -gt 0) {
        throw 'Operation ownership is no longer provable; the item was not overwritten.'
    }
    $zone = $item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
    $current = Get-ExOPItemSnapshot -Session $Session -Mailbox $Operation.Mailbox -Item $item -From $zone -To $zone
    $alreadyOriginal = (Get-ExOPCalendarStateHash -Snapshot $current) -ceq $Operation.OriginalStateHash
    # The ChangeKey proves that nobody else changed the item only if it is the key this operation (or its journal)
    # acknowledged. Reconcile starts from the current key, so it also carries the journaled key for comparison.
    $journalKeyMatches = $null -eq $Operation.PSObject.Properties['JournalChangeKey'] -or
    ([bool]$Operation.JournalChangeKey -and $Operation.JournalChangeKey -ceq $key)
    $keyProven = $key -ceq $Operation.LastChangeKey -and $journalKeyMatches
    if ($key -cne $Operation.LastChangeKey) {
        # A rejected meeting update can be saved before Exchange refuses the submission. Only the ChangeKey
        # differs then: the calendar data still equals the verified target state written by this operation.
        $rejectedSendSaved = $owned -and $null -ne $Operation.PSObject.Properties['NotificationRejected'] -and
        [bool]$Operation.NotificationRejected -and $null -ne $Operation.PSObject.Properties['VerifiedTargetHash'] -and
        [bool]$Operation.VerifiedTargetHash -and (Get-ExOPCalendarStateHash -Snapshot $current) -ceq $Operation.VerifiedTargetHash
        # Only when resuming a journaled rollback can a key from this operation's own unacknowledged last write be
        # explained without proof; the endpoint and preserved-data checks below then decide whether the state is ours.
        $ownUnknownWrite = $owned -and [bool]$Operation.LastWriteUnknown -and
        $null -ne $Operation.PSObject.Properties['RollbackInProgress'] -and [bool]$Operation.RollbackInProgress
        if (-not $rejectedSendSaved -and -not $ownUnknownWrite -and (-not $alreadyOriginal -or (-not $owned -and $Operation.WriteAttempted))) {
            throw 'The latest write outcome or a concurrent change cannot be safely reconciled; rollback was not forced.'
        }
        if ($rejectedSendSaved) { $keyProven = $true }
        # Only our bookkeeping is removed when read-back proves all calendar data is already original.
        $Operation.LastChangeKey = $key
    }
    if (-not $alreadyOriginal) {
        if (-not $owned) { throw 'An unmarked changed item cannot be automatically restored.' }
        if (-not $keyProven) {
            # A ChangeKey that the journal did not acknowledge is only explained by our own unacknowledged last write.
            if (-not [bool]$Operation.LastWriteUnknown) {
                throw 'The item changed after the last acknowledged write of this operation; it was not overwritten.'
            }
            $rollbackIntermediate = $null -ne $Operation.PSObject.Properties['RollbackIntermediatePossible'] -and [bool]$Operation.RollbackIntermediatePossible
            Assert-ExOPRollbackEndpoints -Item $item -Values $Operation.Values -AllowRollbackIntermediate:$rollbackIntermediate
        }
        Assert-ExOPPreservedItemData -Session $Session -Mailbox $Operation.Mailbox -Item $item -Snapshot $Operation.Before
        if ($Operation.IsSeries) {
            # Read before any rollback write: an occurrence update sent to changed attendees must never be moved back.
            foreach ($entry in @($current.Modified)) {
                $slot = Get-ExOPOriginalSlotKey -Utc $entry.OriginalStartUtc -Zone $zone
                $original = @($Operation.Before.Modified | Where-Object {
                        (Get-ExOPOriginalSlotKey -Utc $_.OriginalStartUtc -Zone $Operation.Values.StartZone) -ceq $slot
                    })
                if ($original.Count -ne 1) { throw 'An exception no longer matches the original or intended operation state.' }
                Assert-ExOPPreservedExceptionData -Current $entry -Original $original[0]
                if (-not (Test-ExOPExceptionEndpointPair -Entry $entry -Original $original[0])) {
                    throw 'An exception no longer matches the original or intended operation state.'
                }
            }
        }
        if ($Operation.IsSeries) {
            if ($Operation.MetadataWritten -and -not $Operation.DatesWritten) {
                $Operation.Phase = 'RollbackNormalizeIntermediateDates'
                $updates = @(
                    (New-ExOPSetField -FieldUri 'calendar:Start' -ValueXml ('<t:Start>' + $Operation.Values.NewStartUtc + '</t:Start>')),
                    (New-ExOPSetField -FieldUri 'calendar:End' -ValueXml ('<t:End>' + $Operation.Values.NewEndUtc + '</t:End>'))
                )
                $null = Set-ExOPCalendarFields -Session $Session -Mailbox $Operation.Mailbox -Item $item -Updates $updates -PassThru
                $item = Get-ExOPCalendarItem -Session $Session -Mailbox $Operation.Mailbox -ItemId $Operation.ItemId
            }
            $ns = Get-ExOPNamespaceManager -Node $item
            $zone = $item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
            $current = Get-ExOPItemSnapshot -Session $Session -Mailbox $Operation.Mailbox -Item $item -From $zone -To $zone
            if ($current.Modified.Count -ne $Operation.Before.Modified.Count -or $current.Deleted.Count -ne $Operation.Before.Deleted.Count) {
                throw 'Exception loss prevents a safe in-place rollback.'
            }
            foreach ($entry in $current.Modified) {
                $slot = Get-ExOPOriginalSlotKey -Utc $entry.OriginalStartUtc -Zone $zone
                $original = @($Operation.Before.Modified | Where-Object {
                        (Get-ExOPOriginalSlotKey -Utc $_.OriginalStartUtc -Zone $Operation.Values.StartZone) -ceq $slot
                    })
                if ($original.Count -ne 1 -or -not (Test-ExOPExceptionEndpointPair -Entry $entry -Original $original[0])) {
                    throw 'An exception no longer matches the original or intended operation state.'
                }
            }
            $bridge = New-ExOPExceptionTimeBridge -Snapshot $current -From $zone -To $Operation.Values.StartZone
            $properties = @($Operation.Before.TimeZoneProperties) + @(
                '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33302" PropertyType="Binary"/>' +
                '<t:Value>' + $bridge + '</t:Value></t:ExtendedProperty>'
            )
            $null = Set-ExOPSeriesTimeZoneState -Session $Session -Mailbox $Operation.Mailbox -Item $item -Properties $properties `
                -StartUtc $Operation.Values.StartUtc -EndUtc $Operation.Values.EndUtc
            Update-ExOPPreservedExceptions -Session $Session -Mailbox $Operation.Mailbox -MasterId $Operation.ItemId `
                -Snapshot $Operation.Before -OldSeriesZone $Operation.Values.StartZone -NewSeriesZone $Operation.Values.StartZone -Original
        } else {
            $null = Set-ExOPSeriesTimeZoneState -Session $Session -Mailbox $Operation.Mailbox -Item $item `
                -Properties $Operation.Before.TimeZoneProperties -StartUtc $Operation.Values.StartUtc -EndUtc $Operation.Values.EndUtc
        }
        $item = Get-ExOPCalendarItem -Session $Session -Mailbox $Operation.Mailbox -ItemId $Operation.ItemId
        $Operation.Phase = 'RollbackRestoreRepresentation'
        $originalXml = New-Object Xml.XmlDocument
        $originalXml.XmlResolver = $null
        $originalXml.LoadXml($Operation.Before.Xml)
        $null = Set-ExOPCalendarFields -Session $Session -Mailbox $Operation.Mailbox -Item $item `
            -Updates (@(ConvertTo-ExOPTimezoneUpdates -Properties $Operation.Before.TimeZoneProperties) +
            @(Get-ExOPReminderTimeUpdate -OriginalItem $originalXml.DocumentElement -NewStartUtc $Operation.Values.StartUtc -NewStartZone $Operation.Values.StartZone)) -PassThru
        $seriesSnapshot = if ($Operation.IsSeries) { $Operation.Before } else { $null }
        $item = Assert-ExOPRehomeResult -Session $Session -Mailbox $Operation.Mailbox -ItemId $Operation.ItemId `
            -Values $Operation.Values -Snapshot $seriesSnapshot -Original
        Assert-ExOPPreservedItemData -Session $Session -Mailbox $Operation.Mailbox -Item $item -Snapshot $Operation.Before
        $current = Get-ExOPItemSnapshot -Session $Session -Mailbox $Operation.Mailbox -Item $item `
            -From $Operation.Values.StartZone -To $Operation.Values.StartZone
        Assert-ExOPTimeZoneProperties -Expected $Operation.Before.TimeZoneProperties -Actual $current.TimeZoneProperties
        if ((Get-ExOPCalendarStateHash -Snapshot $current) -cne $Operation.OriginalStateHash) {
            throw 'Rollback did not restore the original verified calendar state.'
        }
    }
    $Operation.Phase = 'RollbackFinalize'
    Set-ExOPFinalMigrationState -Session $Session -Mailbox $Operation.Mailbox -Item $item -Receipt $Operation.Before.Receipt
    $item = Get-ExOPCalendarItem -Session $Session -Mailbox $Operation.Mailbox -ItemId $Operation.ItemId
    $current = Get-ExOPItemSnapshot -Session $Session -Mailbox $Operation.Mailbox -Item $item `
        -From $Operation.Values.StartZone -To $Operation.Values.StartZone
    if ($null -ne (Get-ExOPMigrationState -Item $item) -or
        (Get-ExOPCalendarStateHash -Snapshot $current) -cne $Operation.OriginalStateHash) {
        throw 'Final rollback verification failed.'
    }
    $path = Save-ExOPMigrationSnapshot -Run $Operation.Run -Mailbox $Operation.Mailbox -OperationId $Operation.OperationId `
        -Name 'rollback-verified' -Snapshot $current
    Write-ExOPMigrationAudit -Run $Operation.Run -Mailbox $Operation.Mailbox -OperationId $Operation.OperationId `
        -Phase $Operation.Phase -EventName 'RollbackVerified' -Data ([PSCustomObject]@{Snapshot = $path })
    $path
}

function Invoke-ExOPCalendarEventMigration {
    <#
    .SYNOPSIS
    Previews or applies a reviewed report using EWS. No writes without -Apply.
    .DESCRIPTION
    Run in regular Windows PowerShell on a management/user computer, no local admin.
    Uses existing own/delegate/scoped impersonation permissions, not EMS.
    A delegate needs Send on Behalf or Send As for the owner unless -SkipSendPermissionCheck is used.
    CSV input is used as an explicit item list; it never expands to additional items.
    Single items and whole recurring series (including past occurrences) are supported.
    Validated Windows/EWS timezone definitions are serialized before date changes.
    O12 full/partial representation is preserved separately for each property.
    An in-progress marker blocks blind retries after interrupted multi-step writes.
    Existing exception objects are updated in place; they are never reconstructed.
    A validated binary exception-time bridge keeps embedded messages addressable.
    The known unsafe invited all-day series case is rejected before writing.
    Failures before notification trigger one guarded, verified rollback attempt.
    After a possible notification, no automatic rollback or resend is performed.
    File attachments are verified by SHA256; embedded items and reference attachments by metadata.
    Items carrying unhandled IANA timezone metadata are not supported.
    A snapshot and marker do not make the operation transactional.
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
        [string]
        $ToWindowsTimeZoneId,

        [switch]
        $Apply,

        [string]
        $SnapshotDirectory,

        [string]
        $LogDirectory,

        [switch]
        $Force,

        [switch]
        $SkipSendPermissionCheck
    )
    begin {
        $inputRows=New-Object 'System.Collections.Generic.List[object]'
        if ($PSCmdlet.ParameterSetName -eq 'Csv') {
            foreach ($entry in @(Import-Csv -LiteralPath $CsvPath)) { $inputRows.Add($entry) }
        }
        $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Rows') {
            foreach ($entry in @($InputObject)) { $inputRows.Add($entry) }
        }
    }
    end {
        if ($inputRows.Count -eq 0) { throw 'No input report rows were supplied.' }
        $directory = if ($LogDirectory) { $LogDirectory } else { $SnapshotDirectory }
        if ($Apply -and -not $WhatIfPreference -and -not $directory) {
            throw 'LogDirectory or SnapshotDirectory is required with -Apply.'
        }
        $run = New-ExOPMigrationRun -Directory $directory -Rows @($inputRows.ToArray()) -Apply ([bool]$Apply) `
            -EwsUrl $Session.EwsUrl.AbsoluteUri -EwsUrlSource (Get-ExOPSessionEwsUrlSource -Session $Session) -ToWindowsTimeZoneId $ToWindowsTimeZoneId
        $calendarIds = @{}
        $blocked = @{}
        Update-ExOPMigrationSummary -Run $run
        foreach ($row in $inputRows) {
            $mailbox = if ($null -ne $row.PSObject.Properties['Mailbox'] -and [string]$row.Mailbox) { [string]$row.Mailbox } else { '_invalid-input' }
            $itemId = if ($null -ne $row.PSObject.Properties['ItemId']) { [string]$row.ItemId } else { '' }
            $recordType = if ($null -ne $row.PSObject.Properties['RecordType']) { [string]$row.RecordType } else { '' }
            $sourceId = if ($null -ne $row.PSObject.Properties['FromWindowsTimeZoneId']) { [string]$row.FromWindowsTimeZoneId } else { '' }
            $result=[PSCustomObject][ordered]@{
                RunId=$run.RunId; OperationId=[Guid]::NewGuid().ToString('N')
                Mailbox=$mailbox; ItemId=$itemId; UID=''; Subject=''; Status='Failed'; Severity='Warning'
                From=$sourceId; To=''; RecordType=$recordType; Phase='Preflight'
                StartUtcBefore=''; StartUtcAfter=''; EndUtcBefore=''; EndUtcAfter=''
                HasRoom=$false; RoomNames=''; RoomSmtpAddresses=''; ResourceStatus='NotChecked'
                CalendarState='Unchanged'; NotificationStatus='NotStarted'; RollbackStatus='NotNeeded'
                SnapshotPath=''; AfterSnapshotPath=''; RollbackSnapshotPath=''; O12Modes=''; ChangedFields=''
                Error=''; ErrorCode=''; RollbackError=''; RelatedOperationId=''; FinishedUtc=''
                ReportDirectory =$run.Directory
            }
            $operation = [PSCustomObject]@{
                Run=$run; OperationId=$result.OperationId; Mailbox=$mailbox; ItemId=$itemId
                Phase='Preflight'; LastChangeKey=''; AcknowledgedWrites=0; WriteAttempted=$false
                LastWriteUnknown=$false; MetadataWritten=$false; DatesWritten=$false; NotificationStarted=$false
                RollingBack=$false; IsSeries=$false; Before=$null; Values=$null; Prepared=$null
                OriginalStateHash=''; VerifiedTargetHash=''
            }
            $Session.ActiveOperation = $null
            try {
                if ($run.LoggingFailed) {
                    $result.Status = 'NotAttempted'
                    throw 'Audit storage is unavailable; no additional writes are allowed.'
                }
                if ($blocked.ContainsKey($mailbox)) {
                    $result.Status = 'NotAttempted'
                    throw ('Mailbox processing is suspended: ' + $blocked[$mailbox])
                }
                foreach ($required in 'SchemaVersion', 'Mailbox', 'ItemId', 'ChangeKey', 'FromWindowsTimeZoneId', 'StartTimeZoneId', 'EndTimeZoneId', 'StartUtc', 'EndUtc', 'RecordType') {
                    if (-not $row.PSObject.Properties[$required] -or -not [string]$row.$required) { throw "Required report field missing: $required" }
                }
                if ([string]$row.SchemaVersion -ne '1') { throw 'Unsupported report schema version.' }
                if (-not $seen.Add($row.Mailbox.ToLowerInvariant()+'|'+$row.ItemId)) { throw 'The input contains a duplicate mailbox/item ID.' }
                try {
                    Assert-ExOPSendPermission -Session $Session -Mailbox $row.Mailbox -SkipSendPermissionCheck:$SkipSendPermissionCheck
                } catch {
                    $result.Status = 'NotAttempted'
                    throw
                }
                $from = Resolve-ExOPWindowsTimeZoneId -Id ([string]$row.FromWindowsTimeZoneId)
                $result.From = $from
                $to = Resolve-ExOPWindowsTimeZoneId -Id $ToWindowsTimeZoneId
                $result.To=$to
                if ($from -eq $to) { throw 'Source and target timezone IDs must differ.' }
                if (-not $calendarIds.ContainsKey($row.Mailbox)) { $calendarIds[$row.Mailbox]=Get-ExOPDefaultCalendarId $Session $row.Mailbox }
                $item=Get-ExOPCalendarItem $Session $row.Mailbox $row.ItemId
                $ns=Get-ExOPNamespaceManager $item
                $parent=$item.SelectSingleNode('t:ParentFolderId', $ns)
                if ($null -eq $parent -or $parent.GetAttribute('Id') -cne $calendarIds[$row.Mailbox]) { throw 'Item is not in the stated mailbox owner''s default calendar.' }
                if ((Get-ExOPText $item 't:IsOrganizer') -ne 'true') { throw 'The calendar owner is not the organizer.' }
                $type=Get-ExOPText $item 't:CalendarItemType'
                $isSeries=$type -eq 'RecurringMaster'
                $operation.IsSeries = $isSeries
                if ($type -notin @('Single', 'RecurringMaster')) { throw 'Only single items and recurring masters are accepted.' }
                if (($isSeries -and $row.RecordType -ne 'RecurringSeries') -or (-not $isSeries -and $row.RecordType -ne 'Single')) { throw 'Report item type no longer matches the server.' }
                $result.Subject = Get-ExOPText -Node $item -Path 't:Subject'
                $result.UID = Get-ExOPText -Node $item -Path 't:UID'
                $rooms = Get-ExOPRoomInfo -Item $item
                $result.HasRoom = $rooms.HasRoom
                $result.RoomNames = $rooms.RoomNames
                $result.RoomSmtpAddresses = $rooms.RoomSmtpAddresses
                $result.ResourceStatus = if ($rooms.HasRoom) { 'NotVerified' } else { 'NotApplicable' }
                $existingState = Get-ExOPMigrationState -Item $item
                if ($null -ne $existingState) {
                    $result.RelatedOperationId = $existingState.OperationId
                    $result.Status = 'Critical'
                    $result.Severity = 'Critical'
                    $result.CalendarState = 'RequiresManualAttention'
                    throw "Migration $($existingState.OperationId) is incomplete. Run the script with -Reconcile before retrying."
                }
                $currentStartZone=$item.SelectSingleNode('t:StartTimeZone', $ns).GetAttribute('Id')
                $currentEndZone=$item.SelectSingleNode('t:EndTimeZone', $ns).GetAttribute('Id')
                $expectedStartZone=if ($row.StartTimeZoneId -eq $from) { $to }else { $row.StartTimeZoneId }
                $expectedEndZone=if ($row.EndTimeZoneId -eq $from) { $to }else { $row.EndTimeZoneId }
                $inputIdentity = [ordered]@{
                    Mailbox=$mailbox; ItemId=$itemId; From=$from; To=$to; RecordType=$recordType
                    StartZone=[string]$row.StartTimeZoneId; EndZone=[string]$row.EndTimeZoneId
                    StartUtc=[string]$row.StartUtc; EndUtc=[string]$row.EndUtc; ChangeKey=[string]$row.ChangeKey
                }
                $inputHash = Get-ExOPCanonicalHash -Value $inputIdentity
                if ($currentStartZone -eq $expectedStartZone -and $currentEndZone -eq $expectedEndZone) {
                    $receipt = Get-ExOPMigrationReceipt -Item $item
                    if ($null -eq $receipt -or $receipt.InputHash -cne $inputHash -or
                        $null -eq $receipt.PSObject.Properties['StateHashVersion'] -or $receipt.StateHashVersion -notin 4, 5) {
                        throw 'The item is already in the target zone but has no matching verified migration receipt.'
                    }
                    $current = Get-ExOPItemSnapshot -Session $Session -Mailbox $mailbox -Item $item -From $currentStartZone -To $currentStartZone `
                        -AttachmentHashLimitBytes $(if ($null -ne $receipt.PSObject.Properties['AttachmentHashLimitBytes']) { [long]$receipt.AttachmentHashLimitBytes } else { -1 })
                    if ((Get-ExOPCalendarStateHash -Snapshot $current -Version $receipt.StateHashVersion) -cne $receipt.StateHash) {
                        throw 'The target-zone item no longer matches its verified complete migration state.'
                    }
                    $result.RelatedOperationId = $receipt.OperationId
                    $result.Status='AlreadyMigrated'
                    $result.Severity='Information'
                    $result.CalendarState='TargetVerified'
                    $result.NotificationStatus='NotResent'
                } else {
                    if ($item.SelectSingleNode('t:ItemId', $ns).GetAttribute('ChangeKey') -cne $row.ChangeKey) { throw 'The item changed after report creation. Create and review a fresh report.' }
                    if ($currentStartZone -ne $row.StartTimeZoneId -or $currentEndZone -ne $row.EndTimeZoneId) { throw 'The item timezone state differs from the reviewed report.' }
                    if ($currentStartZone -ne $from -and $currentEndZone -ne $from) { throw 'Neither endpoint matches the source zone.' }
                    if ((ConvertTo-ExOPInstant -Value $row.StartUtc) -ne (ConvertTo-ExOPInstant -Value (Get-ExOPText -Node $item -Path 't:Start')) -or
                        (ConvertTo-ExOPInstant -Value $row.EndUtc) -ne (ConvertTo-ExOPInstant -Value (Get-ExOPText -Node $item -Path 't:End'))) {
                        throw 'The reviewed UTC values differ from the server item.'
                    }
                    $values=Get-ExOPRehomeValues -Item $item -From $from -To $to
                    $operation.Values = $values
                    $operation.LastChangeKey = $item.SelectSingleNode('t:ItemId', $ns).GetAttribute('ChangeKey')
                    $result.StartUtcBefore=$values.StartUtc; $result.StartUtcAfter=$values.NewStartUtc
                    $result.EndUtcBefore=$values.EndUtc; $result.EndUtcAfter=$values.NewEndUtc
                    if ($isSeries) {
                        $pattern=$item.SelectSingleNode('t:Recurrence/*[1]', $ns)
                        if ($null -eq $pattern -or $pattern.LocalName -notin @(
                                'DailyRecurrence', 'WeeklyRecurrence', 'AbsoluteMonthlyRecurrence',
                                'RelativeMonthlyRecurrence', 'AbsoluteYearlyRecurrence', 'RelativeYearlyRecurrence'
                            )) {
                            throw 'This recurrence pattern is not supported.'
                        }
                        if ($currentStartZone -ne $from -or $currentEndZone -ne $from) {
                            throw 'Series migration requires both master endpoints to use the source zone.'
                        }
                        if ((Get-ExOPText -Node $item -Path 't:IsAllDayEvent') -eq 'true' -and
                            (Get-ExOPText -Node $item -Path 't:IsMeeting') -eq 'true' -and
                            $values.StartUtc -eq $values.NewStartUtc -and $values.EndUtc -eq $values.NewEndUtc) {
                            throw 'All-day recurring meetings are report-only when master UTC endpoints remain unchanged: native attendee exception merging is unsafe for this class. No changes were made.'
                        }
                    }
                    $snapshot = Get-ExOPItemSnapshot -Session $Session -Mailbox $mailbox -Item $item -From $from -To $to
                    $operation.Before = $snapshot
                    $zoneIds = @($values.StartZone, $values.EndZone, $values.NewStartZone, $values.NewEndZone)
                    foreach ($entry in $snapshot.Modified) {
                        $zoneIds += @($entry.Values.StartZone, $entry.Values.EndZone, $entry.Values.NewStartZone, $entry.Values.NewEndZone)
                    }
                    $definitions = Get-ExOPValidatedTimeZoneData -Session $Session -Mailbox $mailbox -Ids $zoneIds
                    $prepared = Get-ExOPPreparedTimeZoneProperties -Properties $snapshot.TimeZoneProperties -Definitions $definitions `
                        -Values $values -Item $item -Receipt $snapshot.Receipt
                    $operation.Prepared = $prepared
                    $null = @(Get-ExOPReminderTimeUpdate -OriginalItem $item -NewStartUtc $values.NewStartUtc -NewStartZone $values.NewStartZone)
                    $result.O12Modes = ConvertTo-Json -InputObject $prepared.O12Modes -Depth 8 -Compress
                    $exceptionModes = @{}
                    foreach ($entry in $snapshot.Modified) {
                        $exceptionXml = New-Object Xml.XmlDocument
                        $exceptionXml.XmlResolver = $null
                        $exceptionXml.LoadXml($entry.Xml)
                        $slot = Get-ExOPOriginalSlotKey -Utc $entry.OriginalStartUtc -Zone $values.StartZone
                        $modeReceipt = $null
                        if ($null -ne $snapshot.Receipt -and $null -ne $snapshot.Receipt.PSObject.Properties['ExceptionModes']) {
                            $property = $snapshot.Receipt.ExceptionModes.PSObject.Properties[$slot]
                            if ($null -ne $property) { $modeReceipt = [PSCustomObject]@{O12Modes =$property.Value } }
                        }
                        $exceptionPrepared = Get-ExOPPreparedTimeZoneProperties -Properties $entry.TimeZoneProperties -Definitions $definitions `
                            -Values $entry.Values -Item $exceptionXml.DocumentElement -Receipt $modeReceipt
                        $entry.PreparedProperties = $exceptionPrepared.Properties
                        $entry.O12Modes = $exceptionPrepared.O12Modes
                        $null = @(Get-ExOPReminderTimeUpdate -OriginalItem $exceptionXml.DocumentElement -NewStartUtc $entry.Values.NewStartUtc -NewStartZone $entry.Values.NewStartZone)
                        $exceptionModes[$slot] = $exceptionPrepared.O12Modes
                    }
                    $operation.OriginalStateHash = Get-ExOPCalendarStateHash -Snapshot $snapshot
                    $bridge = if ($isSeries) { New-ExOPExceptionTimeBridge -Snapshot $snapshot -From $from -To $to } else { '' }
                    Write-ExOPMigrationAudit -Run $run -Mailbox $mailbox -OperationId $result.OperationId -Phase 'Preflight' `
                        -EventName 'PlanValidated' -Data ([ordered]@{
                            Input=$inputIdentity; Values=$values; O12Modes=$prepared.O12Modes; ExceptionModes=$exceptionModes
                            HasRoom=$rooms.HasRoom; EwsServerVersion=$Session.LastServerVersion
                            TimezoneDefinitionsBackEndServer=$Session.LastBackEndServer; FrontEndServer=$Session.LastFrontEndServer
                            TimezoneRuleSignatures =@($definitions.Keys | Sort-Object | ForEach-Object {
                                    $definition=$definitions[$_]
                                    [PSCustomObject]@{Id=$_; Rules=@($definition.Rules | ForEach-Object { [PSCustomObject]@{Year=$_.Year; Signature=$_.Rule.Signature } }) }
                                })
                        })
                    if (-not $Apply) { $result.Status='Preview'; $result.Severity='Information' }
                    elseif ($PSCmdlet.ShouldProcess("$($row.Mailbox): $($row.ItemId)", "Rehome $($row.RecordType) from '$from' to '$to' and send normal meeting updates")) {
                        $beforeDocument = [ordered]@{
                            SchemaVersion=4; RunId=$run.RunId; OperationId=$result.OperationId; Input=$inputIdentity; Values=$values
                            AttachmentHashLimitBytes=[long]$script:MaxAttachmentHashBytes; Snapshot=$snapshot
                        }
                        $result.SnapshotPath = Save-ExOPMigrationSnapshot -Run $run -Mailbox $mailbox -OperationId $result.OperationId -Name 'before' -Snapshot $beforeDocument
                        $fresh = Get-ExOPCalendarItem -Session $Session -Mailbox $mailbox -ItemId $itemId
                        if ($fresh.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager -Node $fresh)).GetAttribute('ChangeKey') -cne $row.ChangeKey) {
                            throw 'The item changed during preflight; no original item changes were made.'
                        }
                        $Session.ActiveOperation = $operation
                        $operation.Phase = 'Marker'
                        $state = [PSCustomObject]@{
                            SchemaVersion=1; Status='InProgress'; OperationId=$result.OperationId; FromZone=$from; ToZone=$to
                            StartedUtc=[DateTimeOffset]::UtcNow.ToString('o'); NotificationMayHaveStarted=$false
                        }
                        $marker = Set-ExOPMigrationState -Session $Session -Mailbox $mailbox -Item $fresh -State $state
                        $markedItem = $fresh.CloneNode($true)
                        $markedItem.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager -Node $markedItem)).SetAttribute('ChangeKey', $marker.ChangeKey)
                        $properties = @($prepared.Properties)
                        if ($isSeries) {
                            $properties += @(
                                '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33302" PropertyType="Binary"/>' +
                                '<t:Value>' + $bridge + '</t:Value></t:ExtendedProperty>'
                            )
                        }
                        $null = Set-ExOPSeriesTimeZoneState -Session $Session -Mailbox $mailbox -Item $markedItem `
                            -Properties $properties -StartUtc $values.NewStartUtc -EndUtc $values.NewEndUtc
                        if ($isSeries) {
                            Update-ExOPPreservedExceptions -Session $Session -Mailbox $row.Mailbox -MasterId $row.ItemId -Snapshot $snapshot `
                                -OldSeriesZone $values.StartZone -NewSeriesZone $values.NewStartZone
                        }
                        $operation.Phase = 'PreserveO12Representation'
                        $item = Get-ExOPCalendarItem -Session $Session -Mailbox $mailbox -ItemId $itemId
                        $null = Set-ExOPCalendarFields -Session $Session -Mailbox $mailbox -Item $item `
                            -Updates (@(ConvertTo-ExOPTimezoneUpdates -Properties $prepared.Properties) +
                            @(Get-ExOPReminderTimeUpdate -OriginalItem $fresh -NewStartUtc $values.NewStartUtc -NewStartZone $values.NewStartZone)) -PassThru
                        $operation.Phase = 'VerifyBeforeNotification'
                        $seriesSnapshot = if ($isSeries) { $snapshot } else { $null }
                        $verified = Assert-ExOPRehomeResult -Session $Session -Mailbox $mailbox -ItemId $itemId -Values $values -Snapshot $seriesSnapshot
                        Assert-ExOPPreservedItemData -Session $Session -Mailbox $mailbox -Item $verified -Snapshot $snapshot
                        Assert-ExOPReminderTime -OriginalItem $fresh -CurrentItem $verified -NewStartUtc $values.NewStartUtc -NewStartZone $values.NewStartZone
                        $after = Get-ExOPItemSnapshot -Session $Session -Mailbox $mailbox -Item $verified -From $values.NewStartZone -To $values.NewStartZone
                        Assert-ExOPTimeZoneProperties -Expected $prepared.Properties -Actual $after.TimeZoneProperties
                        foreach ($entry in $after.Modified) {
                            $slot = Get-ExOPOriginalSlotKey -Utc $entry.OriginalStartUtc -Zone $values.NewStartZone
                            $original = @($snapshot.Modified | Where-Object {
                                    (Get-ExOPOriginalSlotKey -Utc $_.OriginalStartUtc -Zone $values.StartZone) -ceq $slot
                                })
                            if ($original.Count -ne 1) { throw 'An exception could not be matched for timezone verification.' }
                            Assert-ExOPTimeZoneProperties -Expected $original[0].PreparedProperties -Actual $entry.TimeZoneProperties
                        }
                        $operation.VerifiedTargetHash = Get-ExOPCalendarStateHash -Snapshot $after
                        $result.CalendarState = 'TargetVerified'
                        $result.AfterSnapshotPath = Save-ExOPMigrationSnapshot -Run $run -Mailbox $mailbox -OperationId $result.OperationId -Name 'after' -Snapshot $after
                        $changes = @(Get-ExOPCalendarDifferences -Before $snapshot -After $after)
                        $result.ChangedFields = @($changes.Field) -join '; '
                        Write-ExOPMigrationAudit -Run $run -Mailbox $mailbox -OperationId $result.OperationId `
                            -Phase $operation.Phase -EventName 'ActualChangesVerified' -Data $changes
                        if (Test-ExOPNotificationRequired -Item $verified) {
                            $operation.Phase = 'NotificationIntent'
                            $state.NotificationMayHaveStarted = $true
                            $null = Set-ExOPMigrationState -Session $Session -Mailbox $mailbox -Item $verified -State $state
                            $verified = Get-ExOPCalendarItem -Session $Session -Mailbox $mailbox -ItemId $itemId
                            $operation.Phase = 'Notification'
                            Send-ExOPSeriesUpdate -Session $Session -Mailbox $mailbox -Item $verified
                            $result.NotificationStatus = 'SendAcknowledged'
                        } else { $result.NotificationStatus = 'NotRequired' }
                        $operation.Phase = 'FinalVerification'
                        $verified = Assert-ExOPRehomeResult -Session $Session -Mailbox $mailbox -ItemId $itemId -Values $values -Snapshot $seriesSnapshot
                        $final = Get-ExOPItemSnapshot -Session $Session -Mailbox $mailbox -Item $verified -From $values.NewStartZone -To $values.NewStartZone
                        if ((Get-ExOPCalendarStateHash -Snapshot $final) -cne $operation.VerifiedTargetHash) { throw 'The verified state changed before finalization.' }
                        $receipt = [PSCustomObject]@{
                            SchemaVersion=1; OperationId=$result.OperationId; RunId=$run.RunId; InputHash=$inputHash
                            StateHash=$operation.VerifiedTargetHash; StateHashVersion=5; FromZone=$from; ToZone=$to
                            AttachmentHashLimitBytes=[long]$script:MaxAttachmentHashBytes; O12Modes=$prepared.O12Modes
                            ExceptionModes=$exceptionModes; CompletedUtc=[DateTimeOffset]::UtcNow.ToString('o')
                        }
                        $operation.Phase = 'FinalizeReceipt'
                        if ($result.NotificationStatus -eq 'SendAcknowledged') {
                            Set-ExOPVerifiedFinalMigrationState -Session $Session -Mailbox $mailbox -ItemId $itemId -Item $verified `
                                -Receipt $receipt -TargetHash $operation.VerifiedTargetHash
                        } else {
                            Set-ExOPFinalMigrationState -Session $Session -Mailbox $mailbox -Item $verified -Receipt $receipt
                        }
                        $verified = Get-ExOPCalendarItem -Session $Session -Mailbox $mailbox -ItemId $itemId
                        if ($null -ne (Get-ExOPMigrationState -Item $verified) -or
                            (Get-ExOPMigrationReceipt -Item $verified).OperationId -cne $result.OperationId) {
                            throw 'Final migration bookkeeping did not pass read-back verification.'
                        }
                        $result.Status='Applied'
                        $result.Severity='Information'
                    } else {
                        $result.Status = if ($WhatIfPreference) { 'WhatIf' } else { 'Skipped' }
                        $result.Severity='Information'
                    }
                }
            } catch {
                $result.Error=$_.Exception.Message
                $result.ErrorCode = [string]$_.Exception.Data['EwsResponseCode']
                $result.Phase = $operation.Phase
                if ($operation.WriteAttempted) {
                    if ($operation.NotificationStarted) {
                        $result.Status = 'Critical'
                        $result.Severity = 'Critical'
                        if ($result.NotificationStatus -ne 'SendAcknowledged') { $result.NotificationStatus = 'OutcomeUnknown' }
                        $result.RollbackStatus = 'ProhibitedAfterNotification'
                    } else {
                        $result.RollbackStatus = 'Attempted'
                        try {
                            $result.RollbackSnapshotPath = Invoke-ExOPPreSendRollback -Session $Session -Operation $operation
                            $result.Status = 'RolledBack'
                            $result.Severity = 'Warning'
                            $result.CalendarState = 'OriginalVerified'
                            $result.RollbackStatus = 'Verified'
                            $result.NotificationStatus = 'NotSent'
                        } catch {
                            $result.Status = 'Critical'
                            $result.Severity = 'Critical'
                            $result.CalendarState = 'RequiresManualAttention'
                            $result.RollbackStatus = 'Failed'
                            $result.RollbackError = $_.Exception.Message
                        }
                    }
                }
                if ($run.LoggingFailed) { $blocked[$mailbox] = 'Audit storage failure' }
                Write-Warning ("{0}: {1}. {2} Snapshot: {3}" -f $result.Severity.ToUpperInvariant(), $result.Status, $result.Error, $result.SnapshotPath)
            } finally {
                $Session.ActiveOperation = $null
            }
            if ($result.Phase -eq 'Preflight' -and $result.Status -in 'Applied', 'Preview', 'WhatIf', 'AlreadyMigrated', 'Skipped') {
                $result.Phase = if ($result.Status -eq 'Applied') { 'Completed' } else { $result.Status }
            }
            Complete-ExOPMigrationResult -Run $run -Result $result
            Write-Output -InputObject $result
        }
        Update-ExOPFinalMigrationSummary -Run $run
    }
}
