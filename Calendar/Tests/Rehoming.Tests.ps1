# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cspell:ignore Rehome Rehoming

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeDiscovery {
    # Golden values are hand-computed: US DST runs from the second Sunday in March to the first Sunday in November,
    # Australian DST from the first Sunday in October to the first Sunday in April; India, Arizona and UTC have no DST.
    $Script:wallClockCases = @(
        @{ From = 'Pacific Standard Time'; To = 'US Mountain Standard Time'; Utc = '2026-01-15T18:00:00Z'; Expected = '2026-01-15T17:00:00.0000000Z'; DeltaMinutes = -60 }
        @{ From = 'Pacific Standard Time'; To = 'US Mountain Standard Time'; Utc = '2026-11-02T18:00:00Z'; Expected = '2026-11-02T17:00:00.0000000Z'; DeltaMinutes = -60 }
        @{ From = 'Pacific Standard Time'; To = 'US Mountain Standard Time'; Utc = '2027-07-01T17:00:00Z'; Expected = '2027-07-01T17:00:00.0000000Z'; DeltaMinutes = 0 }
        @{ From = 'Central Standard Time'; To = 'UTC'; Utc = '2026-01-15T16:00:00Z'; Expected = '2026-01-15T10:00:00.0000000Z'; DeltaMinutes = -360 }
        @{ From = 'Central Standard Time'; To = 'UTC'; Utc = '2026-11-02T16:00:00Z'; Expected = '2026-11-02T10:00:00.0000000Z'; DeltaMinutes = -360 }
        @{ From = 'Central Standard Time'; To = 'UTC'; Utc = '2027-07-01T15:00:00Z'; Expected = '2027-07-01T10:00:00.0000000Z'; DeltaMinutes = -300 }
        @{ From = 'AUS Eastern Standard Time'; To = 'India Standard Time'; Utc = '2026-01-14T23:00:00Z'; Expected = '2026-01-15T04:30:00.0000000Z'; DeltaMinutes = 330 }
        @{ From = 'AUS Eastern Standard Time'; To = 'India Standard Time'; Utc = '2026-11-01T23:00:00Z'; Expected = '2026-11-02T04:30:00.0000000Z'; DeltaMinutes = 330 }
        @{ From = 'AUS Eastern Standard Time'; To = 'India Standard Time'; Utc = '2027-07-01T00:00:00Z'; Expected = '2027-07-01T04:30:00.0000000Z'; DeltaMinutes = 270 }
    )
    $Script:rejectedLocalTimeCases = @(
        @{ Name = 'US spring-forward gap'; To = 'Pacific Standard Time'; Utc = '2027-03-14T02:30:00Z' }
        @{ Name = 'US fall-back fold'; To = 'Pacific Standard Time'; Utc = '2027-11-07T01:30:00Z' }
        @{ Name = 'Australian spring-forward gap'; To = 'AUS Eastern Standard Time'; Utc = '2027-10-03T02:30:00Z' }
        @{ Name = 'Australian fall-back fold'; To = 'AUS Eastern Standard Time'; Utc = '2027-04-04T02:30:00Z' }
    )
    $Script:recurrenceCases = @(
        foreach ($pattern in 0, 1, 2, 3) {
            foreach ($version in 0x3008, 0x3009) {
                foreach ($flags in 0, 1, 16, 512, 1023) {
                    @{ Pattern = $pattern; Version = $version; Flags = $flags }
                }
            }
        }
    )
    $Script:corruptionCases = @(
        @{ Name = 'unknown pattern'; Anchor = 'Start'; Delta = 6; Value = 7 }
        @{ Name = 'unknown calendar type'; Anchor = 'Start'; Delta = 8; Value = 6 }
        @{ Name = 'unknown exception flags'; Anchor = 'Exception'; Delta = 13; Value = 128 }
        @{ Name = 'exception count mismatch'; Anchor = 'Exception'; Delta = -2; Value = 3 }
        @{ Name = 'extended date mismatch'; Anchor = 'Extended'; Delta = 0; Value = 0 }
    )
}

BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\EwsTransport.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\CalendarTimeZoneData.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\MigrationJournal.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Rehoming.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Reconcile.ps1

    # Pacific Standard Time is UTC-08:00 throughout the November 2026 test data.
    function ConvertTo-PacificStandardLocal {
        param(
            [string]
            $Utc
        )
        [DateTime]::SpecifyKind((ConvertTo-ExOPInstant -Value $Utc).UtcDateTime.AddHours(-8), [DateTimeKind]::Unspecified)
    }

    function New-RecurrenceTestData {
        param(
            [int]
            $Pattern,

            [int]
            $Version = 0x3009,

            [int]
            $Flags = 0x03FF,

            [switch]
            $Empty
        )
        $modified = @(
            [PSCustomObject]@{
                OriginalStartUtc = '2026-11-09T18:00:00Z'
                Values           = [PSCustomObject]@{ StartUtc = '2026-11-09T21:00:00Z'; EndUtc = '2026-11-09T22:30:00Z' }
            },
            [PSCustomObject]@{
                OriginalStartUtc = '2026-11-17T18:00:00Z'
                Values           = [PSCustomObject]@{ StartUtc = '2026-11-18T07:30:00Z'; EndUtc = '2026-11-18T09:00:00Z' }
            }
        )
        if ($Empty) { $modified = @() }
        $records = @(
            foreach ($entry in $modified) {
                [PSCustomObject]@{
                    Start    = ConvertTo-ExOPRecurrenceMinutes -Local (ConvertTo-PacificStandardLocal -Utc $entry.Values.StartUtc)
                    End      = ConvertTo-ExOPRecurrenceMinutes -Local (ConvertTo-PacificStandardLocal -Utc $entry.Values.EndUtc)
                    Original = ConvertTo-ExOPRecurrenceMinutes -Local (ConvertTo-PacificStandardLocal -Utc $entry.OriginalStartUtc)
                }
            }
        )
        $stream = New-Object IO.MemoryStream
        $writer = New-Object IO.BinaryWriter($stream)
        try {
            foreach ($number in 0x3004, 0x3004, 0x200A, $Pattern, 0) { $writer.Write([uint16]$number) }
            foreach ($number in 0, 1440, 0) { $writer.Write([uint32]$number) }
            switch ($Pattern) {
                1 { $writer.Write([uint32]2) }
                2 { $writer.Write([uint32]9) }
                3 { $writer.Write([uint32]2); $writer.Write([uint32]2) }
            }
            foreach ($number in 0x2023, 10, 1) { $writer.Write([uint32]$number) }
            $deleted = @($records | ForEach-Object { [uint32]($_.Original - ($_.Original % 1440)) } | Sort-Object)
            $writer.Write([uint32]$deleted.Count)
            foreach ($number in $deleted) { $writer.Write([uint32]$number) }
            $writer.Write([uint32]$records.Count)
            foreach ($number in @($records | ForEach-Object { [uint32]($_.Start - ($_.Start % 1440)) } | Sort-Object)) {
                $writer.Write([uint32]$number)
            }
            $writer.Write([uint32](ConvertTo-ExOPRecurrenceMinutes -Local ([DateTime]::new(2026, 11, 2))))
            foreach ($number in 0x5AE980DF, 0x3006, $Version, 600, 660) { $writer.Write([uint32]$number) }
            $writer.Write([uint16]$records.Count)
            foreach ($record in $records) {
                foreach ($number in $record.Start, $record.End, $record.Original) { $writer.Write([uint32]$number) }
                $writer.Write([uint16]$Flags)
                foreach ($flag in 1, 2, 4, 8, 16, 32, 64, 128, 256) {
                    if (($Flags -band $flag) -eq 0) { continue }
                    if ($flag -in 1, 16) {
                        $text = [Text.Encoding]::ASCII.GetBytes('value')
                        $writer.Write([uint16]($text.Length + 1))
                        $writer.Write([uint16]$text.Length)
                        $writer.Write($text)
                    } else {
                        $writer.Write([uint32]1)
                    }
                }
            }
            $writer.Write([uint32]0)
            foreach ($record in $records) {
                if ($Version -eq 0x3009) { $writer.Write([uint32]4); $writer.Write([uint32]0x100) }
                $writer.Write([uint32]0)
                if (($Flags -band 0x11) -ne 0) {
                    foreach ($number in $record.Start, $record.End, $record.Original) { $writer.Write([uint32]$number) }
                    foreach ($flag in 1, 16) {
                        if (($Flags -band $flag) -ne 0) {
                            $text = 'Unicode ' + [char]0x0416
                            $writer.Write([uint16]$text.Length)
                            $writer.Write([Text.Encoding]::Unicode.GetBytes($text))
                        }
                    }
                    $writer.Write([uint32]3)
                    $writer.Write([byte[]](11, 22, 33))
                }
            }
            $writer.Write([uint32]0)
            $writer.Flush()
            [PSCustomObject]@{ RecurrenceBase64 = [Convert]::ToBase64String($stream.ToArray()); Modified = $modified }
        } finally {
            $writer.Dispose()
            $stream.Dispose()
        }
    }

    function New-CalendarItemXml {
        param(
            [string]
            $InnerXml
        )
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '">' + $InnerXml + '</t:CalendarItem>')
        Write-Output -InputObject $document -NoEnumerate
    }

    function New-UpdateItemResponse {
        param(
            [string]
            $ChangeKey
        )
        $document = New-Object Xml.XmlDocument
        $document.LoadXml('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="' + $script:MessagesNamespace + '" xmlns:t="' +
            $script:TypesNamespace + '"><s:Body><m:UpdateItemResponse><m:ResponseMessages><m:UpdateItemResponseMessage ResponseClass="Success">' +
            '<m:ResponseCode>NoError</m:ResponseCode><m:Items><t:CalendarItem><t:ItemId Id="item-1" ChangeKey="' + $ChangeKey + '"/></t:CalendarItem>' +
            '</m:Items></m:UpdateItemResponseMessage></m:ResponseMessages></m:UpdateItemResponse></s:Body></s:Envelope>')
        Write-Output -InputObject $document -NoEnumerate
    }

    # The exception Invoke-ExOPEwsRequest throws for an EWS error; without a code it resembles a transport failure.
    function New-EwsFailure {
        param(
            [string]
            $Code
        )
        if ($Code) {
            $exception = New-Object InvalidOperationException("EWS [$Code]: The request was rejected.")
            $exception.Data['EwsResponseCode'] = $Code
        } else {
            $exception = New-Object Net.WebException('The underlying connection was closed.')
        }
        $exception
    }

    # Loads the in-memory HTTP endpoint from Data\FakeEwsWebRequest.cs for the EWS test host below .invalid.
    function Register-FakeHttp {
        if (-not ('ExOPTests.FakeEwsWebRequest' -as [type])) {
            Add-Type -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Data\FakeEwsWebRequest.cs') -IgnoreWarnings -WarningAction SilentlyContinue
        }
        $null = [Net.WebRequest]::RegisterPrefix('https://ews-test.contoso.invalid/', (New-Object -TypeName ExOPTests.FakeEwsWebRequestCreator))
    }
}

Describe 'Testing Rehoming.ps1' {
    BeforeAll {
        # Offline tests run as the mailbox owner; the delegate send-permission check has its own contexts.
        Mock Get-ExOPSendPermission { [PSCustomObject]@{ Mode = 'Owner'; Error = '' } }
    }
    Context 'Convert-ExOPWallClockZone preserves the local wall-clock time' {
        It '<From> to <To> at <Utc>' -ForEach $Script:wallClockCases {
            $actual = Convert-ExOPWallClockZone -Utc $Utc -From $From -To $To
            $actual | Should -BeExactly $Expected
            ((ConvertTo-ExOPInstant -Value $actual) - (ConvertTo-ExOPInstant -Value $Utc)).TotalMinutes | Should -Be $DeltaMinutes
        }

        It 'Returns the normalized instant when source and target zones are equal' {
            Convert-ExOPWallClockZone -Utc '2026-11-09T10:00:00-08:00' -From 'Pacific Standard Time' -To 'Pacific Standard Time' |
                Should -BeExactly '2026-11-09T18:00:00.0000000Z'
        }

        It 'Rejects the <Name> instead of guessing' -ForEach $Script:rejectedLocalTimeCases {
            { Convert-ExOPWallClockZone -Utc $Utc -From 'UTC' -To $To } | Should -Throw -ExpectedMessage '*invalid or ambiguous*'
        }
    }

    Context 'Recurrence blob bridge for pattern <Pattern>, writer version <Version>, exception flags <Flags>' -ForEach $Script:recurrenceCases {
        BeforeAll {
            $Script:snapshot = New-RecurrenceTestData -Pattern $Pattern -Version $Version -Flags $Flags
            $Script:before = [Convert]::FromBase64String($Script:snapshot.RecurrenceBase64)
            $Script:layout = Get-ExOPRecurrenceBlobLayout -Bytes $Script:before
            $Script:bridge = New-ExOPExceptionTimeBridge -Snapshot $Script:snapshot -From 'Pacific Standard Time' -To 'Mountain Standard Time'
            $Script:after = [Convert]::FromBase64String($Script:bridge)
            $Script:newLayout = Get-ExOPRecurrenceBlobLayout -Bytes $Script:after
        }

        It 'Returns identical bytes when the zone does not change' {
            New-ExOPExceptionTimeBridge -Snapshot $Script:snapshot -From 'Pacific Standard Time' -To 'Pacific Standard Time' |
                Should -BeExactly $Script:snapshot.RecurrenceBase64
        }

        It 'Moves each exception by 60 minutes and keeps its original slot' {
            $Script:layout.Exceptions | Should -HaveCount 2
            for ($index = 0; $index -lt $Script:layout.Exceptions.Count; $index++) {
                $old = $Script:layout.Exceptions[$index]
                $new = $Script:newLayout.Exceptions[$index]
                $new.Start | Should -Be ($old.Start + 60)
                $new.End | Should -Be ($old.End + 60)
                $new.Original | Should -Be $old.Original
            }
        }

        It 'Changes no bytes other than exception times and modified dates' {
            $allowed = New-Object 'System.Collections.Generic.HashSet[int]'
            for ($index = 0; $index -lt $Script:layout.Exceptions.Count; $index++) {
                $old = $Script:layout.Exceptions[$index]
                foreach ($offset in $old.Offset, $old.ExtendedOffset) {
                    if ($offset -ge 0) {
                        for ($byte = 0; $byte -lt 8; $byte++) { $null = $allowed.Add($offset + $byte) }
                    }
                }
                for ($byte = 0; $byte -lt 4; $byte++) { $null = $allowed.Add($Script:layout.ModifiedDateOffsets[$index] + $byte) }
            }
            $Script:after.Length | Should -Be $Script:before.Length
            $changed = @(for ($index = 0; $index -lt $Script:before.Length; $index++) {
                    if (-not $allowed.Contains($index) -and $Script:before[$index] -ne $Script:after[$index]) { $index }
                })
            $changed | Should -BeNullOrEmpty
        }

        It 'Returns the original bytes when bridged back' {
            $backSnapshot = [PSCustomObject]@{
                RecurrenceBase64 = $Script:bridge
                Modified         = @(
                    foreach ($entry in $Script:snapshot.Modified) {
                        [PSCustomObject]@{
                            OriginalStartUtc = Convert-ExOPWallClockZone -Utc $entry.OriginalStartUtc -From 'Pacific Standard Time' -To 'Mountain Standard Time'
                            Values           = $entry.Values
                        }
                    }
                )
            }
            New-ExOPExceptionTimeBridge -Snapshot $backSnapshot -From 'Mountain Standard Time' -To 'Pacific Standard Time' |
                Should -BeExactly $Script:snapshot.RecurrenceBase64
        }
    }

    Context 'Recurrence blob validation' {
        BeforeAll {
            $Script:validSnapshot = New-RecurrenceTestData -Pattern 0
            $Script:validBytes = [Convert]::FromBase64String($Script:validSnapshot.RecurrenceBase64)
            $Script:validLayout = Get-ExOPRecurrenceBlobLayout -Bytes $Script:validBytes
        }

        It 'Leaves a series without exceptions unchanged' {
            $empty = New-RecurrenceTestData -Pattern 0 -Empty
            New-ExOPExceptionTimeBridge -Snapshot $empty -From 'Pacific Standard Time' -To 'Mountain Standard Time' |
                Should -BeExactly $empty.RecurrenceBase64
        }

        It 'Rejects the blob truncated at every length' {
            $Script:validBytes.Length | Should -Be 354
            for ($length = 0; $length -lt $Script:validBytes.Length; $length++) {
                $truncated = New-Object byte[] $length
                [Array]::Copy($Script:validBytes, $truncated, $length)
                { Get-ExOPRecurrenceBlobLayout -Bytes $truncated } | Should -Throw -Because "a blob truncated to $length bytes is incomplete"
            }
        }

        It 'Rejects <Name>' -ForEach $Script:corruptionCases {
            $offset = switch ($Anchor) {
                'Start' { $Delta }
                'Exception' { $Script:validLayout.Exceptions[0].Offset + $Delta }
                'Extended' { $Script:validLayout.Exceptions[0].ExtendedOffset + $Delta }
            }
            $changed = [byte[]]$Script:validBytes.Clone()
            $changed[$offset] = [byte]$Value
            { Get-ExOPRecurrenceBlobLayout -Bytes $changed } | Should -Throw
        }

        It 'Rejects EWS exception times that disagree with the binary data' {
            $snapshot = New-RecurrenceTestData -Pattern 0
            $snapshot.Modified[0].Values.StartUtc = '2026-11-09T21:01:00Z'
            { New-ExOPExceptionTimeBridge -Snapshot $snapshot -From 'Pacific Standard Time' -To 'Mountain Standard Time' } |
                Should -Throw -ExpectedMessage '*disagree*'
        }
    }

    Context 'Recurrence blob data after ReservedBlock2' {
        BeforeAll {
            function Add-ZeroPadding {
                param(
                    [byte[]]
                    $Bytes,

                    [int]
                    $Count
                )
                $padded = New-Object byte[] ($Bytes.Length + $Count)
                [Array]::Copy($Bytes, $padded, $Bytes.Length)
                Write-Output -InputObject $padded -NoEnumerate
            }

            $Script:emptySeries = [Convert]::FromBase64String((New-RecurrenceTestData -Pattern 0 -Empty).RecurrenceBase64)
            $Script:exceptionSeries = New-RecurrenceTestData -Pattern 0
            $Script:exceptionBytes = [Convert]::FromBase64String($Script:exceptionSeries.RecurrenceBase64)
            $Script:exceptionLayout = Get-ExOPRecurrenceBlobLayout -Bytes $Script:exceptionBytes
        }

        It 'Accepts <_> zero bytes after a series without exceptions' -ForEach @(12, 92, 96) {
            $layout = Get-ExOPRecurrenceBlobLayout -Bytes (Add-ZeroPadding -Bytes $Script:emptySeries -Count $_)
            @($layout.Exceptions) | Should -HaveCount 0
            @($layout.ModifiedDateOffsets) | Should -HaveCount 0
            $layout.Pattern | Should -Be 0
        }

        It 'Accepts zero padding after a series with exceptions and keeps every offset' {
            $layout = Get-ExOPRecurrenceBlobLayout -Bytes (Add-ZeroPadding -Bytes $Script:exceptionBytes -Count 12)
            $layout.Exceptions | Should -HaveCount 2
            for ($index = 0; $index -lt 2; $index++) {
                foreach ($name in 'Offset', 'ExtendedOffset', 'Start', 'End', 'Original', 'Flags') {
                    $layout.Exceptions[$index].$name | Should -Be $Script:exceptionLayout.Exceptions[$index].$name -Because "exception $index $name"
                }
            }
            $layout.ModifiedDateOffsets -join ',' | Should -BeExactly ($Script:exceptionLayout.ModifiedDateOffsets -join ',')
        }

        It 'Preserves the padding when exception times are bridged and restored' {
            $padded = Add-ZeroPadding -Bytes $Script:exceptionBytes -Count 12
            $paddedSeries = [PSCustomObject]@{ RecurrenceBase64 = [Convert]::ToBase64String($padded); Modified = $Script:exceptionSeries.Modified }
            $bridge = [Convert]::FromBase64String((New-ExOPExceptionTimeBridge -Snapshot $paddedSeries -From 'Pacific Standard Time' -To 'Mountain Standard Time'))
            $bridge.Length | Should -Be $padded.Length
            @($bridge[($Script:exceptionBytes.Length)..($bridge.Length - 1)] | Where-Object { $_ -ne 0 }) | Should -HaveCount 0
            (Get-ExOPRecurrenceBlobLayout -Bytes $bridge).Exceptions[0].Start | Should -Be ($Script:exceptionLayout.Exceptions[0].Start + 60)
            $backSeries = [PSCustomObject]@{
                RecurrenceBase64 = [Convert]::ToBase64String($bridge)
                Modified         = @(
                    foreach ($entry in $Script:exceptionSeries.Modified) {
                        [PSCustomObject]@{
                            OriginalStartUtc = Convert-ExOPWallClockZone -Utc $entry.OriginalStartUtc -From 'Pacific Standard Time' -To 'Mountain Standard Time'
                            Values           = $entry.Values
                        }
                    }
                )
            }
            New-ExOPExceptionTimeBridge -Snapshot $backSeries -From 'Mountain Standard Time' -To 'Pacific Standard Time' |
                Should -BeExactly $paddedSeries.RecurrenceBase64
        }

        It 'Ignores a non-zero byte at position <_> after ReservedBlock2' -ForEach @(0, 5, 11) {
            $padded = Add-ZeroPadding -Bytes $Script:emptySeries -Count 12
            $padded[$Script:emptySeries.Length + $_] = 1
            $layout = Get-ExOPRecurrenceBlobLayout -Bytes $padded
            @($layout.Exceptions) | Should -HaveCount 0
            @($layout.ModifiedDateOffsets) | Should -HaveCount 0
            $layout.Pattern | Should -Be 0
        }

        It 'Ignores stale exception data after a series with exceptions and keeps every offset' {
            # Outlook can leave remnants of removed exceptions after ReservedBlock2 (bug 8138072).
            $stale = Add-ZeroPadding -Bytes $Script:exceptionBytes -Count 98
            [Array]::Copy($Script:exceptionBytes, $Script:exceptionLayout.Exceptions[0].Offset, $stale, $Script:exceptionBytes.Length, 98)
            $layout = Get-ExOPRecurrenceBlobLayout -Bytes $stale
            $layout.Exceptions | Should -HaveCount 2
            for ($index = 0; $index -lt 2; $index++) {
                foreach ($name in 'Offset', 'ExtendedOffset', 'Start', 'End', 'Original', 'Flags') {
                    $layout.Exceptions[$index].$name | Should -Be $Script:exceptionLayout.Exceptions[$index].$name -Because "exception $index $name"
                }
            }
            $layout.ModifiedDateOffsets -join ',' | Should -BeExactly ($Script:exceptionLayout.ModifiedDateOffsets -join ',')
        }

        It 'Preserves stale data after ReservedBlock2 when exception times are bridged and restored' {
            $stale = Add-ZeroPadding -Bytes $Script:exceptionBytes -Count 98
            [Array]::Copy($Script:exceptionBytes, $Script:exceptionLayout.Exceptions[0].Offset, $stale, $Script:exceptionBytes.Length, 98)
            $staleSeries = [PSCustomObject]@{ RecurrenceBase64 = [Convert]::ToBase64String($stale); Modified = $Script:exceptionSeries.Modified }
            $bridge = [Convert]::FromBase64String((New-ExOPExceptionTimeBridge -Snapshot $staleSeries -From 'Pacific Standard Time' -To 'Mountain Standard Time'))
            $bridge.Length | Should -Be $stale.Length
            [Convert]::ToBase64String($bridge[($Script:exceptionBytes.Length)..($bridge.Length - 1)]) |
                Should -BeExactly ([Convert]::ToBase64String($stale[($Script:exceptionBytes.Length)..($stale.Length - 1)]))
            (Get-ExOPRecurrenceBlobLayout -Bytes $bridge).Exceptions[0].Start | Should -Be ($Script:exceptionLayout.Exceptions[0].Start + 60)
            $backSeries = [PSCustomObject]@{
                RecurrenceBase64 = [Convert]::ToBase64String($bridge)
                Modified         = @(
                    foreach ($entry in $Script:exceptionSeries.Modified) {
                        [PSCustomObject]@{
                            OriginalStartUtc = Convert-ExOPWallClockZone -Utc $entry.OriginalStartUtc -From 'Pacific Standard Time' -To 'Mountain Standard Time'
                            Values           = $entry.Values
                        }
                    }
                )
            }
            New-ExOPExceptionTimeBridge -Snapshot $backSeries -From 'Mountain Standard Time' -To 'Pacific Standard Time' |
                Should -BeExactly $staleSeries.RecurrenceBase64
        }

        It 'Rejects a non-zero ReservedBlock2 size <Name>' -ForEach @(
            @{ Name = 'without block data'; Padding = 0 }
            @{ Name = 'followed by zero bytes'; Padding = 4 }
        ) {
            $bytes = Add-ZeroPadding -Bytes $Script:emptySeries -Count $Padding
            [Array]::Copy([BitConverter]::GetBytes([uint32]4), 0, $bytes, $Script:emptySeries.Length - 4, 4)
            { Get-ExOPRecurrenceBlobLayout -Bytes $bytes } | Should -Throw -ExpectedMessage 'Unsupported recurrence ReservedBlock2.'
        }
    }

    Context 'Get-ExOPAttachmentSnapshot' {
        BeforeAll {
            # 'hello world' in ASCII; its SHA256 is a published test vector.
            $Script:attachmentContent = 'aGVsbG8gd29ybGQ='
            $Script:session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            Mock Invoke-ExOPEwsRequest {
                $response = New-Object Xml.XmlDocument
                $response.LoadXml('<m:GetAttachmentResponse xmlns:m="' + $script:MessagesNamespace + '" xmlns:t="' + $script:TypesNamespace + '">' +
                    '<m:ResponseMessages><m:GetAttachmentResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode>' +
                    '<m:Attachments><t:FileAttachment><t:AttachmentId Id="attachment-small"/><t:Name>agenda.txt</t:Name>' +
                    '<t:Content>' + $Script:attachmentContent + '</t:Content></t:FileAttachment></m:Attachments>' +
                    '</m:GetAttachmentResponseMessage></m:ResponseMessages></m:GetAttachmentResponse>')
                Write-Output -InputObject $response -NoEnumerate
            }
            $largeSize = $script:MaxAttachmentHashBytes + 1
            $Script:attachmentItem = (New-CalendarItemXml -InnerXml (
                    '<t:ItemId Id="item-1" ChangeKey="CK-1"/><t:Attachments>' +
                    '<t:FileAttachment><t:AttachmentId Id="attachment-small"/><t:Name>agenda.txt</t:Name><t:ContentType>text/plain</t:ContentType>' +
                    '<t:ContentId>agenda</t:ContentId><t:Size>11</t:Size><t:IsInline>false</t:IsInline></t:FileAttachment>' +
                    '<t:FileAttachment><t:AttachmentId Id="attachment-large"/><t:Name>recording.mp4</t:Name><t:ContentType>video/mp4</t:ContentType>' +
                    '<t:Size>' + $largeSize + '</t:Size><t:IsInline>false</t:IsInline></t:FileAttachment>' +
                    '<t:ItemAttachment><t:AttachmentId Id="attachment-item"/><t:Name>Forwarded meeting</t:Name><t:Size>2048</t:Size>' +
                    '<t:IsInline>false</t:IsInline></t:ItemAttachment>' +
                    '<t:ReferenceAttachment><t:AttachmentId Id="attachment-reference"/><t:Name>Plan.docx</t:Name><t:Size>0</t:Size>' +
                    '<t:IsInline>false</t:IsInline></t:ReferenceAttachment></t:Attachments>')).DocumentElement
            $Script:descriptors = @(Get-ExOPAttachmentSnapshot -Session $Script:session -Mailbox 'user@contoso.com' -Item $Script:attachmentItem)
        }

        It 'Returns one descriptor per attachment' {
            $Script:descriptors | Should -HaveCount 4
            ($Script:descriptors | ForEach-Object { $_.Type }) -join ',' | Should -BeExactly 'FileAttachment,FileAttachment,ItemAttachment,ReferenceAttachment'
        }

        It 'Hashes a file attachment within the size limit' {
            $Script:descriptors[0].Sha256 | Should -BeExactly 'B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9'
            $Script:descriptors[0].Size | Should -Be 11
            $Script:descriptors[0].Name | Should -BeExactly 'agenda.txt'
            Should -Invoke Invoke-ExOPEwsRequest -Times 1 -Exactly -Scope Context -ParameterFilter { $Body -like '*attachment-small*' -and $ReadOnly }
        }

        It 'Never stores attachment content in a descriptor' {
            foreach ($descriptor in $Script:descriptors) {
                $descriptor.PSObject.Properties.Name | Should -Not -Contain 'Content'
            }
        }

        It 'Does not download a file attachment above the size limit' {
            $Script:descriptors[1].Sha256 | Should -BeExactly ''
            $Script:descriptors[1].Size | Should -Be ($script:MaxAttachmentHashBytes + 1)
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope Context -ParameterFilter { $Body -like '*attachment-large*' }
        }

        It 'Records <_> metadata only' -ForEach @('ItemAttachment', 'ReferenceAttachment') {
            $descriptor = @($Script:descriptors | Where-Object Type -EQ $_)
            $descriptor | Should -HaveCount 1
            $descriptor[0].Sha256 | Should -BeExactly ''
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope Context -ParameterFilter { $Body -like '*attachment-item*' -or $Body -like '*attachment-reference*' }
        }

        It 'Requests attachment content exactly once' {
            Should -Invoke Invoke-ExOPEwsRequest -Times 1 -Exactly -Scope Context
        }

        It 'Accepts unchanged attachments' {
            { Assert-ExOPAttachmentSnapshot -Session $Script:session -Mailbox 'user@contoso.com' -Item $Script:attachmentItem -Expected $Script:descriptors } |
                Should -Not -Throw
        }

        It 'Detects a changed file hash' {
            $expected = @($Script:descriptors | ForEach-Object { $_.PSObject.Copy() })
            $expected[0].Sha256 = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
            { Assert-ExOPAttachmentSnapshot -Session $Script:session -Mailbox 'user@contoso.com' -Item $Script:attachmentItem -Expected $expected } |
                Should -Throw -ExpectedMessage '*not preserved*'
        }

        It 'Detects a changed attachment size' {
            $expected = @($Script:descriptors | ForEach-Object { $_.PSObject.Copy() })
            $expected[2].Size = 4096
            { Assert-ExOPAttachmentSnapshot -Session $Script:session -Mailbox 'user@contoso.com' -Item $Script:attachmentItem -Expected $expected } |
                Should -Throw -ExpectedMessage '*not preserved*'
        }
    }

    Context 'Get-ExOPRehomeValues' {
        BeforeAll {
            function New-RehomeItem {
                param(
                    [string]
                    $Start,

                    [string]
                    $End,

                    [string]
                    $StartZone,

                    [string]
                    $EndZone
                )
                (New-CalendarItemXml -InnerXml ('<t:Start>' + $Start + '</t:Start><t:End>' + $End + '</t:End>' +
                    '<t:StartTimeZone Id="' + $StartZone + '"/><t:EndTimeZone Id="' + $EndZone + '"/>')).DocumentElement
            }
        }

        # Hand-computed: on 2026-11-09 Pacific is UTC-08:00, Mountain UTC-07:00 and Central UTC-06:00.
        It 'Moves a normal item and keeps its wall-clock times' {
            $item = New-RehomeItem -Start '2026-11-09T18:00:00Z' -End '2026-11-09T19:00:00Z' -StartZone 'Pacific Standard Time' -EndZone 'Pacific Standard Time'
            $values = Get-ExOPRehomeValues -Item $item -From 'Pacific Standard Time' -To 'Mountain Standard Time'
            $values.NewStartUtc | Should -BeExactly '2026-11-09T17:00:00.0000000Z'
            $values.NewEndUtc | Should -BeExactly '2026-11-09T18:00:00.0000000Z'
            $values.NewStartZone | Should -BeExactly 'Mountain Standard Time'
        }

        It 'Accepts a zero-duration item that stays zero-duration' {
            $item = New-RehomeItem -Start '2026-11-09T18:00:00Z' -End '2026-11-09T18:00:00Z' -StartZone 'Pacific Standard Time' -EndZone 'Pacific Standard Time'
            $values = Get-ExOPRehomeValues -Item $item -From 'Pacific Standard Time' -To 'Mountain Standard Time'
            $values.NewStartUtc | Should -BeExactly '2026-11-09T17:00:00.0000000Z'
            $values.NewEndUtc | Should -BeExactly $values.NewStartUtc
            $values.StartUtc | Should -BeExactly $values.EndUtc
        }

        It 'Rejects a zero-duration item whose end would precede its start' {
            $item = New-RehomeItem -Start '2026-11-09T18:00:00Z' -End '2026-11-09T18:00:00Z' -StartZone 'UTC' -EndZone 'Pacific Standard Time'
            { Get-ExOPRehomeValues -Item $item -From 'Pacific Standard Time' -To 'Mountain Standard Time' } |
                Should -Throw -ExpectedMessage 'Rehoming would make the end time less than or equal to the start time.'
        }

        It 'Rejects an item whose end would precede its start' {
            $item = New-RehomeItem -Start '2026-11-09T17:00:00Z' -End '2026-11-09T18:30:00Z' -StartZone 'UTC' -EndZone 'Pacific Standard Time'
            { Get-ExOPRehomeValues -Item $item -From 'Pacific Standard Time' -To 'Central Standard Time' } |
                Should -Throw -ExpectedMessage 'Rehoming would make the end time less than or equal to the start time.'
        }

        It 'Rejects an item with a duration that would collapse to zero' {
            $item = New-RehomeItem -Start '2026-11-09T16:30:00Z' -End '2026-11-09T18:30:00Z' -StartZone 'UTC' -EndZone 'Pacific Standard Time'
            { Get-ExOPRehomeValues -Item $item -From 'Pacific Standard Time' -To 'Central Standard Time' } |
                Should -Throw -ExpectedMessage 'Rehoming would make the end time less than or equal to the start time.'
        }
    }

    Context 'Get-ExOPExceptionUpdateOrder' {
        BeforeAll {
            function New-ExceptionEntry {
                param(
                    [string]
                    $Slot,

                    [int]
                    $DeltaMinutes
                )
                $start = ConvertTo-ExOPInstant -Value $Slot
                [PSCustomObject]@{
                    OriginalStartUtc = $Slot
                    Values           = [PSCustomObject]@{
                        StartUtc    = Format-ExOPInstant -Value $start
                        NewStartUtc = Format-ExOPInstant -Value $start.AddMinutes($DeltaMinutes)
                    }
                }
            }

            # Three consecutive daily exceptions at 18:00 UTC that move 11 hours later (to 05:00 UTC the next day).
            # The input order is deliberately not sorted.
            $Script:laterEntries = @(
                (New-ExceptionEntry -Slot '2026-11-10T18:00:00Z' -DeltaMinutes 660),
                (New-ExceptionEntry -Slot '2026-11-09T18:00:00Z' -DeltaMinutes 660),
                (New-ExceptionEntry -Slot '2026-11-11T18:00:00Z' -DeltaMinutes 660)
            )

            # Moves exceptions one at a time in the given order and returns, per step, whether two exceptions
            # share a local date in a fixed UTC+00:00 target zone (where the local date equals the UTC date).
            function Get-MoveCollision {
                param(
                    [object[]]
                    $Order
                )
                $positions = @{}
                foreach ($entry in $Order) { $positions[$entry.OriginalStartUtc] = ConvertTo-ExOPInstant -Value $entry.Values.StartUtc }
                foreach ($entry in $Order) {
                    $positions[$entry.OriginalStartUtc] = ConvertTo-ExOPInstant -Value $entry.Values.NewStartUtc
                    $dates = @($positions.Values | ForEach-Object { $_.UtcDateTime.Date })
                    @($dates | Sort-Object -Unique).Count -ne $dates.Count
                }
            }
        }

        It 'Returns exceptions moving later in descending slot order' {
            $order = @(Get-ExOPExceptionUpdateOrder -Modified $Script:laterEntries)
            ($order | ForEach-Object { $_.OriginalStartUtc }) -join ',' |
                Should -BeExactly '2026-11-11T18:00:00Z,2026-11-10T18:00:00Z,2026-11-09T18:00:00Z'
        }

        It 'Returns the same exceptions in ascending slot order when restoring the original' {
            $order = @(Get-ExOPExceptionUpdateOrder -Modified $Script:laterEntries -Original)
            ($order | ForEach-Object { $_.OriginalStartUtc }) -join ',' |
                Should -BeExactly '2026-11-09T18:00:00Z,2026-11-10T18:00:00Z,2026-11-11T18:00:00Z'
        }

        It 'Returns exceptions moving earlier in ascending slot order' {
            $earlierEntries = @(
                (New-ExceptionEntry -Slot '2026-11-11T05:00:00Z' -DeltaMinutes -660),
                (New-ExceptionEntry -Slot '2026-11-09T05:00:00Z' -DeltaMinutes -660),
                (New-ExceptionEntry -Slot '2026-11-10T05:00:00Z' -DeltaMinutes -660)
            )
            $order = @(Get-ExOPExceptionUpdateOrder -Modified $earlierEntries)
            ($order | ForEach-Object { $_.OriginalStartUtc }) -join ',' |
                Should -BeExactly '2026-11-09T05:00:00Z,2026-11-10T05:00:00Z,2026-11-11T05:00:00Z'
        }

        It 'Returns non-positive moves ascending, then positive moves descending' {
            $mixedEntries = @(
                (New-ExceptionEntry -Slot '2026-11-09T18:00:00Z' -DeltaMinutes 120),
                (New-ExceptionEntry -Slot '2026-11-10T18:00:00Z' -DeltaMinutes 0),
                (New-ExceptionEntry -Slot '2026-11-11T18:00:00Z' -DeltaMinutes -180),
                (New-ExceptionEntry -Slot '2026-11-12T18:00:00Z' -DeltaMinutes 300),
                (New-ExceptionEntry -Slot '2026-11-08T18:00:00Z' -DeltaMinutes -60)
            )
            $order = @(Get-ExOPExceptionUpdateOrder -Modified $mixedEntries)
            $order | Should -HaveCount 5
            ($order | ForEach-Object { $_.OriginalStartUtc }) -join ',' |
                Should -BeExactly '2026-11-08T18:00:00Z,2026-11-10T18:00:00Z,2026-11-11T18:00:00Z,2026-11-12T18:00:00Z,2026-11-09T18:00:00Z'
        }

        It 'Returns nothing for a series without exceptions' {
            @(Get-ExOPExceptionUpdateOrder -Modified @()) | Should -HaveCount 0
        }

        It 'Never puts two exceptions on the same date when moves follow the returned order' {
            $order = @(Get-ExOPExceptionUpdateOrder -Modified $Script:laterEntries)
            $collisions = @(Get-MoveCollision -Order $order)
            $collisions | Should -HaveCount 3
            $collisions | Should -Not -Contain $true
        }

        It 'Would put two exceptions on the same date when moves follow ascending order' {
            $ascending = @($Script:laterEntries | Sort-Object -Property { (ConvertTo-ExOPInstant -Value $_.OriginalStartUtc).UtcTicks })
            $collisions = @(Get-MoveCollision -Order $ascending)
            $collisions | Should -HaveCount 3
            $collisions[0] | Should -BeTrue
        }
    }

    Context 'Room and reminder handling' {
        BeforeAll {
            $Script:reminderItem = New-CalendarItemXml -InnerXml (
                '<t:ReminderIsSet>true</t:ReminderIsSet><t:Start>2026-11-09T02:00:00Z</t:Start>' +
                '<t:ExtendedProperty><t:ExtendedFieldURI DistinguishedPropertySetId="Common" PropertyId="34050" PropertyType="SystemTime"/>' +
                '<t:Value>2026-11-09T02:00:00Z</t:Value></t:ExtendedProperty>' +
                '<t:ExtendedProperty><t:ExtendedFieldURI DistinguishedPropertySetId="Common" PropertyId="34144" PropertyType="SystemTime"/>' +
                '<t:Value>2026-11-09T01:15:00Z</t:Value></t:ExtendedProperty>')
            $Script:movedReminderItem = $Script:reminderItem.CloneNode($true)
            $namespaces = Get-ExOPNamespaceManager -Node $Script:movedReminderItem
            $Script:movedReminderItem.SelectSingleNode("//t:ExtendedProperty[t:ExtendedFieldURI/@PropertyId='34050']/t:Value", $namespaces).InnerText = '2026-11-09T13:00:00Z'
            $Script:movedReminderItem.SelectSingleNode("//t:ExtendedProperty[t:ExtendedFieldURI/@PropertyId='34144']/t:Value", $namespaces).InnerText = '2026-11-09T12:15:00Z'
        }

        It 'Reports room presence, name and address' {
            $item = New-CalendarItemXml -InnerXml (
                '<t:Resources><t:Attendee><t:Mailbox><t:Name>Test Room</t:Name><t:EmailAddress>room@contoso.com</t:EmailAddress>' +
                '</t:Mailbox></t:Attendee></t:Resources>')
            $room = Get-ExOPRoomInfo -Item $item.DocumentElement
            $room.HasRoom | Should -BeTrue
            $room.RoomNames | Should -BeExactly 'Test Room'
            $room.RoomSmtpAddresses | Should -BeExactly 'room@contoso.com'
        }

        It 'Moves the reminder signal with the start time' {
            $update = @(Get-ExOPReminderTimeUpdate -OriginalItem $Script:reminderItem.DocumentElement -NewStartUtc '2026-11-09T13:00:00Z')
            ($update -join '') | Should -BeLike '*2026-11-09T12:15:00*'
        }

        It 'Verifies a reminder that followed the migration' {
            { Assert-ExOPReminderTime -OriginalItem $Script:reminderItem.DocumentElement -CurrentItem $Script:movedReminderItem.DocumentElement -NewStartUtc '2026-11-09T13:00:00Z' } |
                Should -Not -Throw
        }

        It 'Rejects a stale reminder' {
            { Assert-ExOPReminderTime -OriginalItem $Script:reminderItem.DocumentElement -CurrentItem $Script:reminderItem.DocumentElement -NewStartUtc '2026-11-09T13:00:00Z' } |
                Should -Throw -ExpectedMessage '*reminder raw*'
        }

        It 'Keeps the inherited reminder anchor of an exception' {
            $exception = $Script:reminderItem.CloneNode($true)
            $type = $exception.CreateElement('t', 'CalendarItemType', $script:TypesNamespace)
            $type.InnerText = 'Exception'
            $null = $exception.DocumentElement.AppendChild($type)
            $updates = @(Get-ExOPReminderTimeUpdate -OriginalItem $exception.DocumentElement -NewStartUtc '2026-11-09T13:00:00Z')
            $updates | Should -HaveCount 1
            $updates[0] | Should -BeLike '*PropertyId="34144"*'
            $updates[0] | Should -Not -BeLike '*PropertyId="34050"*'
        }
    }

    Context 'Write safety' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
        }

        It 'Classifies a concurrent change explicitly and sends nothing' {
            $item = New-CalendarItemXml -InnerXml '<t:ItemId Id="test" ChangeKey="external-change"/>'
            $session = [PSCustomObject]@{ ActiveOperation = [PSCustomObject]@{ LastChangeKey = 'last-acknowledged' } }
            $failure = { Set-ExOPCalendarFields -Session $session -Mailbox 'first@contoso.com' -Item $item.DocumentElement -Updates @('not-sent') } |
                Should -Throw -PassThru
            $failure.Exception.Data['ConcurrentChange'] | Should -BeTrue
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope It
        }

        It 'Requires an explicit destination zone for migration' {
            $parameter = (Get-Command -Name Invoke-ExOPCalendarEventMigration).Parameters['ToWindowsTimeZoneId']
            @($parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }) | Should -HaveCount 1
        }
    }

    Context 'Test-ExOPNotificationRequired' {
        It 'Returns <Expected> for <Name>' -ForEach @(
            @{ Name = 'an appointment with attendees'; Meeting = 'false'; Attendees = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>a@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees>'; Expected = $false }
            @{ Name = 'an item without IsMeeting'; Meeting = ''; Attendees = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>a@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees>'; Expected = $false }
            @{ Name = 'a meeting without attendees'; Meeting = 'true'; Attendees = ''; Expected = $false }
            @{ Name = 'a meeting with empty attendee lists'; Meeting = 'true'; Attendees = '<t:RequiredAttendees/><t:OptionalAttendees/><t:Resources/>'; Expected = $false }
            @{ Name = 'a meeting with a required attendee'; Meeting = 'true'; Attendees = '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>a@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees>'; Expected = $true }
            @{ Name = 'a meeting with an optional attendee'; Meeting = 'true'; Attendees = '<t:OptionalAttendees><t:Attendee><t:Mailbox><t:EmailAddress>b@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:OptionalAttendees>'; Expected = $true }
            @{ Name = 'a meeting with only a room'; Meeting = 'true'; Attendees = '<t:Resources><t:Attendee><t:Mailbox><t:EmailAddress>room@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:Resources>'; Expected = $true }
        ) {
            $meetingXml = if ($Meeting) { '<t:IsMeeting>' + $Meeting + '</t:IsMeeting>' } else { '' }
            $item = (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="CK-1"/>' + $meetingXml + $Attendees)).DocumentElement
            $actual = Test-ExOPNotificationRequired -Item $item
            $actual | Should -BeOfType [bool]
            $actual | Should -Be $Expected
        }
    }

    Context 'Send-ExOPSeriesUpdate' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { New-UpdateItemResponse -ChangeKey 'CK-2' }
            $Script:plainSession = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
        }

        It 'Sends nothing for a meeting without attendees' {
            $item = (New-CalendarItemXml -InnerXml '<t:ItemId Id="item-1" ChangeKey="CK-1"/><t:Subject>Sync</t:Subject><t:IsMeeting>true</t:IsMeeting>').DocumentElement
            Send-ExOPSeriesUpdate -Session $Script:plainSession -Mailbox 'user@contoso.com' -Item $item
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope It
        }

        It 'Sends one update with the unchanged subject to attendees' {
            $item = (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="CK-1"/><t:Subject>Sync &amp; review</t:Subject><t:IsMeeting>true</t:IsMeeting>' +
                    '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>a@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees>')).DocumentElement
            Send-ExOPSeriesUpdate -Session $Script:plainSession -Mailbox 'user@contoso.com' -Item $item
            Should -Invoke Invoke-ExOPEwsRequest -Times 1 -Exactly -Scope It -ParameterFilter {
                $Body -like '*SendMeetingInvitationsOrCancellations="SendToAllAndSaveCopy"*' -and $Body -like '*<t:Subject>Sync &amp; review</t:Subject>*'
            }
        }
    }

    Context 'Set-ExOPCalendarFields send failure classification' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest {
                $Script:lastFailure = New-EwsFailure -Code $Script:failureCode
                throw $Script:lastFailure
            }
            $Script:writeItem = (New-CalendarItemXml -InnerXml '<t:ItemId Id="item-1" ChangeKey="CK-1"/>').DocumentElement

            function New-WriteSession {
                param(
                    $Run
                )
                $operation = [PSCustomObject]@{
                    Run = $Run; OperationId = 'operation-1'; Phase = 'Notification'; LastChangeKey = 'CK-1'; AcknowledgedWrites = 0
                    WriteAttempted = $false; LastWriteUnknown = $false; NotificationStarted = $false
                }
                [PSCustomObject]@{ ActiveOperation = $operation; LastFrontEndServer = ''; LastBackEndServer = '' }
            }
        }

        It 'Marks <_> as a definitive send rejection' -ForEach @('ErrorSendAsDenied', 'ErrorInvalidRecipients') {
            $Script:failureCode = $_
            $session = New-WriteSession
            $failure = { Set-ExOPCalendarFields -Session $session -Mailbox 'user@contoso.com' -Item $Script:writeItem -Updates @('update') -Send } |
                Should -Throw -PassThru
            $failure.Exception.Data['EwsResponseCode'] | Should -BeExactly $_
            $session.ActiveOperation.NotificationStarted | Should -BeFalse
            $session.ActiveOperation.NotificationRejected | Should -BeExactly $_
            $session.ActiveOperation.WriteAttempted | Should -BeTrue
            $session.ActiveOperation.LastWriteUnknown | Should -BeFalse
        }

        It 'Keeps a possible notification for <Name>' -ForEach @(
            @{ Name = 'another EWS error'; Code = 'ErrorInternalServerError'; Unknown = $false }
            @{ Name = 'a transport failure'; Code = ''; Unknown = $true }
        ) {
            $Script:failureCode = $Code
            $session = New-WriteSession
            { Set-ExOPCalendarFields -Session $session -Mailbox 'user@contoso.com' -Item $Script:writeItem -Updates @('update') -Send } | Should -Throw
            $session.ActiveOperation.NotificationStarted | Should -BeTrue
            $session.ActiveOperation.PSObject.Properties['NotificationRejected'] | Should -BeNullOrEmpty
            $session.ActiveOperation.LastWriteUnknown | Should -Be $Unknown
        }

        It 'Journals a definitive rejection and rethrows the same error' {
            $Script:failureCode = 'ErrorSendAsDenied'
            $run = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath 'rejection-journal') -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $true
            $session = New-WriteSession -Run $run
            $failure = { Set-ExOPCalendarFields -Session $session -Mailbox 'user@contoso.com' -Item $Script:writeItem -Updates @('update') -Send } |
                Should -Throw -PassThru
            [object]::ReferenceEquals($failure.Exception, $Script:lastFailure) | Should -BeTrue
            $journal = @(Get-Content -LiteralPath (Join-Path -Path $run.Mailboxes['user@contoso.com'].Directory -ChildPath 'details.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
            ($journal | ForEach-Object { $_.Event }) -join ',' | Should -BeExactly 'WriteIntent,NotificationRejected'
            $journal[1].OperationId | Should -BeExactly 'operation-1'
            $journal[1].Phase | Should -BeExactly 'Notification'
            $journal[1].Data.ItemId | Should -BeExactly 'item-1'
            $journal[1].Data.Code | Should -BeExactly 'ErrorSendAsDenied'
            (Get-ExOPJournalWriteState -Events $journal).NotificationRejected | Should -BeTrue
        }

        It 'Journals no rejection for <_>' -ForEach @('ErrorInternalServerError', '') {
            $Script:failureCode = $_
            $run = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath "other-journal-$_") -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $true
            $session = New-WriteSession -Run $run
            { Set-ExOPCalendarFields -Session $session -Mailbox 'user@contoso.com' -Item $Script:writeItem -Updates @('update') -Send } | Should -Throw
            $journal = @(Get-Content -LiteralPath (Join-Path -Path $run.Mailboxes['user@contoso.com'].Directory -ChildPath 'details.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
            ($journal | ForEach-Object { $_.Event }) -join ',' | Should -BeExactly 'WriteIntent'
            (Get-ExOPJournalWriteState -Events $journal).NotificationAttempted | Should -BeTrue
        }

        It 'Does not mark a rejected write that sends nothing' {
            $Script:failureCode = 'ErrorSendAsDenied'
            $session = New-WriteSession
            { Set-ExOPCalendarFields -Session $session -Mailbox 'user@contoso.com' -Item $Script:writeItem -Updates @('update') } | Should -Throw
            $session.ActiveOperation.NotificationStarted | Should -BeFalse
            $session.ActiveOperation.PSObject.Properties['NotificationRejected'] | Should -BeNullOrEmpty
        }
    }

    Context 'Assert-ExOPRehomeResult endpoint verification' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            Mock Get-ExOPCalendarItem {
                Write-Output -InputObject (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="CK-1"/><t:Start>2026-11-09T18:00:00Z</t:Start>' +
                        '<t:End>2026-11-09T19:00:00Z</t:End><t:StartTimeZone Id="Pacific Standard Time"/><t:EndTimeZone Id="Pacific Standard Time"/>')).DocumentElement -NoEnumerate
            }
            $Script:endpointValues = [PSCustomObject]@{
                StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; NewStartZone = 'Mountain Standard Time'; NewEndZone = 'Mountain Standard Time'
                StartUtc = '2026-11-09T18:00:00.0000000Z'; EndUtc = '2026-11-09T19:00:00.0000000Z'
                NewStartUtc = '2026-11-09T17:00:00.0000000Z'; NewEndUtc = '2026-11-09T18:00:00.0000000Z'
            }
        }

        It 'Accepts the original state when restoring' {
            $item = Assert-ExOPRehomeResult -Session $null -Mailbox 'user@contoso.com' -ItemId 'item-1' -Values $Script:endpointValues -Snapshot $null -Original
            $item.LocalName | Should -BeExactly 'CalendarItem'
        }

        It 'Reports expected and found endpoints when verification fails' {
            $failure = { Assert-ExOPRehomeResult -Session $null -Mailbox 'user@contoso.com' -ItemId 'item-1' -Values $Script:endpointValues -Snapshot $null } |
                Should -Throw -PassThru
            $failure.Exception.Message | Should -BeExactly ('Read-back verification failed for endpoint times/timezones. Expected 2026-11-09T17:00:00.0000000Z [Mountain Standard Time] - ' +
                '2026-11-09T18:00:00.0000000Z [Mountain Standard Time], found 2026-11-09T18:00:00Z [Pacific Standard Time] - 2026-11-09T19:00:00Z [Pacific Standard Time].')
        }
    }

    Context 'Rerun of a completed migration whose receipt <Name>' -ForEach @(
        @{ Name = 'records a 0 MB attachment hash limit'; Limit = 0; Status = 'AlreadyMigrated'; AttachmentReads = 0 }
        @{ Name = 'was written by an earlier version without the limit'; Limit = -1; Status = 'Failed'; AttachmentReads = 1 }
    ) {
        BeforeAll {
            $Script:receiptLimit = $Limit
            function New-CompletedItem {
                param([string]$ReceiptJson)
                $receiptXml = if ($ReceiptJson) {
                    '<t:ExtendedProperty>' + $script:MigrationReceiptFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $ReceiptJson) + '</t:Value></t:ExtendedProperty>'
                } else { '' }
                (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="CK-done"/><t:ParentFolderId Id="calendar-folder"/>' +
                    '<t:Subject>Weekly sync</t:Subject><t:UID>calendar-uid-1</t:UID><t:CalendarItemType>Single</t:CalendarItemType>' +
                    '<t:IsOrganizer>true</t:IsOrganizer><t:Start>2026-11-09T17:00:00Z</t:Start><t:End>2026-11-09T18:00:00Z</t:End>' +
                    '<t:Attachments><t:FileAttachment><t:AttachmentId Id="attachment-1"/><t:Name>notes.txt</t:Name><t:ContentType>text/plain</t:ContentType>' +
                    '<t:Size>100</t:Size><t:IsInline>false</t:IsInline></t:FileAttachment></t:Attachments>' +
                    '<t:StartTimeZone Id="Mountain Standard Time"/><t:EndTimeZone Id="Mountain Standard Time"/>' + $receiptXml)).DocumentElement
            }
            Mock Get-ExOPDefaultCalendarId { 'calendar-folder' }
            Mock Get-ExOPTimeZoneProperties { [PSCustomObject]@{ ChangeKey = 'CK-done'; Properties = @(); HasIanaNames = $false } }
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            $row = [PSCustomObject]@{
                SchemaVersion = '1'; Mailbox = 'user@contoso.com'; ItemId = 'item-1'; ChangeKey = 'CK-0'; RecordType = 'Single'
                FromWindowsTimeZoneId = 'Pacific Standard Time'; StartTimeZoneId = 'Pacific Standard Time'; EndTimeZoneId = 'Pacific Standard Time'
                StartUtc = '2026-11-09T18:00:00Z'; EndUtc = '2026-11-09T19:00:00Z'
            }
            $inputHash = Get-ExOPCanonicalHash -Value ([ordered]@{
                    Mailbox = 'user@contoso.com'; ItemId = 'item-1'; From = 'Pacific Standard Time'; To = 'Mountain Standard Time'; RecordType = 'Single'
                    StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'
                    StartUtc = '2026-11-09T18:00:00Z'; EndUtc = '2026-11-09T19:00:00Z'; ChangeKey = 'CK-0'
                })
            # The completing run hashed the target state with a 0 MB limit, so the attachment has no content hash.
            $stateHash = Get-ExOPCalendarStateHash -Snapshot (Get-ExOPItemSnapshot -Session $null -Mailbox 'user@contoso.com' `
                    -Item (New-CompletedItem) -From 'Mountain Standard Time' -To 'Mountain Standard Time' -AttachmentHashLimitBytes 0)
            $receipt = [ordered]@{
                SchemaVersion = 1; OperationId = 'done-op'; RunId = 'earlier-run'; InputHash = $inputHash; StateHash = $stateHash; StateHashVersion = 5
                FromZone = 'Pacific Standard Time'; ToZone = 'Mountain Standard Time'
            }
            if ($Limit -ge 0) { $receipt.AttachmentHashLimitBytes = [long]$Limit }
            $Script:completedItem = New-CompletedItem -ReceiptJson (ConvertTo-Json -InputObject $receipt -Compress)
            Mock Get-ExOPCalendarItem { Write-Output -InputObject $Script:completedItem -NoEnumerate }
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $Script:limitBefore = $script:MaxAttachmentHashBytes
            $Script:rerunResult = Invoke-ExOPCalendarEventMigration -Session $session -InputObject $row -ToWindowsTimeZoneId 'Mountain Standard Time' `
                -Apply -LogDirectory (Join-Path -Path $TestDrive -ChildPath ('rerun-' + [Guid]::NewGuid().ToString('N'))) -Confirm:$false -WarningAction SilentlyContinue
        }

        It 'Ends with <Status>' {
            $Script:rerunResult.Status | Should -BeExactly $Status
            if ($Status -eq 'AlreadyMigrated') { $Script:rerunResult.CalendarState | Should -BeExactly 'TargetVerified' }
        }

        It 'Reads attachment content only under the run''s own limit' {
            Should -Invoke Invoke-ExOPEwsRequest -Times $AttachmentReads -Exactly -Scope Context -ParameterFilter { $Body -like '*<m:GetAttachment>*' }
        }

        It 'Restores the limit of the current run' {
            $script:MaxAttachmentHashBytes | Should -Be $Script:limitBefore
        }
    }

    Context 'Final receipt after a sent meeting update when <Name>' -ForEach @(
        @{ Name = 'the key is unchanged'; InitialKey = 'CK-sent'; StateMatches = $true; Conflicts = 0; ErrorText = ''; Updates = 1; Snapshots = 0; Accepted = 0; Reads = 0 }
        @{ Name = 'a response changed the key'; InitialKey = 'CK-response'; StateMatches = $true; Conflicts = 0; ErrorText = ''; Updates = 1; Snapshots = 1; Accepted = 1; Reads = 0 }
        @{ Name = 'a response arrives between the read and the write'; InitialKey = 'CK-sent'; StateMatches = $true; Conflicts = 1; ErrorText = ''; Updates = 2; Snapshots = 1; Accepted = 1; Reads = 1 }
        @{ Name = 'calendar data changed with the key'; InitialKey = 'CK-response'; StateMatches = $false; Conflicts = 0; ErrorText = 'The verified state changed before finalization.'; Updates = 0; Snapshots = 1; Accepted = 0; Reads = 0 }
        @{ Name = 'conflicts persist'; InitialKey = 'CK-sent'; StateMatches = $true; Conflicts = 5; ErrorText = 'EWS `[ErrorIrresolvableConflict`]*'; Updates = 3; Snapshots = 2; Accepted = 2; Reads = 2 }
    ) {
        BeforeAll {
            $Script:receiptServer = [PSCustomObject]@{ Key = $InitialKey; Conflicts = $Conflicts; Responses = 0 }
            function New-ReceiptItem {
                (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="' + $Script:receiptServer.Key + '"/><t:Subject>Weekly sync</t:Subject>' +
                    '<t:StartTimeZone Id="Mountain Standard Time"/><t:EndTimeZone Id="Mountain Standard Time"/>')).DocumentElement
            }
            function New-ReceiptSnapshot {
                param([string]$Subject)
                [PSCustomObject]@{
                    Xml = '<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:Subject>' + $Subject + '</t:Subject>' +
                    '<t:StartTimeZone Id="Mountain Standard Time"/><t:EndTimeZone Id="Mountain Standard Time"/></t:CalendarItem>'
                    TimeZoneProperties = @(); Attachments = @(); Deleted = @(); Modified = @()
                }
            }
            $Script:receiptTargetHash = Get-ExOPCalendarStateHash -Snapshot (New-ReceiptSnapshot -Subject 'Weekly sync')
            $Script:receiptMatches = $StateMatches
            Mock Get-ExOPCalendarItem { Write-Output -InputObject (New-ReceiptItem) -NoEnumerate }
            Mock Get-ExOPItemSnapshot { if ($Script:receiptMatches) { New-ReceiptSnapshot -Subject 'Weekly sync' } else { New-ReceiptSnapshot -Subject 'Edited' } }
            Mock Invoke-ExOPEwsRequest {
                if ($Body -notlike '*<m:UpdateItem *') { throw 'Unexpected EWS request in an offline test.' }
                if ($Script:receiptServer.Conflicts -gt 0) {
                    $Script:receiptServer.Conflicts--
                    $Script:receiptServer.Responses++
                    $Script:receiptServer.Key = 'CK-response-' + $Script:receiptServer.Responses
                    throw (New-EwsFailure -Code 'ErrorIrresolvableConflict')
                }
                New-UpdateItemResponse -ChangeKey 'CK-final'
            }
            $run = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath ('receipt-' + [Guid]::NewGuid().ToString('N'))) `
                -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $true
            $Script:receiptRun = $run
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $session.ActiveOperation = [PSCustomObject]@{
                Run = $run; OperationId = 'receipt-op'; Mailbox = 'user@contoso.com'; ItemId = 'item-1'; Phase = 'FinalizeReceipt'
                LastChangeKey = 'CK-sent'; AcknowledgedWrites = 4; WriteAttempted = $true; LastWriteUnknown = $false; NotificationStarted = $true
            }
            $receipt = [PSCustomObject]@{ SchemaVersion = 1; OperationId = 'receipt-op'; StateHash = $Script:receiptTargetHash; StateHashVersion = 5 }
            $Script:receiptError = ''
            try {
                Set-ExOPVerifiedFinalMigrationState -Session $session -Mailbox 'user@contoso.com' -ItemId 'item-1' -Item (New-ReceiptItem) `
                    -Receipt $receipt -TargetHash $Script:receiptTargetHash
            } catch { $Script:receiptError = $_.Exception.Message }
            $Script:receiptOperation = $session.ActiveOperation
        }

        It 'Ends as expected' {
            if ($ErrorText) { $Script:receiptError | Should -BeLike $ErrorText }
            else {
                $Script:receiptError | Should -BeExactly ''
                $Script:receiptOperation.LastChangeKey | Should -BeExactly 'CK-final'
            }
        }

        It 'Writes the receipt <Updates> time(s) with the proven key' {
            Should -Invoke Invoke-ExOPEwsRequest -Times $Updates -Exactly -Scope Context
            if ($Updates -gt 0 -and -not $ErrorText) {
                $Script:expectedReceiptKey = if ($Conflicts -gt 0) { 'CK-response-' + $Conflicts } else { $InitialKey }
                Should -Invoke Invoke-ExOPEwsRequest -Times 1 -Exactly -Scope Context -ParameterFilter { $Body -like ('*ChangeKey="' + $Script:expectedReceiptKey + '"*') }
            }
        }

        It 'Accepts a new key only after proving the verified state' {
            Should -Invoke Get-ExOPItemSnapshot -Times $Snapshots -Exactly -Scope Context
            Should -Invoke Get-ExOPCalendarItem -Times $Reads -Exactly -Scope Context
            $events = @(Get-ChildItem -LiteralPath $Script:receiptRun.Directory -Recurse -Filter 'details.jsonl' |
                    ForEach-Object { [IO.File]::ReadAllLines($_.FullName) } | ForEach-Object { $_ | ConvertFrom-Json } |
                    Where-Object Event -EQ 'VerifiedTargetKeyAccepted')
            $events | Should -HaveCount $Accepted
        }
    }

    Context 'Audit storage failure during a migration run' {
        BeforeAll {
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $directory = Join-Path -Path $TestDrive -ChildPath 'storage-failure'
            Mock Write-ExOPDurableText { throw 'The disk is full.' } -ParameterFilter { $Path -like '*details.jsonl' }
            $rows = @(
                [PSCustomObject]@{ Mailbox = 'user@contoso.com'; ItemId = 'item-1' }
                [PSCustomObject]@{ Mailbox = 'user@contoso.com'; ItemId = 'item-2' }
            )
            $Script:storageError = ''
            try {
                $Script:storageResults = @(Invoke-ExOPCalendarEventMigration -Session $session -InputObject $rows -ToWindowsTimeZoneId 'Mountain Standard Time' `
                        -Apply -LogDirectory $directory -Confirm:$false -WarningAction SilentlyContinue)
            } catch { $Script:storageError = $_.Exception.Message }
        }

        It 'Returns a result for every row instead of failing' {
            $Script:storageError | Should -BeExactly ''
            $Script:storageResults | Should -HaveCount 2
            $Script:storageResults[0].Error | Should -BeLike '*Audit storage failed: *The disk is full.*'
        }

        It 'Changes nothing after the failure' {
            $Script:storageResults[1].Status | Should -BeExactly 'NotAttempted'
            $Script:storageResults[1].Error | Should -BeLike 'Audit storage is unavailable*'
        }
    }

    Context 'Invoke-ExOPCalendarEventMigration notification outcome: <Name>' -ForEach @(
        @{ Name = 'send rejected with ErrorSendAsDenied'; Attendees = $true; FailureCode = 'ErrorSendAsDenied'; SendFails = $true; Status = 'RolledBack'; NotificationStatus = 'NotSent'; RollbackStatus = 'Verified'; RollbackCalls = 1; ErrorCode = 'ErrorSendAsDenied' }
        @{ Name = 'send rejected with ErrorInvalidRecipients'; Attendees = $true; FailureCode = 'ErrorInvalidRecipients'; SendFails = $true; Status = 'RolledBack'; NotificationStatus = 'NotSent'; RollbackStatus = 'Verified'; RollbackCalls = 1; ErrorCode = 'ErrorInvalidRecipients' }
        @{ Name = 'send failed with ErrorInternalServerError'; Attendees = $true; FailureCode = 'ErrorInternalServerError'; SendFails = $true; Status = 'Critical'; NotificationStatus = 'OutcomeUnknown'; RollbackStatus = 'ProhibitedAfterNotification'; RollbackCalls = 0; ErrorCode = 'ErrorInternalServerError' }
        @{ Name = 'send failed in transport'; Attendees = $true; FailureCode = ''; SendFails = $true; Status = 'Critical'; NotificationStatus = 'OutcomeUnknown'; RollbackStatus = 'ProhibitedAfterNotification'; RollbackCalls = 0; ErrorCode = '' }
        @{ Name = 'meeting without attendees'; Attendees = $false; FailureCode = ''; SendFails = $false; Status = 'Applied'; NotificationStatus = 'NotRequired'; RollbackStatus = 'NotNeeded'; RollbackCalls = 0; ErrorCode = '' }
    ) {
        BeforeAll {
            $Script:migrationAttendees = $Attendees
            $Script:migrationFailureCode = $FailureCode
            $Script:migrationSendFails = $SendFails
            $Script:serverChangeKey = 'CK-0'
            $Script:serverWrites = 0
            $Script:receiptOperationId = ''
            $Script:preparedProperties = @('<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33374" PropertyType="Binary"/><t:Value>AAAA</t:Value></t:ExtendedProperty>')

            # The calendar item as the mocked server currently returns it.
            function New-MigrationItem {
                $attendeeXml = if ($Script:migrationAttendees) {
                    '<t:RequiredAttendees><t:Attendee><t:Mailbox><t:EmailAddress>attendee@contoso.com</t:EmailAddress></t:Mailbox></t:Attendee></t:RequiredAttendees>'
                } else { '' }
                $receiptXml = ''
                if ($Script:receiptOperationId) {
                    $receipt = ConvertTo-Json -Compress -InputObject ([ordered]@{ SchemaVersion = 1; OperationId = $Script:receiptOperationId; StateHash = 'verified' })
                    $receiptXml = '<t:ExtendedProperty>' + $script:MigrationReceiptFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $receipt) + '</t:Value></t:ExtendedProperty>'
                }
                (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="' + $Script:serverChangeKey + '"/><t:ParentFolderId Id="calendar-folder"/>' +
                    '<t:Subject>Weekly sync</t:Subject><t:UID>calendar-uid-1</t:UID><t:CalendarItemType>Single</t:CalendarItemType>' +
                    '<t:IsOrganizer>true</t:IsOrganizer><t:IsMeeting>true</t:IsMeeting><t:Start>2026-11-09T18:00:00Z</t:Start><t:End>2026-11-09T19:00:00Z</t:End>' +
                    '<t:StartTimeZone Id="Pacific Standard Time"/><t:EndTimeZone Id="Pacific Standard Time"/>' + $attendeeXml + $receiptXml)).DocumentElement
            }

            Mock Get-ExOPDefaultCalendarId { 'calendar-folder' }
            Mock Get-ExOPCalendarItem { Write-Output -InputObject (New-MigrationItem) -NoEnumerate }
            Mock Get-ExOPItemSnapshot {
                [PSCustomObject]@{
                    Xml = (New-MigrationItem).OuterXml; TimeZoneProperties = $Script:preparedProperties; Attachments = @(); Modified = @(); Deleted = @()
                    RecurrenceBase64 = ''; HasIanaNames = $false; Receipt = $null
                }
            }
            Mock Get-ExOPValidatedTimeZoneData { @{} }
            Mock Get-ExOPPreparedTimeZoneProperties { [PSCustomObject]@{ Properties = $Script:preparedProperties; O12Modes = @{} } }
            Mock Set-ExOPSeriesTimeZoneState { }
            Mock Assert-ExOPRehomeResult { Write-Output -InputObject (New-MigrationItem) -NoEnumerate }
            Mock Assert-ExOPPreservedItemData { }
            Mock Set-ExOPFinalMigrationState { $Script:receiptOperationId = $Receipt.OperationId }
            Mock Invoke-ExOPPreSendRollback { 'rollback-verified.json' }
            Mock Invoke-ExOPEwsRequest {
                if ($Body -notlike '*<m:UpdateItem *') { throw 'Unexpected EWS request in an offline test.' }
                if ($Body -like '*SendToAllAndSaveCopy*' -and $Script:migrationSendFails) { throw (New-EwsFailure -Code $Script:migrationFailureCode) }
                $Script:serverWrites++
                $Script:serverChangeKey = 'CK-' + $Script:serverWrites
                New-UpdateItemResponse -ChangeKey $Script:serverChangeKey
            }

            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $row = [PSCustomObject]@{
                SchemaVersion = '1'; Mailbox = 'user@contoso.com'; ItemId = 'item-1'; ChangeKey = 'CK-0'; RecordType = 'Single'
                FromWindowsTimeZoneId = 'Pacific Standard Time'; StartTimeZoneId = 'Pacific Standard Time'; EndTimeZoneId = 'Pacific Standard Time'
                StartUtc = '2026-11-09T18:00:00Z'; EndUtc = '2026-11-09T19:00:00Z'
            }
            $Script:migrationLogDirectory = Join-Path -Path $TestDrive -ChildPath ('migration-' + [Guid]::NewGuid().ToString('N'))
            $Script:migrationResult = Invoke-ExOPCalendarEventMigration -Session $session -InputObject $row -ToWindowsTimeZoneId 'mountain STANDARD time' `
                -Apply -LogDirectory $Script:migrationLogDirectory -Confirm:$false -WarningAction SilentlyContinue
        }

        It 'Uses the exact Windows time zone ID, not the spelling typed by the operator' {
            $Script:migrationResult.To | Should -BeExactly 'Mountain Standard Time'
            Should -Invoke Set-ExOPFinalMigrationState -Times ([int]($Status -eq 'Applied')) -Exactly -Scope Context -ParameterFilter { $Receipt.ToZone -ceq 'Mountain Standard Time' }
        }

        It 'Records the attachment hash limit in the completion receipt' {
            Should -Invoke Set-ExOPFinalMigrationState -Times ([int]($Status -eq 'Applied')) -Exactly -Scope Context -ParameterFilter {
                $null -ne $Receipt -and $Receipt.AttachmentHashLimitBytes -eq $script:MaxAttachmentHashBytes
            }
        }

        It 'Ends with status <Status>, notification <NotificationStatus> and rollback <RollbackStatus>' {
            $Script:migrationResult.Status | Should -BeExactly $Status
            $Script:migrationResult.NotificationStatus | Should -BeExactly $NotificationStatus
            $Script:migrationResult.RollbackStatus | Should -BeExactly $RollbackStatus
            $Script:migrationResult.ErrorCode | Should -BeExactly $ErrorCode
        }

        It 'Rolls back only after a definitive send rejection' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times $RollbackCalls -Exactly -Scope Context
        }

        It 'Attempts the meeting update only when attendees exist' {
            $expectedSends = if ($Attendees) { 1 } else { 0 }
            Should -Invoke Invoke-ExOPEwsRequest -Times $expectedSends -Exactly -Scope Context -ParameterFilter { $Body -like '*SendToAllAndSaveCopy*' }
        }

        It 'Rolls back from the last acknowledged state with no notification started' {
            Should -Invoke Invoke-ExOPPreSendRollback -Times $RollbackCalls -Exactly -Scope Context -ParameterFilter {
                $Operation.NotificationStarted -eq $false -and $Operation.NotificationRejected -ceq $Script:migrationFailureCode -and
                $Operation.LastWriteUnknown -eq $false -and $Operation.LastChangeKey -ceq $Script:serverChangeKey
            }
        }

        It 'Writes the new master endpoints' {
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times 1 -Exactly -Scope Context -ParameterFilter {
                $StartUtc -ceq '2026-11-09T17:00:00.0000000Z' -and $EndUtc -ceq '2026-11-09T18:00:00.0000000Z'
            }
        }

        It 'Saves the attachment hash limit with the original snapshot' {
            $before = Get-Content -LiteralPath $Script:migrationResult.SnapshotPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $before.AttachmentHashLimitBytes | Should -Be $script:MaxAttachmentHashBytes
        }
        It 'Journals a definitive rejection only for rejected sends' {
            $journal = @(Get-ChildItem -LiteralPath $Script:migrationLogDirectory -Recurse -Filter 'details.jsonl' |
                    ForEach-Object { Get-Content -LiteralPath $_.FullName } | ForEach-Object { $_ | ConvertFrom-Json })
            @($journal | Where-Object { $_.Event -eq 'NotificationRejected' }) | Should -HaveCount $RollbackCalls
        }
    }

    Context 'New-ExOPRawEndpointUpdates' {
        BeforeAll {
            function Get-UpdateSummary {
                param(
                    [string[]]
                    $Updates
                )
                foreach ($update in $Updates) {
                    $document = New-Object Xml.XmlDocument
                    $document.LoadXml('<root xmlns:t="' + $script:TypesNamespace + '">' + $update + '</root>')
                    $field = $document.DocumentElement.FirstChild.FirstChild
                    $identity = if ($field.HasAttribute('PropertyId')) { $field.GetAttribute('PropertyId') } else { $field.GetAttribute('PropertyTag') }
                    $identity + '=' + $field.GetAttribute('PropertyType') + '=' + $document.DocumentElement.InnerText
                }
            }
        }

        It 'Writes StartWhole, EndWhole and the start and end date properties' {
            $updates = @(New-ExOPRawEndpointUpdates -StartUtc '2026-11-09T17:00:00Z' -EndUtc '2026-11-09T18:00:00Z')
            (Get-UpdateSummary -Updates $updates) -join ',' | Should -BeExactly (@(
                    '33293=SystemTime=2026-11-09T17:00:00Z', '33294=SystemTime=2026-11-09T18:00:00Z',
                    '0x0060=SystemTime=2026-11-09T17:00:00Z', '0x0061=SystemTime=2026-11-09T18:00:00Z') -join ',')
        }

        It 'Adds ClipStart and ClipEnd when requested' {
            $updates = @(New-ExOPRawEndpointUpdates -StartUtc '2026-11-09T00:00:00Z' -EndUtc '2026-11-10T00:00:00Z' -IncludeClip)
            (Get-UpdateSummary -Updates $updates) -join ',' | Should -BeExactly (@(
                    '33293=SystemTime=2026-11-09T00:00:00Z', '33294=SystemTime=2026-11-10T00:00:00Z',
                    '33333=SystemTime=2026-11-09T00:00:00Z', '33334=SystemTime=2026-11-10T00:00:00Z',
                    '0x0060=SystemTime=2026-11-09T00:00:00Z', '0x0061=SystemTime=2026-11-10T00:00:00Z') -join ',')
        }

        It 'Writes complete SetItemField updates' {
            $updates = @(New-ExOPRawEndpointUpdates -StartUtc '2026-11-09T17:00:00Z' -EndUtc '2026-11-09T18:00:00Z')
            $updates[0] | Should -BeExactly ('<t:SetItemField><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33293" PropertyType="SystemTime"/>' +
                '<t:CalendarItem><t:ExtendedProperty><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="33293" PropertyType="SystemTime"/>' +
                '<t:Value>2026-11-09T17:00:00Z</t:Value></t:ExtendedProperty></t:CalendarItem></t:SetItemField>')
            $updates[3] | Should -BeExactly ('<t:SetItemField><t:ExtendedFieldURI PropertyTag="0x0061" PropertyType="SystemTime"/>' +
                '<t:CalendarItem><t:ExtendedProperty><t:ExtendedFieldURI PropertyTag="0x0061" PropertyType="SystemTime"/>' +
                '<t:Value>2026-11-09T18:00:00Z</t:Value></t:ExtendedProperty></t:CalendarItem></t:SetItemField>')
        }
    }

    Context 'Set-ExOPSeriesTimeZoneState requests' {
        BeforeAll {
            Register-FakeHttp
            $Script:metadataProperty = '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" ' +
            'PropertyId="33331" PropertyType="Binary"/><t:Value>AAAA</t:Value></t:ExtendedProperty>'

            function Get-RequestFieldOrder {
                param(
                    [string]
                    $Request
                )
                @([regex]::Matches($Request, '<t:SetItemField><t:(?:Extended)?FieldURI (?:DistinguishedPropertySetId="Appointment" PropertyId="(?<id>\d+)"|PropertyTag="(?<id>0x[0-9A-Fa-f]+)"|FieldURI="(?<id>[^"]+)")') |
                        ForEach-Object { $_.Groups['id'].Value }) -join ','
            }
        }

        BeforeEach {
            [ExOPTests.FakeEwsServer]::Reset()
        }

        It 'Writes the endpoints of <Name> with <Expected>' -ForEach @(
            @{ Name = 'a timed single item'; Type = 'Single'; AllDay = 'false'; Expected = '33293,33294,33333,33334,0x0060,0x0061'; Start = '2026-10-04T08:00:00Z'; End = '2026-10-04T09:00:00Z' }
            @{ Name = 'an all-day single item'; Type = 'Single'; AllDay = 'true'; Expected = '33293,33294,33333,33334,0x0060,0x0061'; Start = '2026-11-08T23:00:00Z'; End = '2026-11-09T23:00:00Z' }
            @{ Name = 'a recurring master'; Type = 'RecurringMaster'; AllDay = 'false'; Expected = 'calendar:Start,calendar:End'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z' }
        ) {
            $session = New-ExOPCalendarSession -EwsUrl 'https://ews-test.contoso.invalid/EWS/Exchange.asmx'
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-UpdateItemResponse -ChangeKey 'CK-2').OuterXml)
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-UpdateItemResponse -ChangeKey 'CK-3').OuterXml)
            $item = (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="CK-1"/><t:CalendarItemType>' + $Type + '</t:CalendarItemType>' +
                    '<t:IsAllDayEvent>' + $AllDay + '</t:IsAllDayEvent>')).DocumentElement
            $written = Set-ExOPSeriesTimeZoneState -Session $session -Mailbox 'user@contoso.com' -Item $item -Properties @($Script:metadataProperty) -StartUtc $Start -EndUtc $End
            $written.ChangeKey | Should -BeExactly 'CK-3'
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 2
            $metadataRequest = [ExOPTests.FakeEwsServer]::Requests[0]
            $datesRequest = [ExOPTests.FakeEwsServer]::Requests[1]
            Get-RequestFieldOrder -Request $metadataRequest | Should -BeExactly '33331'
            Get-RequestFieldOrder -Request $datesRequest | Should -BeExactly $Expected
            $datesRequest | Should -BeLike "*>$Start<*"
            $datesRequest | Should -BeLike "*>$End<*"
            $datesRequest | Should -BeLike '*ChangeKey="CK-2"*'
            foreach ($request in $metadataRequest, $datesRequest) {
                $request | Should -BeLike '*<t:TimeZoneContext><t:TimeZoneDefinition Id="UTC"/></t:TimeZoneContext>*'
            }
        }

        It 'Writes no calendar:Start or calendar:End for a single item' {
            $session = New-ExOPCalendarSession -EwsUrl 'https://ews-test.contoso.invalid/EWS/Exchange.asmx'
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-UpdateItemResponse -ChangeKey 'CK-2').OuterXml)
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-UpdateItemResponse -ChangeKey 'CK-3').OuterXml)
            $item = (New-CalendarItemXml -InnerXml '<t:ItemId Id="item-1" ChangeKey="CK-1"/><t:CalendarItemType>Single</t:CalendarItemType>').DocumentElement
            $null = Set-ExOPSeriesTimeZoneState -Session $session -Mailbox 'user@contoso.com' -Item $item -Properties @($Script:metadataProperty) `
                -StartUtc '2026-10-04T08:00:00Z' -EndUtc '2026-10-04T09:00:00Z'
            [ExOPTests.FakeEwsServer]::Requests[1] | Should -Not -BeLike '*calendar:Start*'
            [ExOPTests.FakeEwsServer]::Requests[1] | Should -Not -BeLike '*calendar:End*'
        }
    }
    Context 'Assert-ExOPRollbackEndpoints' {
        BeforeAll {
            $Script:endpointValuesForRollback = [PSCustomObject]@{
                StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; NewStartZone = 'Mountain Standard Time'; NewEndZone = 'Mountain Standard Time'
                StartUtc = '2026-11-09T18:00:00.0000000Z'; EndUtc = '2026-11-09T19:00:00.0000000Z'
                NewStartUtc = '2026-11-09T17:00:00.0000000Z'; NewEndUtc = '2026-11-09T18:00:00.0000000Z'
            }

            function New-EndpointItem {
                param(
                    [string]
                    $Start,

                    [string]
                    $End,

                    [string]
                    $StartZone,

                    [string]
                    $EndZone
                )
                (New-CalendarItemXml -InnerXml ('<t:Start>' + $Start + '</t:Start><t:End>' + $End + '</t:End><t:StartTimeZone Id="' + $StartZone + '"/>' +
                    '<t:EndTimeZone Id="' + $EndZone + '"/>')).DocumentElement
            }
        }

        It 'Accepts <Name>' -ForEach @(
            @{ Name = 'original times and original zones'; Start = '2026-11-09T18:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time' }
            @{ Name = 'original times and new zones'; Start = '2026-11-09T18:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time' }
            @{ Name = 'new times and new zones'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time' }
            @{ Name = 'new times written with an offset'; Start = '2026-11-09T10:00:00-07:00'; End = '2026-11-09T10:00:00-08:00'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time' }
        ) {
            $item = New-EndpointItem -Start $Start -End $End -StartZone $StartZone -EndZone $EndZone
            { Assert-ExOPRollbackEndpoints -Item $item -Values $Script:endpointValuesForRollback } | Should -Not -Throw
        }

        It 'Refuses <Name>' -ForEach @(
            @{ Name = 'new times with original zones'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time' }
            @{ Name = 'an intended start with an original end and original zones'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time' }
            @{ Name = 'an intended start with an original end and mixed zones'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Pacific Standard Time' }
            @{ Name = 'an original start with an intended end and new zones'; Start = '2026-11-09T18:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time' }
            @{ Name = 'original times with mixed zones'; Start = '2026-11-09T18:00:00Z'; End = '2026-11-09T19:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Pacific Standard Time' }
            @{ Name = 'a start moved by the user'; Start = '2026-11-10T15:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time' }
            @{ Name = 'an end moved by the user'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:30:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Mountain Standard Time' }
            @{ Name = 'a foreign start time zone'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'UTC'; EndZone = 'Mountain Standard Time' }
            @{ Name = 'a foreign end time zone'; Start = '2026-11-09T17:00:00Z'; End = '2026-11-09T18:00:00Z'; StartZone = 'Mountain Standard Time'; EndZone = 'Central Standard Time' }
        ) {
            $item = New-EndpointItem -Start $Start -End $End -StartZone $StartZone -EndZone $EndZone
            { Assert-ExOPRollbackEndpoints -Item $item -Values $Script:endpointValuesForRollback } |
                Should -Throw -ExpectedMessage 'The item times or time zones changed outside this operation; the item was not overwritten.'
        }
    }
    Context 'Series rollback after an unknown write outcome with an exception in state <Name>' -ForEach @(
        @{ Name = 'intended'; Start = '2026-11-16T17:00:00.0000000Z'; End = '2026-11-16T18:00:00.0000000Z'; Restores = $true }
        @{ Name = 'original'; Start = '2026-11-16T18:00:00.0000000Z'; End = '2026-11-16T19:00:00.0000000Z'; Restores = $true }
        @{ Name = 'intended start with original end (an organizer edit)'; Start = '2026-11-16T17:00:00.0000000Z'; End = '2026-11-16T19:00:00.0000000Z'; Restores = $false }
        @{ Name = 'original start with intended end'; Start = '2026-11-16T18:00:00.0000000Z'; End = '2026-11-16T18:00:00.0000000Z'; Restores = $false }
    ) {
        BeforeAll {
            $Script:seriesRollback = [PSCustomObject]@{ Restored = $false; MarkerCleared = $false; OperationId = [Guid]::NewGuid().ToString('N') }
            function New-SeriesRollbackItem {
                $marker = ''
                if (-not $Script:seriesRollback.MarkerCleared) {
                    $state = ConvertTo-Json -Compress -InputObject ([ordered]@{ SchemaVersion = 1; Status = 'InProgress'; OperationId = $Script:seriesRollback.OperationId })
                    $marker = '<t:ExtendedProperty>' + $script:MigrationStateFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $state) + '</t:Value></t:ExtendedProperty>'
                }
                (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="CK-unknown-write"/><t:Subject>Weekly sync</t:Subject>' +
                    '<t:CalendarItemType>RecurringMaster</t:CalendarItemType><t:Start>2026-11-09T17:00:00Z</t:Start><t:End>2026-11-09T18:00:00Z</t:End>' +
                    '<t:StartTimeZone Id="Mountain Standard Time"/><t:EndTimeZone Id="Mountain Standard Time"/>' + $marker)).DocumentElement
            }
            function New-SeriesRollbackSnapshot {
                param([string]$OriginalStartUtc, $Values)
                [PSCustomObject]@{
                    Xml      = (New-CalendarItemXml -InnerXml '<t:Subject>Weekly sync</t:Subject><t:StartTimeZone Id="Pacific Standard Time"/><t:EndTimeZone Id="Pacific Standard Time"/>').DocumentElement.OuterXml
                    TimeZoneProperties = @(); Attachments = @(); Deleted = @(); RecurrenceBase64 = ''; Receipt = $null
                    Modified = @([PSCustomObject]@{
                            OriginalStartUtc = $OriginalStartUtc; Values = $Values; Attachments = @()
                            Xml = (New-CalendarItemXml -InnerXml '<t:Subject>Occurrence</t:Subject>').DocumentElement.OuterXml
                        })
                }
            }
            $exceptionValues = [PSCustomObject]@{
                StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; NewStartZone = 'Mountain Standard Time'; NewEndZone = 'Mountain Standard Time'
                StartUtc = '2026-11-16T18:00:00.0000000Z'; EndUtc = '2026-11-16T19:00:00.0000000Z'; NewStartUtc = '2026-11-16T17:00:00.0000000Z'; NewEndUtc = '2026-11-16T18:00:00.0000000Z'
            }
            $Script:seriesOriginal = New-SeriesRollbackSnapshot -OriginalStartUtc '2026-11-16T18:00:00.0000000Z' -Values $exceptionValues
            # The same local slot (10:00) after the series moved to Mountain time.
            $Script:seriesCurrent = New-SeriesRollbackSnapshot -OriginalStartUtc '2026-11-16T17:00:00.0000000Z' -Values ([PSCustomObject]@{ StartUtc = $Start; EndUtc = $End })
            Mock Get-ExOPCalendarItem { Write-Output -InputObject (New-SeriesRollbackItem) -NoEnumerate }
            Mock Get-ExOPItemSnapshot { if ($Script:seriesRollback.Restored) { $Script:seriesOriginal } else { $Script:seriesCurrent } }
            Mock Assert-ExOPPreservedItemData { }
            Mock New-ExOPExceptionTimeBridge { 'AAAA' }
            Mock Set-ExOPSeriesTimeZoneState { }
            Mock Update-ExOPPreservedExceptions { $Script:seriesRollback.Restored = $true }
            Mock Set-ExOPCalendarFields { }
            Mock Assert-ExOPRehomeResult { Write-Output -InputObject (New-SeriesRollbackItem) -NoEnumerate }
            Mock Set-ExOPFinalMigrationState { $Script:seriesRollback.MarkerCleared = $true }
            $operation = [PSCustomObject]@{
                Run               = (New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath ('series-rollback-' + [Guid]::NewGuid().ToString('N'))) `
                        -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'RecurringSeries' }) -Apply $true)
                OperationId = $Script:seriesRollback.OperationId; Mailbox = 'user@contoso.com'; ItemId = 'item-1'; Phase = 'MasterDates'
                LastChangeKey = 'CK-acknowledged'; AcknowledgedWrites = 3; WriteAttempted = $true; LastWriteUnknown = $true; RollbackInProgress = $true
                MetadataWritten = $true; DatesWritten = $true; NotificationStarted = $false; RollingBack = $false; IsSeries = $true
                Before = $Script:seriesOriginal; Prepared = $null; VerifiedTargetHash = ''
                Values            = [PSCustomObject]@{
                    StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; NewStartZone = 'Mountain Standard Time'; NewEndZone = 'Mountain Standard Time'
                    StartUtc = '2026-11-09T18:00:00.0000000Z'; EndUtc = '2026-11-09T19:00:00.0000000Z'; NewStartUtc = '2026-11-09T17:00:00.0000000Z'; NewEndUtc = '2026-11-09T18:00:00.0000000Z'
                }
                OriginalStateHash = Get-ExOPCalendarStateHash -Snapshot $Script:seriesOriginal
            }
            $Script:seriesRollbackError = ''
            try { $null = Invoke-ExOPPreSendRollback -Session $null -Operation $operation } catch { $Script:seriesRollbackError = $_.Exception.Message }
        }

        It 'Restores only when every exception has a complete original or intended pair' {
            if ($Restores) {
                $Script:seriesRollbackError | Should -BeExactly ''
                Should -Invoke Update-ExOPPreservedExceptions -Times 1 -Exactly -Scope Context
            } else {
                $Script:seriesRollbackError | Should -BeExactly 'An exception no longer matches the original or intended operation state.'
                Should -Invoke Set-ExOPSeriesTimeZoneState -Times 0 -Exactly -Scope Context
                Should -Invoke Update-ExOPPreservedExceptions -Times 0 -Exactly -Scope Context
            }
        }
    }

    Context 'Invoke-ExOPPreSendRollback after the item ChangeKey changed' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            Mock Assert-ExOPPreservedItemData { }
            Mock Set-ExOPSeriesTimeZoneState { $Script:restored = $true }
            Mock Set-ExOPCalendarFields { }
            Mock Assert-ExOPRehomeResult { Write-Output -InputObject (New-RollbackItem) -NoEnumerate }
            Mock Set-ExOPFinalMigrationState { $Script:markerCleared = $true }
            Mock Get-ExOPCalendarItem { Write-Output -InputObject (New-RollbackItem) -NoEnumerate }
            Mock Get-ExOPItemSnapshot { if ($Script:restored) { $Script:originalSnapshot } else { $Script:currentSnapshot } }

            function New-RollbackItem {
                $marker = ''
                if (-not $Script:markerCleared) {
                    $state = ConvertTo-Json -Compress -InputObject ([ordered]@{ SchemaVersion = 1; Status = 'InProgress'; OperationId = $Script:rollbackOperationId })
                    $marker = '<t:ExtendedProperty>' + $script:MigrationStateFieldUri + '<t:Value>' + (ConvertTo-ExOPXmlText -Value $state) + '</t:Value></t:ExtendedProperty>'
                }
                (New-CalendarItemXml -InnerXml ('<t:ItemId Id="item-1" ChangeKey="' + $Script:serverKey + '"/><t:Subject>Weekly sync</t:Subject>' +
                    '<t:StartTimeZone Id="Mountain Standard Time"/><t:EndTimeZone Id="Mountain Standard Time"/>' + $marker)).DocumentElement
            }

            function New-RollbackSnapshot {
                param(
                    [string]
                    $Subject,

                    [string]
                    $Start,

                    [string]
                    $Zone
                )
                [PSCustomObject]@{
                    Xml = (New-CalendarItemXml -InnerXml ('<t:Subject>' + $Subject + '</t:Subject><t:Start>' + $Start + '</t:Start>' +
                            '<t:StartTimeZone Id="' + $Zone + '"/><t:EndTimeZone Id="' + $Zone + '"/>')).DocumentElement.OuterXml
                    TimeZoneProperties = @(); Attachments = @(); Modified = @(); Deleted = @(); RecurrenceBase64 = ''; Receipt = $null
                }
            }

            $Script:originalSnapshot = New-RollbackSnapshot -Subject 'Weekly sync' -Start '2026-11-09T18:00:00Z' -Zone 'Pacific Standard Time'
            $Script:targetSnapshot = New-RollbackSnapshot -Subject 'Weekly sync' -Start '2026-11-09T17:00:00Z' -Zone 'Mountain Standard Time'
            $Script:changedSnapshot = New-RollbackSnapshot -Subject 'Changed by someone else' -Start '2026-11-09T17:00:00Z' -Zone 'Mountain Standard Time'
            $Script:rollbackRun = New-ExOPMigrationRun -Directory (Join-Path -Path $TestDrive -ChildPath 'rollback') -Rows @([PSCustomObject]@{ Mailbox = 'user@contoso.com'; RecordType = 'Single' }) -Apply $true

            function New-RollbackOperation {
                param(
                    [string]
                    $Rejected,

                    [switch]
                    $WithoutTargetHash,

                    [int]
                    $AcknowledgedWrites = 3
                )
                $Script:rollbackOperationId = [Guid]::NewGuid().ToString('N')
                $operation = [PSCustomObject]@{
                    Run = $Script:rollbackRun; OperationId = $Script:rollbackOperationId; Mailbox = 'user@contoso.com'; ItemId = 'item-1'
                    Phase = 'Notification'; LastChangeKey = 'CK-acknowledged'; AcknowledgedWrites = $AcknowledgedWrites; WriteAttempted = $true
                    LastWriteUnknown = $false; MetadataWritten = $true; DatesWritten = $true; NotificationStarted = $false; RollingBack = $false
                    IsSeries = $false; Before = $Script:originalSnapshot; Prepared = $null
                    Values             = [PSCustomObject]@{
                        StartZone = 'Pacific Standard Time'; EndZone = 'Pacific Standard Time'; NewStartZone = 'Mountain Standard Time'; NewEndZone = 'Mountain Standard Time'
                        StartUtc = '2026-11-09T18:00:00.0000000Z'; EndUtc = '2026-11-09T19:00:00.0000000Z'
                        NewStartUtc = '2026-11-09T17:00:00.0000000Z'; NewEndUtc = '2026-11-09T18:00:00.0000000Z'
                    }
                    OriginalStateHash  = Get-ExOPCalendarStateHash -Snapshot $Script:originalSnapshot
                    VerifiedTargetHash = $(if ($WithoutTargetHash) { '' } else { Get-ExOPCalendarStateHash -Snapshot $Script:targetSnapshot })
                }
                if ($Rejected) { $operation | Add-Member -NotePropertyName NotificationRejected -NotePropertyValue $Rejected }
                $operation
            }
        }

        BeforeEach {
            $Script:restored = $false
            $Script:markerCleared = $false
            $Script:serverKey = 'CK-saved-by-exchange'
            $Script:currentSnapshot = $Script:targetSnapshot
        }

        It 'Restores an item that Exchange saved before rejecting the send' {
            $operation = New-RollbackOperation -Rejected 'ErrorSendAsDenied'
            $path = Invoke-ExOPPreSendRollback -Session $null -Operation $operation
            $path | Should -BeLike "*$($operation.OperationId)-rollback-verified.json"
            $operation.LastChangeKey | Should -BeExactly 'CK-saved-by-exchange'
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times 1 -Exactly -Scope It -ParameterFilter {
                $StartUtc -ceq '2026-11-09T18:00:00.0000000Z' -and $EndUtc -ceq '2026-11-09T19:00:00.0000000Z' -and
                $Item.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager -Node $Item)).GetAttribute('ChangeKey') -ceq 'CK-saved-by-exchange'
            }
            Should -Invoke Set-ExOPFinalMigrationState -Times 1 -Exactly -Scope It
        }

        It 'Refuses when <Name>' -ForEach @(
            @{ Name = 'the saved item differs from the verified target'; Rejected = 'ErrorSendAsDenied'; NoTargetHash = $false; Changed = $true; Owned = $true; Acknowledged = 3 }
            @{ Name = 'the send was not rejected'; Rejected = ''; NoTargetHash = $false; Changed = $false; Owned = $true; Acknowledged = 3 }
            @{ Name = 'no verified target state exists'; Rejected = 'ErrorSendAsDenied'; NoTargetHash = $true; Changed = $false; Owned = $true; Acknowledged = 3 }
            @{ Name = 'the operation does not own the item'; Rejected = 'ErrorSendAsDenied'; NoTargetHash = $false; Changed = $false; Owned = $false; Acknowledged = 0 }
        ) {
            if ($Changed) { $Script:currentSnapshot = $Script:changedSnapshot }
            if (-not $Owned) { $Script:markerCleared = $true }
            $operation = New-RollbackOperation -Rejected $Rejected -WithoutTargetHash:$NoTargetHash -AcknowledgedWrites $Acknowledged
            { Invoke-ExOPPreSendRollback -Session $null -Operation $operation } |
                Should -Throw -ExpectedMessage 'The latest write outcome or a concurrent change cannot be safely reconciled; rollback was not forced.'
            $operation.LastChangeKey | Should -BeExactly 'CK-acknowledged'
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times 0 -Exactly -Scope It
            Should -Invoke Set-ExOPFinalMigrationState -Times 0 -Exactly -Scope It
        }

        It 'Refuses an unexplained key after an unknown write outcome outside a journaled rollback' {
            $operation = New-RollbackOperation
            $operation.LastWriteUnknown = $true
            { Invoke-ExOPPreSendRollback -Session $null -Operation $operation } |
                Should -Throw -ExpectedMessage 'The latest write outcome or a concurrent change cannot be safely reconciled; rollback was not forced.'
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times 0 -Exactly -Scope It
        }

        It 'Refuses an item that the operation no longer owns after acknowledged writes' {
            $Script:markerCleared = $true
            $operation = New-RollbackOperation -Rejected 'ErrorSendAsDenied'
            { Invoke-ExOPPreSendRollback -Session $null -Operation $operation } | Should -Throw -ExpectedMessage '*ownership is no longer provable*'
        }

        It 'Removes only the bookkeeping when the changed item is already original' {
            $Script:currentSnapshot = $Script:originalSnapshot
            $operation = New-RollbackOperation
            $null = Invoke-ExOPPreSendRollback -Session $null -Operation $operation
            $operation.LastChangeKey | Should -BeExactly 'CK-saved-by-exchange'
            Should -Invoke Set-ExOPSeriesTimeZoneState -Times 0 -Exactly -Scope It
            Should -Invoke Set-ExOPFinalMigrationState -Times 1 -Exactly -Scope It
        }

        It 'Refuses after a notification may have started' {
            $operation = New-RollbackOperation -Rejected 'ErrorSendAsDenied'
            $operation.NotificationStarted = $true
            { Invoke-ExOPPreSendRollback -Session $null -Operation $operation } | Should -Throw -ExpectedMessage '*prohibited after notification*'
        }
    }

    Context 'Invoke-ExOPCalendarEventMigration send permission check for a delegate with mode <Mode>' -ForEach @(
        @{ Mode = 'None'; Skip = $false; Status = 'NotAttempted'; ErrorCode = 'SendPermissionMissing'; Blocked = $true }
        @{ Mode = 'Unknown'; Skip = $false; Status = 'NotAttempted'; ErrorCode = 'SendPermissionUnknown'; Blocked = $true }
        @{ Mode = 'None'; Skip = $true; Status = 'Failed'; ErrorCode = ''; Blocked = $false }
        @{ Mode = 'SendOnBehalf'; Skip = $false; Status = 'Failed'; ErrorCode = ''; Blocked = $false }
        @{ Mode = 'SendAs'; Skip = $false; Status = 'Failed'; ErrorCode = ''; Blocked = $false }
    ) {
        BeforeAll {
            $Script:permissionMode = $Mode
            Mock Get-ExOPSendPermission { [PSCustomObject]@{ Mode = $Script:permissionMode; Error = 'directory unavailable' } }
            # Reaching the first EWS read proves that the check let the item through.
            Mock Get-ExOPDefaultCalendarId { throw 'Reached the first EWS read.' }
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $rows = @(
                foreach ($id in 'item-1', 'item-2') {
                    [PSCustomObject]@{
                        SchemaVersion = '1'; Mailbox = 'owner@contoso.com'; ItemId = $id; ChangeKey = 'CK-0'; RecordType = 'Single'
                        FromWindowsTimeZoneId = 'Pacific Standard Time'; StartTimeZoneId = 'Pacific Standard Time'; EndTimeZoneId = 'Pacific Standard Time'
                        StartUtc = '2026-11-09T18:00:00Z'; EndUtc = '2026-11-09T19:00:00Z'
                    }
                }
            )
            $Script:permissionResults = @($rows | Invoke-ExOPCalendarEventMigration -Session $session -ToWindowsTimeZoneId 'Mountain Standard Time' -Apply `
                    -LogDirectory (Join-Path -Path $TestDrive -ChildPath ('permission-' + [Guid]::NewGuid().ToString('N'))) `
                    -SkipSendPermissionCheck:$Skip -Confirm:$false -WarningAction SilentlyContinue)
        }

        It 'Ends every item with status <Status> and error code <ErrorCode>' {
            $Script:permissionResults | Should -HaveCount 2
            foreach ($result in $Script:permissionResults) {
                $result.Status | Should -BeExactly $Status
                $result.ErrorCode | Should -BeExactly $ErrorCode
                $result.CalendarState | Should -BeExactly 'Unchanged'
                $result.NotificationStatus | Should -BeExactly 'NotStarted'
            }
        }

        It 'Explains the remedies when it blocks' {
            foreach ($result in $Script:permissionResults) {
                if ($Blocked) {
                    $result.Error | Should -BeLike '*owner@contoso.com*-SkipSendPermissionCheck*Nothing was changed.'
                } else {
                    $result.Error | Should -BeExactly 'Reached the first EWS read.'
                }
            }
        }

        It 'Reads nothing from the mailbox when it blocks' {
            $reads = if ($Blocked) { 0 } else { 2 }
            Should -Invoke Get-ExOPDefaultCalendarId -Times $reads -Exactly -Scope Context
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope Context
        }

        It 'Does not check the permission when -SkipSendPermissionCheck is used' {
            $checks = if ($Skip) { 0 } else { 2 }
            Should -Invoke Get-ExOPSendPermission -Times $checks -Exactly -Scope Context
        }
    }
}
