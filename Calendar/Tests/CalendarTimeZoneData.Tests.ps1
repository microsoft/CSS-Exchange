# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cspell:ignore Rehoming Tzi

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeDiscovery {
    # Zones captured in Data\RegistryTimeZones.json and Data\ServerTimeZones.xml.
    $Script:zoneCases = @(
        @{ Id = 'Pacific Standard Time' }
        @{ Id = 'British Columbia Standard Time' }
        @{ Id = 'AUS Eastern Standard Time' }
        @{ Id = 'Cen. Australia Standard Time' }
        @{ Id = 'Morocco Standard Time' }
        @{ Id = 'India Standard Time' }
        @{ Id = 'Nepal Standard Time' }
        @{ Id = 'UTC' }
    )
    # Mid-month instants: the local year equals the UTC year in every zone.
    $instantCases = @(
        @{ Date = '2025-01-15T12:00:00Z'; Year = 2025 }
        @{ Date = '2026-11-09T12:00:00Z'; Year = 2026 }
        @{ Date = '2027-07-05T12:00:00Z'; Year = 2027 }
    )
    $Script:encodingCases = @(
        foreach ($zone in $Script:zoneCases) {
            foreach ($instant in $instantCases) {
                foreach ($mode in 'Full', 'Partial') {
                    foreach ($recurring in $false, $true) {
                        @{ Id = $zone.Id; Date = $instant.Date; Year = $instant.Year; Mode = $mode; Recurring = $recurring }
                    }
                }
            }
        }
    )
    $Script:legacyCases = @(
        foreach ($zone in $Script:zoneCases) {
            foreach ($instant in $instantCases) {
                @{ Id = $zone.Id; Date = $instant.Date }
            }
        }
    )
    # Hand-derived from the captured rules and local-year transition boundaries:
    # AUS Eastern: standard UTC+10 from April, daylight UTC+11 from October, so daylight applies at New Year.
    # Pacific 2007+: daylight UTC-07:00 from March, standard UTC-08:00 from November, so standard applies at New Year.
    # Morocco 2026: standard UTC+00:00 from September, daylight UTC+01:00 from March, so standard applies at New Year.
    # British Columbia 2027: fixed UTC-07:00; its daylight bias is ignored because the rule has no transitions.
    $Script:localYearCases = @(
        @{ Id = 'AUS Eastern Standard Time'; Utc = '2026-12-31T13:30:00Z'; Expected = 2027; Local = '2027-01-01 00:30 (UTC+11)' }
        @{ Id = 'AUS Eastern Standard Time'; Utc = '2026-12-31T12:30:00Z'; Expected = 2026; Local = '2026-12-31 23:30 (UTC+11)' }
        @{ Id = 'Pacific Standard Time'; Utc = '2027-01-01T05:00:00Z'; Expected = 2026; Local = '2026-12-31 21:00 (UTC-08)' }
        @{ Id = 'Pacific Standard Time'; Utc = '2027-01-01T08:30:00Z'; Expected = 2027; Local = '2027-01-01 00:30 (UTC-08)' }
        @{ Id = 'Pacific Standard Time'; Utc = '2027-01-01T07:30:00Z'; Expected = 2026; Local = '2026-12-31 23:30 (UTC-08)' }
        @{ Id = 'UTC'; Utc = '2026-12-31T23:59:59Z'; Expected = 2026; Local = '2026-12-31 23:59:59 (UTC)' }
        @{ Id = 'UTC'; Utc = '2027-01-01T00:00:00Z'; Expected = 2027; Local = '2027-01-01 00:00 (UTC)' }
        @{ Id = 'Morocco Standard Time'; Utc = '2026-12-31T23:30:00Z'; Expected = 2026; Local = '2026-12-31 23:30 (UTC+00)' }
        @{ Id = 'British Columbia Standard Time'; Utc = '2027-01-01T06:30:00Z'; Expected = 2026; Local = '2026-12-31 23:30 (UTC-07)' }
        @{ Id = 'British Columbia Standard Time'; Utc = '2027-01-01T07:30:00Z'; Expected = 2027; Local = '2027-01-01 00:30 (UTC-07)' }
        @{ Id = 'British Columbia Standard Time'; Utc = '2026-01-01T07:30:00Z'; Expected = 2025; Local = '2025-12-31 23:30 (UTC-08)' }
        @{ Id = 'British Columbia Standard Time'; Utc = '2026-01-01T07:59:59Z'; Expected = 2025; Local = '2025-12-31 23:59:59 (UTC-08)' }
        @{ Id = 'British Columbia Standard Time'; Utc = '2026-01-01T08:00:00Z'; Expected = 2026; Local = '2026-01-01 00:00 (UTC-08)' }
        @{ Id = 'British Columbia Standard Time'; Utc = '2027-01-01T07:00:00Z'; Expected = 2027; Local = '2027-01-01 00:00 (UTC-07)' }
    )
}

BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\EwsTransport.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\CalendarTimeZoneData.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\MigrationJournal.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Rehoming.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Reconcile.ps1

    $registryText = Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'Data\RegistryTimeZones.json') -Raw
    # Windows PowerShell emits a top-level JSON array as one object; enumerate it explicitly for both editions.
    $Script:registryZones = @(ConvertFrom-Json -InputObject $registryText | ForEach-Object { $_ })
    $Script:serverXml = New-Object Xml.XmlDocument
    $Script:serverXml.XmlResolver = $null
    $Script:serverXml.Load((Join-Path -Path $PSScriptRoot -ChildPath 'Data\ServerTimeZones.xml'))

    # The captured registry data replaces the machine registry, whose zone rules depend on the Windows patch level.
    Mock Get-ExOPRegistryTimeZoneRaw {
        $entry = @($Script:registryZones | Where-Object { $_.Id -ceq $Id })[0]
        [PSCustomObject]@{
            Id          = $entry.Id
            Tzi         = [Convert]::FromBase64String($entry.Tzi)
            Dynamic     = @(foreach ($year in @($entry.Dynamic)) {
                    [PSCustomObject]@{ Year = [int]$year.Year; Tzi = [Convert]::FromBase64String($year.Tzi) }
                })
            DisplayName = $entry.Id
        }
    }

    function Get-TestServerDefinition {
        param(
            [System.Xml.XmlNode]
            $Document,

            [string]
            $Id
        )
        $namespaces = Get-ExOPNamespaceManager -Node $Document
        @($Document.SelectNodes('//t:TimeZoneDefinition', $namespaces) | Where-Object { $_.GetAttribute('Id') -ceq $Id })
    }

    # Builds a 44-byte Windows TZI rule. A transition is @(Month, DayOfWeek, WeekOfMonth, Hour); month 0 means no transition.
    function New-TziBytes {
        param(
            [int]
            $Bias,

            [int]
            $StandardBias = 0,

            [int]
            $DaylightBias = 0,

            [int[]]
            $Standard = @(0, 0, 0, 0),

            [int[]]
            $Daylight = @(0, 0, 0, 0)
        )
        $stream = New-Object IO.MemoryStream
        $writer = New-Object IO.BinaryWriter($stream)
        try {
            foreach ($value in $Bias, $StandardBias, $DaylightBias) { $writer.Write([int32]$value) }
            foreach ($transition in @(, $Standard) + @(, $Daylight)) {
                foreach ($value in 0, $transition[0], $transition[1], $transition[2], $transition[3], 0, 0, 0) { $writer.Write([uint16]$value) }
            }
            $writer.Flush()
            Write-Output -InputObject $stream.ToArray() -NoEnumerate
        } finally {
            $writer.Dispose()
            $stream.Dispose()
        }
    }

    # Builds an O12 time zone definition with the header, rule size and reserved values that Outlook writes.
    function New-O12Blob {
        param(
            [string]
            $Name,

            [object[]]
            $Rules,

            [int]
            $RuleSize = 62
        )
        $nameBytes = [Text.Encoding]::Unicode.GetBytes($Name)
        $stream = New-Object IO.MemoryStream
        $writer = New-Object IO.BinaryWriter($stream)
        try {
            $writer.Write([byte]2)
            $writer.Write([byte]1)
            $writer.Write([uint16](6 + $nameBytes.Length))
            $writer.Write([uint16]2)
            $writer.Write([uint16]($nameBytes.Length / 2))
            $writer.Write($nameBytes)
            $writer.Write([uint16]$Rules.Count)
            foreach ($rule in $Rules) {
                $writer.Write([byte]2)
                $writer.Write([byte]1)
                $writer.Write([uint16]$RuleSize)
                $writer.Write([uint16]$rule.Flags)
                foreach ($value in $rule.Year, 1, 0, 1, 0, 0, 0, 0) { $writer.Write([uint16]$value) }
                $writer.Write([byte[]]$rule.Tzi)
            }
            $writer.Flush()
            [Convert]::ToBase64String($stream.ToArray())
        } finally {
            $writer.Dispose()
            $stream.Dispose()
        }
    }

    # Russian Standard Time as stored by Outlook on a real item: the second 2013 entry carries the 2014 registry rule.
    $seasonal2010 = New-TziBytes -Bias -180 -DaylightBias -60 -Standard @(10, 0, 5, 3) -Daylight @(3, 0, 5, 2)
    $seasonal2011 = New-TziBytes -Bias -180 -DaylightBias -60 -Standard @(1, 6, 1, 0) -Daylight @(3, 0, 5, 2)
    $seasonal2014 = New-TziBytes -Bias -180 -DaylightBias -60 -Standard @(10, 0, 5, 2) -Daylight @(1, 3, 1, 0)
    $Script:outlookRules = @(
        @{ Year = 1; Flags = 0; Tzi = $seasonal2010 }
        @{ Year = 2011; Flags = 0; Tzi = $seasonal2011 }
        @{ Year = 2012; Flags = 0; Tzi = (New-TziBytes -Bias -240) }
        @{ Year = 2013; Flags = 0; Tzi = (New-TziBytes -Bias -240) }
        @{ Year = 2013; Flags = 0; Tzi = $seasonal2014 }
        @{ Year = 2015; Flags = 2; Tzi = (New-TziBytes -Bias -180) }
    )
    $Script:outlookFullBlob = New-O12Blob -Name 'Russian Standard Time' -Rules $Script:outlookRules
    $Script:outlookPartialBlob = New-O12Blob -Name 'Russian Standard Time' -Rules @(@{ Year = 2015; Flags = 2; Tzi = (New-TziBytes -Bias -180) })
    # Registry-like definition: Dynamic DST years 2010 (first entry, year 1) through 2015; fixed years keep a -60 daylight bias.
    $Script:registryRussian = ConvertFrom-ExOPRegistryTimeZoneRaw -Raw ([PSCustomObject]@{
            Id          = 'Russian Standard Time'
            Tzi         = (New-TziBytes -Bias -180 -DaylightBias -60)
            Dynamic     = @(
                [PSCustomObject]@{ Year = 2010; Tzi = $seasonal2010 }
                [PSCustomObject]@{ Year = 2011; Tzi = $seasonal2011 }
                [PSCustomObject]@{ Year = 2012; Tzi = (New-TziBytes -Bias -240 -DaylightBias -60) }
                [PSCustomObject]@{ Year = 2013; Tzi = (New-TziBytes -Bias -240 -DaylightBias -60) }
                [PSCustomObject]@{ Year = 2014; Tzi = $seasonal2014 }
                [PSCustomObject]@{ Year = 2015; Tzi = (New-TziBytes -Bias -180 -DaylightBias -60) }
            )
            DisplayName = 'Russian Standard Time'
        })
}

Describe 'Testing CalendarTimeZoneData.ps1' {
    Context 'Helper functions are loaded' {
        It 'Defines <_>' -ForEach @('Get-ExOPTimezonePropertyMap', 'Get-ExOPMigrationReceipt', 'Get-ExOPPreparedTimeZoneProperties', 'Assert-ExOPTimeZoneProperties') {
            Get-Command -Name $_ -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Captured registry data replaces the machine registry' {
        It 'Builds British Columbia rules from the captured data' {
            $definition = Get-ExOPRegistryTimeZoneData -Id 'British Columbia Standard Time'
            $definition.Id | Should -BeExactly 'British Columbia Standard Time'
            $definition.Rules | Should -HaveCount 22
            $definition.Rules[0].Year | Should -Be 1
            $definition.Rules[1].Year | Should -Be 2007
            Should -Invoke Get-ExOPRegistryTimeZoneRaw -Times 1 -Exactly -Scope It -ParameterFilter { $Id -ceq 'British Columbia Standard Time' }
        }

        It 'Builds a single fixed rule for a zone without dynamic data' {
            $definition = Get-ExOPRegistryTimeZoneData -Id 'India Standard Time'
            $definition.Rules | Should -HaveCount 1
            $definition.Rules[0].Rule.Signature | Should -BeExactly 'Fixed|330'
        }
    }

    Context 'Client rules match the captured EWS definitions' {
        It '<Id> rules are equivalent to the server definition' -ForEach $Script:zoneCases {
            $node = @(Get-TestServerDefinition -Document $Script:serverXml -Id $Id)
            $node.Count | Should -Be 1
            $reference = Get-ExOPRegistryTimeZoneData -Id $Id
            $remote = ConvertFrom-ExOPServerTimeZoneData -Definition $node[0]
            { Assert-ExOPTimeZoneDefinitions -Client $reference -Server $remote } | Should -Not -Throw
        }

        It 'Rejects a server definition that disagrees with the client rules' {
            $copy = $Script:serverXml.CloneNode($true)
            $namespaces = Get-ExOPNamespaceManager -Node $copy
            $node = @(Get-TestServerDefinition -Document $copy -Id 'UTC')[0]
            $node.SelectSingleNode('t:Periods/t:Period', $namespaces).SetAttribute('Bias', 'PT1H')
            $fixed = Get-ExOPRegistryTimeZoneData -Id 'UTC'
            { Assert-ExOPTimeZoneDefinitions -Client $fixed -Server (ConvertFrom-ExOPServerTimeZoneData -Definition $node) } |
                Should -Throw -ExpectedMessage '*disagree*'
        }
    }

    Context 'Get-ExOPDefinitionLocalYear uses only the definition rules' {
        It '<Id> at <Utc> is local year <Expected> (<Local>)' -ForEach $Script:localYearCases {
            $definition = Get-ExOPRegistryTimeZoneData -Id $Id
            $instant = [DateTimeOffset]::Parse($Utc, [Globalization.CultureInfo]::InvariantCulture)
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc $instant | Should -Be $Expected
        }

        It 'Selects the preceding local year for partial O12 and legacy O11 definitions' {
            $definition = Get-ExOPRegistryTimeZoneData -Id 'British Columbia Standard Time'
            $instant = [DateTimeOffset]::Parse('2026-01-01T07:30:00Z', [Globalization.CultureInfo]::InvariantCulture)
            $encoded = New-ExOPO12Definition -Definition $definition -EffectiveUtc $instant -Mode Partial
            $parsed = Read-ExOPO12Definition -Base64 $encoded
            $parsed.Rules[0].Year | Should -Be 2025
            $parsed.Rules[0].Rule.Signature | Should -BeExactly (Get-ExOPRuleForYear -Definition $definition -Year 2025).Rule.Signature
            $legacy = [Convert]::FromBase64String((New-ExOPO11Definition -Definition $definition -EffectiveUtc $instant))
            [BitConverter]::ToUInt16($legacy, 16) | Should -Be 11
        }

        It 'Handles a transition inside January instead of inferring the season from month order' {
            $bytes = New-TziBytes -Bias 480 -DaylightBias -60 -Standard @(1, 4, 1, 2) -Daylight @(1, 0, 3, 2)
            $definition = ConvertFrom-ExOPRegistryTimeZoneRaw -Raw ([PSCustomObject]@{ Id = 'Test'; DisplayName = 'Test'; Tzi = $bytes; Dynamic = @() })
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2026-01-01T07:30:00Z') | Should -Be 2026
        }

        It 'Handles a fixed-date transition at midnight on January 1' {
            $bytes = New-TziBytes -Bias 480 -DaylightBias -60 -Standard @(1, 0, 1, 0) -Daylight @(3, 0, 2, 2)
            [Array]::Copy([BitConverter]::GetBytes([uint16]2026), 0, $bytes, 12, 2)
            $definition = ConvertFrom-ExOPRegistryTimeZoneRaw -Raw ([PSCustomObject]@{ Id = 'Test'; DisplayName = 'Test'; Tzi = $bytes; Dynamic = @() })
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2026-01-01T07:30:00Z') | Should -Be 2025
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2026-01-01T08:00:00Z') | Should -Be 2026
        }

        It 'Uses the captured base offset to select adjacent yearly rules' {
            $old = New-TziBytes -Bias -660
            $new = New-TziBytes -Bias -600
            $definition = ConvertFrom-ExOPRegistryTimeZoneRaw -Raw ([PSCustomObject]@{
                    Id = 'Test'; DisplayName = 'Test'; Tzi = $new
                    Dynamic = @([PSCustomObject]@{ Year = 2026; Tzi = $old }, [PSCustomObject]@{ Year = 2027; Tzi = $new })
                })
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2026-12-31T12:59:00Z') | Should -Be 2026
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2026-12-31T13:30:00Z') | Should -Be 2027
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2026-12-31T14:00:00Z') | Should -Be 2027
        }

        It 'Preserves the captured base offset independently of the final dynamic rule' {
            $definition = Get-ExOPRegistryTimeZoneData -Id 'British Columbia Standard Time'
            $definition.BaseOffset | Should -Be -480
            $definition.Rules[-1].Rule.StandardOffset | Should -Be -420
        }

        It 'Keeps the preceding daylight season until the base-offset year changes' {
            $old = New-TziBytes -Bias 0 -DaylightBias -60 -Standard @(2, 0, 5, 3) -Daylight @(4, 0, 1, 2)
            $new = New-TziBytes -Bias 0 -DaylightBias -60 -Standard @(9, 0, 3, 2) -Daylight @(3, 0, 4, 2)
            $definition = ConvertFrom-ExOPRegistryTimeZoneRaw -Raw ([PSCustomObject]@{
                    Id = 'Test'; DisplayName = 'Test'; Tzi = $new
                    Dynamic = @([PSCustomObject]@{ Year = 2025; Tzi = $old }, [PSCustomObject]@{ Year = 2026; Tzi = $new })
                })
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2025-12-31T23:30:00Z') | Should -Be 2026
        }

        It 'Handles a January daylight marker with <Name>' -ForEach @(
            @{ Name = 'no preceding base-offset adjustment'; BaseBias = -240; PreviousBias = -240; StandardBias = -180; DeltaBias = -60; Utc = '2013-12-31T20:59:00Z'; Expected = 2013 }
            @{ Name = 'a preceding fixed-offset adjustment'; BaseBias = -540; PreviousBias = -600; StandardBias = -480; DeltaBias = -120; Utc = '2013-12-31T15:59:00Z'; Expected = 2014 }
        ) {
            $base = New-TziBytes -Bias $BaseBias
            $old = New-TziBytes -Bias $PreviousBias
            $transition = New-TziBytes -Bias $StandardBias -DaylightBias $DeltaBias -Standard @(10, 0, 5, 2) -Daylight @(1, 3, 1, 0)
            $definition = ConvertFrom-ExOPRegistryTimeZoneRaw -Raw ([PSCustomObject]@{
                    Id = 'Test'; DisplayName = 'Test'; Tzi = $base
                    Dynamic = @(
                        [PSCustomObject]@{ Year = 2013; Tzi = $old }
                        [PSCustomObject]@{ Year = 2014; Tzi = $transition }
                        [PSCustomObject]@{ Year = 2015; Tzi = (New-TziBytes -Bias $StandardBias) }
                        [PSCustomObject]@{ Year = 2016; Tzi = $base }
                    )
                })
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]$Utc) | Should -Be $Expected
        }

        It 'Handles negative daylight adjustments at New Year' {
            $bytes = New-TziBytes -Bias -60 -DaylightBias 60 -Standard @(4, 0, 1, 2) -Daylight @(10, 0, 1, 2)
            $definition = ConvertFrom-ExOPRegistryTimeZoneRaw -Raw ([PSCustomObject]@{ Id = 'Test'; DisplayName = 'Test'; Tzi = $bytes; Dynamic = @() })
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2026-12-31T23:30:00Z') | Should -Be 2026
            Get-ExOPDefinitionLocalYear -Definition $definition -Utc ([DateTimeOffset]'2027-01-01T00:00:00Z') | Should -Be 2027
        }
    }

    Context 'O12 encoding round trip' {
        It '<Id> at <Date> mode <Mode> recurring <Recurring>' -ForEach $Script:encodingCases {
            $reference = Get-ExOPRegistryTimeZoneData -Id $Id
            $instant = [DateTimeOffset]::Parse($Date, [Globalization.CultureInfo]::InvariantCulture)
            $encoded = New-ExOPO12Definition -Definition $reference -EffectiveUtc $instant -Mode $Mode -Recurring:$Recurring
            $parsed = Read-ExOPO12Definition -Base64 $encoded
            $expectedCount = if ($Mode -eq 'Full') { $reference.Rules.Count } else { 1 }

            $parsed.RuleCount | Should -Be $expectedCount
            $parsed.Id | Should -BeExactly $Id
            $effective = @($parsed.Rules | Where-Object { ($_.Flags -band 2) -ne 0 })
            $effective | Should -HaveCount 1
            (($effective[0].Flags -band 1) -ne 0) | Should -Be $Recurring
            { Assert-ExOPO12Coverage -Stored $parsed -Reference $reference -FirstYear $Year -LastYear $Year } | Should -Not -Throw
            Get-ExOPO12Mode -Stored $parsed -Reference $reference -KnownMode $Mode -KnownHash $parsed.Hash | Should -BeExactly $Mode
        }

        It '<Id> at <Date> legacy O11 definition has 48 bytes' -ForEach $Script:legacyCases {
            $reference = Get-ExOPRegistryTimeZoneData -Id $Id
            $instant = [DateTimeOffset]::Parse($Date, [Globalization.CultureInfo]::InvariantCulture)
            [Convert]::FromBase64String((New-ExOPO11Definition -Definition $reference -EffectiveUtc $instant)) | Should -HaveCount 48
        }
    }

    Context 'O12 validation' {
        BeforeAll {
            $Script:fixedZone = Get-ExOPRegistryTimeZoneData -Id 'UTC'
            $instant = [DateTimeOffset]::Parse('2026-11-09T12:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
            $Script:fixedBlob = New-ExOPO12Definition -Definition $Script:fixedZone -EffectiveUtc $instant -Mode Full
        }

        It 'Reports a single-rule definition as ambiguous' {
            $parsed = Read-ExOPO12Definition -Base64 $Script:fixedBlob
            Get-ExOPO12Mode -Stored $parsed -Reference $Script:fixedZone | Should -BeExactly 'Ambiguous'
        }

        It 'Encodes a definition whose ID is unknown to Windows' {
            $definition = [PSCustomObject]@{ Id = 'Contoso Test Standard Time'; Rules = $Script:fixedZone.Rules; DisplayName = 'Contoso Test' }
            $instant = [DateTimeOffset]::Parse('2026-11-09T12:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
            (Read-ExOPO12Definition -Base64 (New-ExOPO12Definition -Definition $definition -EffectiveUtc $instant -Mode Full)).Id |
                Should -BeExactly 'Contoso Test Standard Time'
            [Convert]::FromBase64String((New-ExOPO11Definition -Definition $definition -EffectiveUtc $instant)) | Should -HaveCount 48
        }

        It 'Rejects a definition truncated to <_> bytes' -ForEach @(0, 8, 9, 14, 60) {
            $bytes = [Convert]::FromBase64String($Script:fixedBlob)
            $truncated = New-Object byte[] $_
            [Array]::Copy($bytes, $truncated, $_)
            { Read-ExOPO12Definition -Base64 ([Convert]::ToBase64String($truncated)) } | Should -Throw
        }

        It 'Rejects a partial recurring definition that cannot express future Morocco rules' {
            $morocco = Get-ExOPRegistryTimeZoneData -Id 'Morocco Standard Time'
            $instant = [DateTimeOffset]::Parse('2026-11-09T12:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
            $partial = Read-ExOPO12Definition -Base64 (New-ExOPO12Definition -Definition $morocco -EffectiveUtc $instant -Mode Partial -Recurring)
            { Assert-ExOPO12Coverage -Stored $partial -Reference $morocco -FirstYear 2026 -LastYear 2027 } |
                Should -Throw -ExpectedMessage '*cannot express*'
        }
    }

    Context 'O12 data written by Outlook' {
        It 'Parses the Russian Standard Time definition with a repeated year' {
            $stored = Read-ExOPO12Definition -Base64 $Script:outlookFullBlob
            $stored.Id | Should -BeExactly 'Russian Standard Time'
            $stored.RuleCount | Should -Be 6
            ($stored.Rules | ForEach-Object { $_.Year }) -join ',' | Should -BeExactly '1,2011,2012,2013,2013,2015'
            ($stored.Rules | ForEach-Object { $_.Flags }) -join ',' | Should -BeExactly '0,0,0,0,0,2'
        }

        It 'Keeps the registry 2014 rule that Outlook stored with the year 2013' {
            $stored = Read-ExOPO12Definition -Base64 $Script:outlookFullBlob
            $stored.Rules[4].Rule.Signature | Should -BeExactly (Get-ExOPRuleForYear -Definition $Script:registryRussian -Year 2014).Rule.Signature
            $stored.Rules[4].Rule.Signature | Should -BeExactly 'Seasonal|180|240|Week,10,0,5,2,0,0,0|Week,1,3,1,0,0,0,0'
        }

        It 'Normalizes fixed rules regardless of their daylight bias' {
            $stored = Read-ExOPO12Definition -Base64 $Script:outlookFullBlob
            $stored.Rules[2].Rule.Signature | Should -BeExactly 'Fixed|240'
            $stored.Rules[5].Rule.Signature | Should -BeExactly 'Fixed|180'
            (Get-ExOPRuleForYear -Definition $Script:registryRussian -Year 2015).Rule.Signature | Should -BeExactly 'Fixed|180'
            (Get-ExOPRuleForYear -Definition $Script:registryRussian -Year 2012).Rule.Signature | Should -BeExactly 'Fixed|240'
        }

        It 'Detects the full Russian definition as Full' {
            Get-ExOPO12Mode -Stored (Read-ExOPO12Definition -Base64 $Script:outlookFullBlob) -Reference $Script:registryRussian | Should -BeExactly 'Full'
        }

        It 'Detects the one-rule Russian companion as Partial' {
            $stored = Read-ExOPO12Definition -Base64 $Script:outlookPartialBlob
            $stored.RuleCount | Should -Be 1
            $stored.Rules[0].Year | Should -Be 2015
            $stored.Rules[0].Flags | Should -Be 2
            Get-ExOPO12Mode -Stored $stored -Reference $Script:registryRussian | Should -BeExactly 'Partial'
        }

        It 'Accepts a definition without an effective-rule flag' {
            $rules = @($Script:outlookRules | ForEach-Object { @{ Year = $_.Year; Flags = 0; Tzi = $_.Tzi } })
            (Read-ExOPO12Definition -Base64 (New-O12Blob -Name 'Russian Standard Time' -Rules $rules)).RuleCount | Should -Be 6
        }

        It 'Accepts a definition with several effective-rule flags' {
            $rules = @($Script:outlookRules | ForEach-Object { @{ Year = $_.Year; Flags = 3; Tzi = $_.Tzi } })
            $stored = Read-ExOPO12Definition -Base64 (New-O12Blob -Name 'Russian Standard Time' -Rules $rules)
            @($stored.Rules | Where-Object { ($_.Flags -band 2) -ne 0 }) | Should -HaveCount 6
        }

        It 'Rejects decreasing rule years' {
            $rules = @($Script:outlookRules[0], $Script:outlookRules[5], $Script:outlookRules[3])
            { Read-ExOPO12Definition -Base64 (New-O12Blob -Name 'Russian Standard Time' -Rules $rules) } |
                Should -Throw -ExpectedMessage 'O12 rule years are not in ascending order.'
        }

        It 'Rejects unsupported rule flag bits' {
            $rules = @(@{ Year = 2015; Flags = 4; Tzi = (New-TziBytes -Bias -180) })
            { Read-ExOPO12Definition -Base64 (New-O12Blob -Name 'Russian Standard Time' -Rules $rules) } |
                Should -Throw -ExpectedMessage 'Unsupported O12 timezone rule flags.'
        }

        It 'Rejects an unsupported rule size' {
            { Read-ExOPO12Definition -Base64 (New-O12Blob -Name 'Russian Standard Time' -Rules $Script:outlookRules -RuleSize 60) } |
                Should -Throw -ExpectedMessage 'Unsupported O12 timezone rule version.'
        }

        It 'Rejects an unsupported header version' {
            $bytes = [Convert]::FromBase64String($Script:outlookFullBlob)
            $bytes[0] = 3
            { Read-ExOPO12Definition -Base64 ([Convert]::ToBase64String($bytes)) } | Should -Throw -ExpectedMessage 'Unsupported O12 timezone header.'
        }

        It 'Rejects a rule count that does not match the length' {
            $bytes = [Convert]::FromBase64String($Script:outlookFullBlob)
            $countOffset = 8 + 2 * 'Russian Standard Time'.Length
            $bytes[$countOffset] = 5
            { Read-ExOPO12Definition -Base64 ([Convert]::ToBase64String($bytes)) } | Should -Throw -ExpectedMessage 'Invalid O12 timezone rule count or length.'
        }
    }

    Context 'Get-ExOPPreparedTimeZoneProperties' {
        BeforeAll {
            $Script:effectiveUtc = '2026-11-09T18:00:00Z'
            $Script:definitions = @{}
            foreach ($id in 'UTC', 'India Standard Time', 'Pacific Standard Time', 'British Columbia Standard Time') {
                $Script:definitions[$id] = Get-ExOPRegistryTimeZoneData -Id $id
            }
            $document = New-Object Xml.XmlDocument
            $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:CalendarItemType>Single</t:CalendarItemType></t:CalendarItem>')
            $Script:singleItem = $document.DocumentElement

            function New-DisplayProperty {
                param(
                    [string]
                    $PropertyId,

                    [string]
                    $Value
                )
                '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="' +
                $PropertyId + '" PropertyType="Binary"/><t:Value>' + $Value + '</t:Value></t:ExtendedProperty>'
            }

            function Invoke-PreparedProperty {
                param(
                    [string]
                    $From,

                    [string]
                    $To,

                    [ValidateSet('Full', 'Partial')]
                    [string]
                    $StoredMode
                )
                $instant = [DateTimeOffset]::Parse($Script:effectiveUtc, [Globalization.CultureInfo]::InvariantCulture)
                $stored = New-ExOPO12Definition -Definition $Script:definitions[$From] -EffectiveUtc $instant -Mode $StoredMode
                $values = [PSCustomObject]@{
                    StartZone = $From; EndZone = $From; NewStartZone = $To; NewEndZone = $To
                    StartUtc = $Script:effectiveUtc; EndUtc = '2026-11-09T19:00:00Z'
                    NewStartUtc = $Script:effectiveUtc; NewEndUtc = '2026-11-09T19:00:00Z'
                }
                $properties = @((New-DisplayProperty -PropertyId '33374' -Value $stored), (New-DisplayProperty -PropertyId '33375' -Value $stored))
                $prepared = Get-ExOPPreparedTimeZoneProperties -Properties $properties -Definitions $Script:definitions -Values $values -Item $Script:singleItem -Receipt $null
                [PSCustomObject]@{ Prepared = $prepared; Map = (Get-ExOPTimezonePropertyMap -Properties $prepared.Properties); StoredHash = (Read-ExOPO12Definition -Base64 $stored).Hash }
            }

            function Get-ExpectedEncoding {
                param(
                    [string]
                    $To,

                    [string]
                    $Mode
                )
                $instant = [DateTimeOffset]::Parse($Script:effectiveUtc, [Globalization.CultureInfo]::InvariantCulture)
                New-ExOPO12Definition -Definition $Script:definitions[$To] -EffectiveUtc $instant -Mode $Mode
            }
        }

        It 'Writes the full target form for an ambiguous source and a multi-rule target' {
            $outcome = Invoke-PreparedProperty -From 'UTC' -To 'Pacific Standard Time' -StoredMode Full
            $entry = $outcome.Prepared.O12Modes['33374']
            $entry.Mode | Should -BeExactly 'Full'
            $entry.SourceMode | Should -BeExactly 'Ambiguous'
            $entry.AssumedFull | Should -BeTrue
            $entry.BeforeRules | Should -Be 1
            $entry.Rules | Should -Be $Script:definitions['Pacific Standard Time'].Rules.Count
            $outcome.Map['33374'].Value | Should -BeExactly (Get-ExpectedEncoding -To 'Pacific Standard Time' -Mode Full)
            $outcome.Map['33374'].Value | Should -Not -BeExactly (Get-ExpectedEncoding -To 'Pacific Standard Time' -Mode Partial)
        }

        It 'Does not record an assumption for a single-rule target' {
            $outcome = Invoke-PreparedProperty -From 'UTC' -To 'India Standard Time' -StoredMode Full
            $entry = $outcome.Prepared.O12Modes['33375']
            $entry.Mode | Should -BeExactly 'Full'
            $entry.SourceMode | Should -BeExactly 'Ambiguous'
            $entry.AssumedFull | Should -BeFalse
            $entry.Rules | Should -Be 1
            (Get-ExpectedEncoding -To 'India Standard Time' -Mode Full) | Should -BeExactly (Get-ExpectedEncoding -To 'India Standard Time' -Mode Partial)
            $outcome.Map['33375'].Value | Should -BeExactly (Get-ExpectedEncoding -To 'India Standard Time' -Mode Full)
        }

        It 'Keeps a recognized <StoredMode> form without an assumption' -ForEach @(
            @{ StoredMode = 'Full' }
            @{ StoredMode = 'Partial' }
        ) {
            $outcome = Invoke-PreparedProperty -From 'Pacific Standard Time' -To 'British Columbia Standard Time' -StoredMode $StoredMode
            foreach ($key in '33374', '33375') {
                $entry = $outcome.Prepared.O12Modes[$key]
                $entry.Mode | Should -BeExactly $StoredMode
                $entry.SourceMode | Should -BeExactly $StoredMode
                $entry.AssumedFull | Should -BeFalse
            }
            $outcome.Map['33374'].Value | Should -BeExactly (Get-ExpectedEncoding -To 'British Columbia Standard Time' -Mode $StoredMode)
        }

        It 'Leaves an ambiguous value unchanged when the zone does not change' {
            $outcome = Invoke-PreparedProperty -From 'UTC' -To 'UTC' -StoredMode Full
            $entry = $outcome.Prepared.O12Modes['33374']
            $entry.Mode | Should -BeExactly 'Ambiguous'
            $entry.SourceMode | Should -BeExactly 'Ambiguous'
            $entry.AssumedFull | Should -BeFalse
            $entry.Hash | Should -BeExactly $outcome.StoredHash
        }
    }

    Context 'Resolve-ExOPWindowsTimeZoneId' {
        # Uses zones present on every supported Windows build; newer zones may be missing on build agents.
        It 'Returns the exact ID for <_>' -ForEach @('MOUNTAIN STANDARD TIME', 'pacific standard time', 'Pacific Standard Time') {
            $expected = if ($_ -like 'Mountain*') { 'Mountain Standard Time' } else { 'Pacific Standard Time' }
            Resolve-ExOPWindowsTimeZoneId -Id $_ | Should -BeExactly $expected
        }

        It 'Rejects an unknown ID' {
            { Resolve-ExOPWindowsTimeZoneId -Id 'Atlantis Standard Time' } | Should -Throw -ExpectedMessage "The time zone 'Atlantis Standard Time' does not exist on this computer.*"
        }
    }

    Context 'Get-ExOPPreparedTimeZoneProperties validates the stored source definition: <Name>' -ForEach @(
        @{ Name = 'a current single-rule Pacific definition'; From = 'Pacific Standard Time'; Stale = 'None'; StartUtc = '2026-03-15T18:00:00Z'; Throws = $false }
        @{ Name = 'a stale pre-2007 Pacific rule in March'; From = 'Pacific Standard Time'; Stale = 'Pre2007'; StartUtc = '2026-03-15T18:00:00Z'; Throws = $true }
        @{ Name = 'a stale pre-2007 Pacific rule in July, where both rules agree on the offset but not the rule'; From = 'Pacific Standard Time'; Stale = 'Pre2007'; StartUtc = '2026-07-15T17:00:00Z'; Throws = $true }
        @{ Name = 'British Columbia stored with the old Pacific rules after the change'; From = 'British Columbia Standard Time'; Stale = 'PacificRules'; StartUtc = '2027-01-20T18:00:00Z'; Throws = $true }
        @{ Name = 'British Columbia stored with its full current rules'; From = 'British Columbia Standard Time'; Stale = 'None'; StartUtc = '2027-01-20T18:00:00Z'; Throws = $false }
    ) {
        BeforeAll {
            $definitions = @{}
            foreach ($id in 'Pacific Standard Time', 'British Columbia Standard Time', 'UTC') { $definitions[$id] = Get-ExOPRegistryTimeZoneData -Id $id }
            $start = [DateTimeOffset]::Parse($StartUtc, [Globalization.CultureInfo]::InvariantCulture)
            $source = $definitions[$From]
            $storedDefinition = switch ($Stale) {
                'Pre2007' { [PSCustomObject]@{ Id = $source.Id; Rules = @($definitions['Pacific Standard Time'].Rules | Where-Object Year -LT 2007) } }
                'PacificRules' { [PSCustomObject]@{ Id = $source.Id; Rules = @($definitions['Pacific Standard Time'].Rules) } }
                default { $source }
            }
            $mode = if ($Stale -eq 'None' -and $From -like 'Pacific*') { 'Partial' } else { 'Full' }
            $stored = New-ExOPO12Definition -Definition $storedDefinition -EffectiveUtc $start -Mode $mode
            $properties = foreach ($key in '33374', '33375') {
                '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="' + $key +
                '" PropertyType="Binary"/><t:Value>' + $stored + '</t:Value></t:ExtendedProperty>'
            }
            $document = New-Object Xml.XmlDocument
            $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:CalendarItemType>Single</t:CalendarItemType></t:CalendarItem>')
            $end = $start.AddHours(1).ToString('o')
            # The validation depends only on the captured definitions; the exact target instants do not matter, and
            # the machine's own time zone data (which may lack newer zones) must not be used.
            $values = [PSCustomObject]@{
                StartZone = $From; EndZone = $From; NewStartZone = 'UTC'; NewEndZone = 'UTC'
                StartUtc = $StartUtc; EndUtc = $end; NewStartUtc = $StartUtc; NewEndUtc = $end
            }
            $Script:sourceError = ''
            try {
                $null = Get-ExOPPreparedTimeZoneProperties -Properties @($properties) -Definitions $definitions -Values $values -Item $document.DocumentElement -Receipt $null
            } catch { $Script:sourceError = $_.Exception.Message }
        }

        It 'Refuses only a definition that disagrees with the Windows rules' {
            if ($Throws) {
                $Script:sourceError | Should -BeLike "The time zone definition stored in the item differs from the current Windows rules of '$From'*no original item changes were made."
            } else { $Script:sourceError | Should -BeExactly '' }
        }
    }

    Context 'Get-ExOPPreparedTimeZoneProperties checks a numbered series through its local last year' {
        BeforeAll {
            $Script:numberedDefinitions = @{}
            foreach ($id in 'Pacific Standard Time', 'AUS Eastern Standard Time', 'British Columbia Standard Time') {
                $Script:numberedDefinitions[$id] = Get-ExOPRegistryTimeZoneData -Id $id
            }

            function Invoke-NumberedPreparation {
                param([string]$From, [string]$Day, [string]$StartDate, [string]$StartUtc, [string]$LastUtc)
                $document = New-Object Xml.XmlDocument
                $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:CalendarItemType>RecurringMaster</t:CalendarItemType>' +
                    '<t:Recurrence><t:WeeklyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>' + $Day + '</t:DaysOfWeek></t:WeeklyRecurrence>' +
                    '<t:NumberedRecurrence><t:StartDate>' + $StartDate + '</t:StartDate><t:NumberOfOccurrences>5</t:NumberOfOccurrences></t:NumberedRecurrence></t:Recurrence>' +
                    '<t:LastOccurrence><t:ItemId Id="last"/><t:Start>' + $LastUtc + '</t:Start></t:LastOccurrence></t:CalendarItem>')
                $start = [DateTimeOffset]::Parse($StartUtc, [Globalization.CultureInfo]::InvariantCulture)
                $definition = $Script:numberedDefinitions[$From]
                $properties = foreach ($key in '33374', '33375', '33376') {
                    '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="' + $key +
                    '" PropertyType="Binary"/><t:Value>' + (New-ExOPO12Definition -Definition $definition -EffectiveUtc $start -Mode Partial -Recurring:($key -eq '33376')) +
                    '</t:Value></t:ExtendedProperty>'
                }
                $values = [PSCustomObject]@{
                    StartZone = $From; EndZone = $From; NewStartZone = 'British Columbia Standard Time'; NewEndZone = 'British Columbia Standard Time'
                    StartUtc = $StartUtc; EndUtc = $start.AddHours(1).ToString('o')
                    NewStartUtc = $StartUtc; NewEndUtc = $start.AddHours(1).ToString('o')
                }
                Get-ExOPPreparedTimeZoneProperties -Properties @($properties) -Definitions $Script:numberedDefinitions -Values $values `
                    -Item $document.DocumentElement -Receipt $null -Now ([DateTimeOffset]::Parse('2026-11-03T12:00:00Z', [Globalization.CultureInfo]::InvariantCulture))
            }
        }

        It 'Requires the target rules of 2027 when the last occurrence is January 1, 2027 locally but 2026 in UTC' {
            # Fridays from December 4, 2026 at 09:00 Sydney summer time; the fifth occurrence is 2026-12-31T22:00Z.
            { Invoke-NumberedPreparation -From 'AUS Eastern Standard Time' -Day 'Friday' -StartDate '2026-12-04' -StartUtc '2026-12-03T22:00:00Z' -LastUtc '2026-12-31T22:00:00Z' } |
                Should -Throw -ExpectedMessage "*cannot express 'British Columbia Standard Time'*"
        }

        It 'Accepts a partial definition when the last occurrence is December 31, 2026 locally but 2027 in UTC' {
            # Thursdays from December 3, 2026 at 20:00 PST; the fifth occurrence is 2027-01-01T04:00Z.
            $prepared = Invoke-NumberedPreparation -From 'Pacific Standard Time' -Day 'Thursday' -StartDate '2026-12-03' -StartUtc '2026-12-04T04:00:00Z' -LastUtc '2027-01-01T04:00:00Z'
            $prepared.O12Modes['33376'].Mode | Should -BeExactly 'Partial'
            $prepared.O12Modes['33376'].Rules | Should -Be 1
        }
    }

    Context 'Get-ExOPPreparedTimeZoneProperties writes 33331 for a series as Exchange derives it from 33376' {
        BeforeAll {
            $Script:seriesStartUtc = '2025-06-04T17:00:00Z'
            $Script:seriesDefinitions = @{}
            foreach ($id in 'Pacific Standard Time', 'AUS Eastern Standard Time', 'British Columbia Standard Time') {
                $Script:seriesDefinitions[$id] = Get-ExOPRegistryTimeZoneData -Id $id
            }
            $document = New-Object Xml.XmlDocument
            $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '"><t:CalendarItemType>RecurringMaster</t:CalendarItemType>' +
                '<t:Recurrence><t:WeeklyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Wednesday</t:DaysOfWeek></t:WeeklyRecurrence>' +
                '<t:EndDateRecurrence><t:StartDate>2025-06-04</t:StartDate><t:EndDate>2027-12-29</t:EndDate></t:EndDateRecurrence></t:Recurrence></t:CalendarItem>')
            $Script:seriesItem = $document.DocumentElement

            function New-SeriesProperty {
                param([string]$PropertyId, [string]$Type, [string]$Value)
                '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '"><t:ExtendedFieldURI DistinguishedPropertySetId="Appointment" PropertyId="' +
                $PropertyId + '" PropertyType="' + $Type + '"/><t:Value>' + $Value + '</t:Value></t:ExtendedProperty>'
            }

            function Invoke-SeriesPreparation {
                param([string]$From, [string]$To, [ValidateSet('Full', 'Partial')][string]$StoredMode, [string]$Now)
                $start = [DateTimeOffset]::Parse($Script:seriesStartUtc, [Globalization.CultureInfo]::InvariantCulture)
                $definition = $Script:seriesDefinitions[$From]
                $properties = @(
                    New-SeriesProperty -PropertyId '33331' -Type 'Binary' -Value (New-ExOPO11Definition -Definition $definition -EffectiveUtc $start)
                    New-SeriesProperty -PropertyId '33332' -Type 'String' -Value $definition.DisplayName
                    New-SeriesProperty -PropertyId '33374' -Type 'Binary' -Value (New-ExOPO12Definition -Definition $definition -EffectiveUtc $start -Mode $StoredMode)
                    New-SeriesProperty -PropertyId '33375' -Type 'Binary' -Value (New-ExOPO12Definition -Definition $definition -EffectiveUtc $start -Mode $StoredMode)
                    New-SeriesProperty -PropertyId '33376' -Type 'Binary' -Value (New-ExOPO12Definition -Definition $definition -EffectiveUtc $start -Mode $StoredMode -Recurring)
                )
                $values = [PSCustomObject]@{
                    StartZone = $From; EndZone = $From; NewStartZone = $To; NewEndZone = $To
                    StartUtc = $Script:seriesStartUtc; EndUtc = '2025-06-04T18:00:00Z'
                    NewStartUtc = $Script:seriesStartUtc; NewEndUtc = '2025-06-04T18:00:00Z'
                }
                $prepared = Get-ExOPPreparedTimeZoneProperties -Properties $properties -Definitions $Script:seriesDefinitions -Values $values `
                    -Item $Script:seriesItem -Receipt $null -Now ([DateTimeOffset]::Parse($Now, [Globalization.CultureInfo]::InvariantCulture))
                [PSCustomObject]@{ Prepared = $prepared; Map = (Get-ExOPTimezonePropertyMap -Properties $prepared.Properties) }
            }

            function Get-O11 {
                param([string]$Zone, [string]$Utc)
                New-ExOPO11Definition -Definition $Script:seriesDefinitions[$Zone] -EffectiveUtc ([DateTimeOffset]::Parse($Utc, [Globalization.CultureInfo]::InvariantCulture))
            }
        }

        It 'Uses the rule in effect now, not the series start, with a full 33376 (bug D6)' {
            $outcome = Invoke-SeriesPreparation -From 'Pacific Standard Time' -To 'British Columbia Standard Time' -StoredMode Full -Now '2026-11-03T12:00:00Z'
            $outcome.Prepared.O12Modes['33376'].Mode | Should -BeExactly 'Full'
            $outcome.Map['33331'].Value | Should -BeExactly (Get-O11 -Zone 'British Columbia Standard Time' -Utc '2026-11-03T12:00:00Z')
            $outcome.Map['33331'].Value | Should -Not -BeExactly (Get-O11 -Zone 'British Columbia Standard Time' -Utc $Script:seriesStartUtc)
        }

        It 'Uses the single rule of a partial 33376' {
            $outcome = Invoke-SeriesPreparation -From 'Pacific Standard Time' -To 'AUS Eastern Standard Time' -StoredMode Partial -Now '2026-11-03T12:00:00Z'
            $outcome.Prepared.O12Modes['33376'].Rules | Should -Be 1
            $outcome.Map['33331'].Value | Should -BeExactly (Get-O11 -Zone 'AUS Eastern Standard Time' -Utc $Script:seriesStartUtc)
        }

        It 'Still rejects a partial 33376 that cannot express the target over the series range' {
            { Invoke-SeriesPreparation -From 'Pacific Standard Time' -To 'British Columbia Standard Time' -StoredMode Partial -Now '2026-11-03T12:00:00Z' } |
                Should -Throw -ExpectedMessage "*cannot express 'British Columbia Standard Time'*"
        }

        It 'Uses the rule of the new year after New Year' {
            $outcome = Invoke-SeriesPreparation -From 'Pacific Standard Time' -To 'British Columbia Standard Time' -StoredMode Full -Now '2027-01-03T12:00:00Z'
            $outcome.Map['33331'].Value | Should -BeExactly (Get-O11 -Zone 'British Columbia Standard Time' -Utc '2027-01-03T12:00:00Z')
            $outcome.Map['33331'].Value | Should -Not -BeExactly (Get-O11 -Zone 'British Columbia Standard Time' -Utc '2026-11-03T12:00:00Z')
        }

        It 'Refuses a series within one day of New Year when the target rules change at <Now>' -ForEach @(
            @{ Now = '2026-12-31T20:00:00Z' }
            @{ Now = '2027-01-01T20:00:00Z' }
        ) {
            { Invoke-SeriesPreparation -From 'Pacific Standard Time' -To 'British Columbia Standard Time' -StoredMode Full -Now $Now } |
                Should -Throw -ExpectedMessage '*within one day of New Year*No original item changes were made.'
        }

        It 'Does not refuse near New Year when the target rules do not change' {
            $outcome = Invoke-SeriesPreparation -From 'Pacific Standard Time' -To 'AUS Eastern Standard Time' -StoredMode Full -Now '2026-12-31T20:00:00Z'
            $outcome.Map['33331'].Value | Should -BeExactly (Get-O11 -Zone 'AUS Eastern Standard Time' -Utc '2026-12-31T20:00:00Z')
        }

        It 'Returns the properties in key order' {
            $outcome = Invoke-SeriesPreparation -From 'Pacific Standard Time' -To 'British Columbia Standard Time' -StoredMode Full -Now '2026-11-03T12:00:00Z'
            $keys = @($outcome.Prepared.Properties | ForEach-Object { ([xml]$_).DocumentElement.FirstChild.GetAttribute('PropertyId') })
            $keys -join ',' | Should -BeExactly '33331,33332,33374,33375,33376'
        }
    }
}
