# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExOPByteHash {
    param (
        [byte[]]
        $Bytes
    )
    $hash = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '') }
    finally { $hash.Dispose() }
}

function ConvertFrom-ExOPRegistryRule {
    param (
        [byte[]]
        $Bytes
    )
    if ($Bytes.Length -ne 44) { throw 'A Windows timezone rule must contain exactly 44 bytes.' }
    $standard = @(for ($index = 12; $index -lt 28; $index += 2) { [BitConverter]::ToUInt16($Bytes, $index) })
    $daylight = @(for ($index = 28; $index -lt 44; $index += 2) { [BitConverter]::ToUInt16($Bytes, $index) })
    $bias = [BitConverter]::ToInt32($Bytes, 0)
    $standardBias = [BitConverter]::ToInt32($Bytes, 4)
    $daylightBias = [BitConverter]::ToInt32($Bytes, 8)
    $standardOffset = -$bias - $standardBias
    $daylightOffset = -$bias - $daylightBias
    if ($standardOffset -lt -1440 -or $standardOffset -gt 1440 -or
        $daylightOffset -lt -1440 -or $daylightOffset -gt 1440) { throw 'Invalid timezone bias.' }
    if ($standard[1] -eq 0 -and $daylight[1] -eq 0) {
        $signature = "Fixed|$standardOffset"
    } else {
        $parts = foreach ($transition in @($standard, $daylight)) {
            if ($transition[1] -notin 1..12 -or $transition[4] -gt 23 -or
                $transition[5] -gt 59 -or $transition[6] -gt 59 -or $transition[7] -gt 999) {
                throw 'Invalid timezone transition.'
            }
            $kind = if ($transition[0] -eq 0) { 'Week' } else { 'Date' }
            $dayOfWeek = if ($kind -eq 'Week') { $transition[2] } else { 0 }
            if (($kind -eq 'Week' -and ($transition[3] -notin 1..5 -or $dayOfWeek -gt 6)) -or
                ($kind -eq 'Date' -and $transition[3] -notin 1..31)) { throw 'Invalid timezone transition day.' }
            @($kind, $transition[1], $dayOfWeek, $transition[3], $transition[4], $transition[5], $transition[6], $transition[7]) -join ','
        }
        $signature = @('Seasonal', $standardOffset, $daylightOffset, $parts[0], $parts[1]) -join '|'
    }
    [PSCustomObject]@{
        Bytes = $Bytes; Standard = $standard; Daylight = $daylight
        StandardOffset = $standardOffset; DaylightOffset = $daylightOffset; Signature = $signature
    }
}

function Get-ExOPRegistryTimeZoneRaw {
    <#
        Reads the raw Windows registry definition. Kept separate so tests can supply captured data.
    #>
    param (
        [string]
        $Id
    )
    $null = [TimeZoneInfo]::FindSystemTimeZoneById($Id)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\' + $Id)
    if ($null -eq $key) { throw "Windows timezone registry data is missing for '$Id'." }
    $dynamic = $null
    try {
        $entries = New-Object 'System.Collections.Generic.List[object]'
        $dynamic = $key.OpenSubKey('Dynamic DST')
        if ($null -ne $dynamic) {
            $first = [int]$dynamic.GetValue('FirstEntry', 0)
            $last = [int]$dynamic.GetValue('LastEntry', 0)
            if ($first -lt 1601 -or $last -lt $first -or $last -gt 9999) { throw "Invalid Dynamic DST range for '$Id'." }
            for ($year = $first; $year -le $last; $year++) {
                $bytes = $dynamic.GetValue([string]$year, $null)
                if ($null -eq $bytes) { throw "Missing Dynamic DST year $year for '$Id'." }
                $entries.Add([PSCustomObject]@{Year = $year; Tzi = [byte[]]$bytes })
            }
        }
        [PSCustomObject]@{
            Id = $Id; Tzi = [byte[]]$key.GetValue('TZI'); Dynamic = $entries.ToArray()
            DisplayName = [TimeZoneInfo]::FindSystemTimeZoneById($Id).DisplayName
        }
    } finally {
        if ($null -ne $dynamic) { $dynamic.Dispose() }
        $key.Dispose()
    }
}

function ConvertFrom-ExOPRegistryTimeZoneRaw {
    param (
        $Raw
    )
    $rules = New-Object 'System.Collections.Generic.List[object]'
    $dynamic = @($Raw.Dynamic)
    if ($dynamic.Count -gt 0) {
        $first = [int]$dynamic[0].Year
        foreach ($entry in $dynamic) {
            $rules.Add([PSCustomObject]@{Year = $(if ([int]$entry.Year -eq $first) { 1 } else { [int]$entry.Year }); Rule = (ConvertFrom-ExOPRegistryRule -Bytes ([byte[]]$entry.Tzi)) })
        }
    } else {
        $rules.Add([PSCustomObject]@{Year = 1; Rule = (ConvertFrom-ExOPRegistryRule -Bytes ([byte[]]$Raw.Tzi)) })
    }
    [PSCustomObject]@{
        Id = $Raw.Id; Rules = $rules.ToArray(); DisplayName = $Raw.DisplayName
        BaseOffset = (ConvertFrom-ExOPRegistryRule -Bytes ([byte[]]$Raw.Tzi)).StandardOffset
    }
}

function Get-ExOPRegistryTimeZoneData {
    param (
        [string]
        $Id
    )
    ConvertFrom-ExOPRegistryTimeZoneRaw -Raw (Get-ExOPRegistryTimeZoneRaw -Id $Id)
}

function Get-ExOPRuleForYear {
    param (
        $Definition,

        [int]
        $Year
    )
    $rule = $null
    foreach ($candidate in $Definition.Rules) {
        if ($candidate.Year -le $Year) { $rule = $candidate } else { break }
    }
    if ($null -eq $rule) { throw "No timezone rule covers year $Year." }
    $rule
}

function Get-ExOPDefinitionLocalYear {
    <#
        Local calendar year of a UTC instant computed from the validated definition itself, so the result
        does not depend on the time zone data of the computer that runs the code.
    #>
    param (
        $Definition,

        [DateTimeOffset]
        $Utc
    )
    $utcDate = $Utc.UtcDateTime
    if (($utcDate.Month -ne 1 -or $utcDate.Day -ne 1) -and ($utcDate.Month -ne 12 -or $utcDate.Day -ne 31)) {
        $null = Get-ExOPRuleForYear -Definition $Definition -Year $utcDate.Year
        return $utcDate.Year
    }

    function Get-TransitionDate {
        param (
            [int[]]
            $Transition,

            [int]
            $Year
        )
        $month = $Transition[1]
        $days = [DateTime]::DaysInMonth($Year, $month)
        if ($Transition[0] -eq 0) {
            $firstDay = [DateTime]::new($Year, $month, 1)
            $day = 1 + (($Transition[2] - [int]$firstDay.DayOfWeek + 7) % 7) + 7 * ($Transition[3] - 1)
            if ($day -gt $days) { $day -= 7 }
        } else {
            $day = [Math]::Min($Transition[3], $days)
        }
        [DateTime]::new($Year, $month, $day, $Transition[4], $Transition[5], $Transition[6], $Transition[7])
    }

    function Get-YearRule {
        param (
            [int]
            $Year
        )
        $rule = (Get-ExOPRuleForYear -Definition $Definition -Year $Year).Rule
        $hasTransitions = $rule.Standard[1] -ne 0
        if ($hasTransitions) {
            $standard = Get-TransitionDate -Transition $rule.Standard -Year $Year
            $daylight = Get-TransitionDate -Transition $rule.Daylight -Year $Year
            if ($standard -eq $daylight) { throw 'Timezone transitions occur at the same local instant.' }
            $markers = @(
                foreach ($transition in @($rule.Daylight, $rule.Standard)) {
                    $transition[1] -eq 1 -and ($transition[0] -eq 0 -or $transition[3] -eq 1) -and
                    $transition[4] -eq 0 -and $transition[5] -eq 0 -and $transition[6] -eq 0
                }
            )
        } else {
            $daylight = [DateTime]::new($Year, 1, 1)
            $standard = $daylight.AddMilliseconds(1)
            $markers = @($true, $true)
        }
        [PSCustomObject]@{
            Rule = $rule; HasTransitions = $hasTransitions
            HasAdjustment  = $hasTransitions -or $rule.StandardOffset -ne $Definition.BaseOffset
            DaylightOffset = if ($hasTransitions) { $rule.DaylightOffset } else { $rule.StandardOffset }
            Standard = $standard; Daylight = $daylight; StartsWithDaylight = $markers[0]; EndsWithDaylight = $markers[1]
        }
    }

    $year = $utcDate.AddMinutes($Definition.BaseOffset).Year
    $current = Get-YearRule -Year $year
    $offset = $current.Rule.StandardOffset
    if ($current.HasTransitions) {
        $start = $current.Daylight.AddMinutes(-$current.Rule.StandardOffset)
        $end = $current.Standard.AddMinutes(-$current.Rule.DaylightOffset)
        $extended = $false
        # Windows uses January 1 midnight transitions as year-boundary markers. Adjacent rules can continue
        # daylight time across that boundary, including fixed offsets different from the zone's base offset.
        if ($current.StartsWithDaylight -and $year -gt 1) {
            $previous = Get-YearRule -Year ($year - 1)
            if ($previous.HasAdjustment -and ($previous.EndsWithDaylight -or $previous.Daylight -gt $previous.Standard)) {
                $start = $previous.Daylight.AddMinutes(-$previous.Rule.StandardOffset)
                $extended = $true
            } else {
                $start = [DateTime]::new($year, 1, 1).AddMinutes(-$current.Rule.StandardOffset)
            }
        }
        if ($current.EndsWithDaylight -and $year -lt 9999) {
            $next = Get-YearRule -Year ($year + 1)
            if ($next.HasAdjustment -and ($next.StartsWithDaylight -or
                    ($next.Standard -lt $next.Daylight -and -not $next.EndsWithDaylight))) {
                $end = if ($next.StartsWithDaylight -and $next.EndsWithDaylight) {
                    [DateTime]::new($year + 1, 12, 31).AddMinutes(-$next.DaylightOffset)
                } else { $next.Standard.AddMinutes(-$next.DaylightOffset) }
                $extended = $true
            } else {
                $end = [DateTime]::new($year + 1, 1, 1).AddTicks(-1).AddMinutes(-$current.Rule.DaylightOffset)
            }
        }
        $instant = $utcDate
        if (-not $extended) {
            $end = $end.AddYears($start.Year - $end.Year)
            $instant = $instant.AddYears($start.Year - $instant.Year)
        }
        $daylight = if ($start -gt $end) { $instant -lt $end -or $instant -ge $start }
        else { $instant -ge $start -and $instant -lt $end }
        if ($daylight) { $offset = $current.Rule.DaylightOffset }
    }
    $utcDate.AddMinutes($offset).Year
}

function ConvertFrom-ExOPServerTimeZoneData {
    param (
        [Xml.XmlNode]
        $Definition
    )
    $ns = Get-ExOPNamespaceManager -Node $Definition
    $periods = @{}
    foreach ($period in $Definition.SelectNodes('t:Periods/t:Period', $ns)) {
        $duration = [Xml.XmlConvert]::ToTimeSpan($period.GetAttribute('Bias'))
        if ($duration.Ticks % [TimeSpan]::TicksPerMinute -ne 0) { throw 'Sub-minute EWS timezone bias is not supported.' }
        $periods[$period.GetAttribute('Id')] = [PSCustomObject]@{Name = $period.GetAttribute('Name'); Bias = [int]$duration.TotalMinutes }
    }
    $groups = @{}
    foreach ($group in $Definition.SelectNodes('t:TransitionsGroups/t:TransitionsGroup', $ns)) {
        $transitions = @($group.ChildNodes | Where-Object NodeType -EQ ([Xml.XmlNodeType]::Element))
        if ($transitions.Count -eq 1 -and $transitions[0].LocalName -eq 'Transition') {
            $period = $periods[(Get-ExOPText -Node $transitions[0] -Path 't:To')]
            if ($null -eq $period) { throw 'EWS timezone references a missing period.' }
            $groups[$group.GetAttribute('Id')] = 'Fixed|' + (-$period.Bias)
            continue
        }
        if ($transitions.Count -ne 2) { throw 'Unsupported EWS timezone transition group.' }
        $parts = @{}
        $offsets = @{}
        foreach ($transition in $transitions) {
            $period = $periods[(Get-ExOPText -Node $transition -Path 't:To')]
            if ($null -eq $period -or $period.Name -notin 'Standard', 'Daylight') { throw 'Unsupported EWS timezone period role.' }
            $offsets[$period.Name] = -$period.Bias
            $time = [Xml.XmlConvert]::ToTimeSpan((Get-ExOPText -Node $transition -Path 't:TimeOffset'))
            if ($time.Ticks -lt 0 -or $time.TotalDays -ge 1) { throw 'Unsupported EWS transition time of day.' }
            $month = [int](Get-ExOPText -Node $transition -Path 't:Month')
            if ($transition.LocalName -eq 'RecurringDayTransition') {
                $day = [int](Get-ExOPText -Node $transition -Path 't:Occurrence')
                if ($day -eq -1) { $day = 5 }
                $dayOfWeek = [int][DayOfWeek]::Parse([DayOfWeek], (Get-ExOPText -Node $transition -Path 't:DayOfWeek'))
                $kind = 'Week'
            } elseif ($transition.LocalName -eq 'RecurringDateTransition') {
                $day = [int](Get-ExOPText -Node $transition -Path 't:Day')
                $dayOfWeek = 0
                $kind = 'Date'
            } else { throw "Unsupported EWS transition '$($transition.LocalName)'." }
            $parts[$period.Name] = @($kind, $month, $dayOfWeek, $day, $time.Hours, $time.Minutes, $time.Seconds, $time.Milliseconds) -join ','
        }
        if (-not $parts.ContainsKey('Standard') -or -not $parts.ContainsKey('Daylight')) { throw 'EWS timezone transition roles are incomplete.' }
        $groups[$group.GetAttribute('Id')] = @('Seasonal', $offsets.Standard, $offsets.Daylight, $parts.Standard, $parts.Daylight) -join '|'
    }
    $rules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($transition in $Definition.SelectNodes('t:Transitions/*', $ns)) {
        $to = $transition.SelectSingleNode('t:To', $ns)
        if ($null -eq $to -or $to.GetAttribute('Kind') -ne 'Group' -or -not $groups.ContainsKey($to.InnerText)) {
            throw 'Invalid EWS timezone group reference.'
        }
        if ($transition.LocalName -eq 'Transition') { $year = 1 }
        elseif ($transition.LocalName -eq 'AbsoluteDateTransition') {
            $date = [DateTime]::Parse((Get-ExOPText -Node $transition -Path 't:DateTime'), [Globalization.CultureInfo]::InvariantCulture)
            if ($date.Month -ne 1 -or $date.Day -ne 1 -or $date.TimeOfDay.Ticks -ne 0) {
                throw 'An EWS rule group does not start at a supported calendar-year boundary.'
            }
            $year = $date.Year
        } else { throw 'Unsupported EWS rule-group transition.' }
        $rules.Add([PSCustomObject]@{Year = $year; Rule = [PSCustomObject]@{Signature = $groups[$to.InnerText] } })
    }
    $ordered = @($rules | Sort-Object Year)
    if ($ordered.Count -eq 0 -or $ordered[0].Year -ne 1 -or @($ordered.Year | Sort-Object -Unique).Count -ne $ordered.Count) {
        throw 'Incomplete EWS timezone rule coverage.'
    }
    [PSCustomObject]@{Id = $Definition.GetAttribute('Id'); Rules = $ordered }
}

function Assert-ExOPTimeZoneDefinitions {
    param (
        $Client,

        $Server
    )
    if ($Client.Id -ine $Server.Id) { throw 'Timezone definition identities differ.' }
    foreach ($year in @(@($Client.Rules.Year) + @($Server.Rules.Year) | Sort-Object -Unique)) {
        $left = Get-ExOPRuleForYear -Definition $Client -Year $year
        $right = Get-ExOPRuleForYear -Definition $Server -Year $year
        if ($left.Rule.Signature -cne $right.Rule.Signature) {
            throw "Client/EWS timezone rules disagree for '$($Client.Id)' from year $year. No calendar writes are allowed."
        }
    }
}

function Get-ExOPValidatedTimeZoneData {
    param (
        $Session,

        [string]
        $Mailbox,

        [string[]]
        $Ids
    )
    $unique = @($Ids | Sort-Object -Unique)
    $nodes = @($unique | ForEach-Object { '<t:Id>' + (ConvertTo-ExOPXmlText -Value $_) + '</t:Id>' }) -join ''
    $response = Invoke-ExOPEwsRequest -Session $Session -Mailbox $Mailbox -ReadOnly -Body (
        '<m:GetServerTimeZones ReturnFullTimeZoneData="true"><m:Ids>' + $nodes + '</m:Ids></m:GetServerTimeZones>')
    $ns = Get-ExOPNamespaceManager -Node $response
    $result = @{}
    foreach ($id in $unique) {
        $matchesById = @($response.SelectNodes('//t:TimeZoneDefinition', $ns) | Where-Object { $_.GetAttribute('Id') -ieq $id })
        if ($matchesById.Count -ne 1) { throw "EWS did not return a unique full definition for '$id'." }
        $client = Get-ExOPRegistryTimeZoneData -Id $id
        $server = ConvertFrom-ExOPServerTimeZoneData -Definition $matchesById[0]
        Assert-ExOPTimeZoneDefinitions -Client $client -Server $server
        $result[$id] = $client
    }
    $result
}

function Read-ExOPO12Definition {
    param (
        [string]
        $Base64
    )
    $bytes = [Convert]::FromBase64String($Base64)
    if ($bytes.Length -lt 10 -or $bytes[0] -ne 2 -or $bytes[1] -ne 1) { throw 'Unsupported O12 timezone header.' }
    $size = [BitConverter]::ToUInt16($bytes, 2)
    $nameLength = [BitConverter]::ToUInt16($bytes, 6)
    $countOffset = 8 + 2 * $nameLength
    if ($size -ne 6 + 2 * $nameLength -or $countOffset + 2 -gt $bytes.Length) { throw 'Invalid O12 timezone header length.' }
    $name = [Text.Encoding]::Unicode.GetString($bytes, 8, 2 * $nameLength)
    $count = [BitConverter]::ToUInt16($bytes, $countOffset)
    if ($count -eq 0 -or $bytes.Length -ne $countOffset + 2 + 66 * $count) { throw 'Invalid O12 timezone rule count or length.' }
    $rules = New-Object 'System.Collections.Generic.List[object]'
    for ($index = 0; $index -lt $count; $index++) {
        $offset = $countOffset + 2 + 66 * $index
        if ($bytes[$offset] -ne 2 -or $bytes[$offset + 1] -ne 1 -or [BitConverter]::ToUInt16($bytes, $offset + 2) -ne 62) {
            throw 'Unsupported O12 timezone rule version.'
        }
        $flags = [BitConverter]::ToUInt16($bytes, $offset + 4)
        if (($flags -band 0xFFFC) -ne 0) { throw 'Unsupported O12 timezone rule flags.' }
        $tzi = New-Object byte[] 44
        [Array]::Copy($bytes, $offset + 22, $tzi, 0, 44)
        $year = [Math]::Max(1, [int][BitConverter]::ToUInt16($bytes, $offset + 6))
        $rules.Add([PSCustomObject]@{Year = $year; Flags = $flags; Rule = (ConvertFrom-ExOPRegistryRule -Bytes $tzi) })
    }
    # Real Outlook/Exchange data can repeat a year (for example a 2014 rule stored with year 2013) and can carry
    # no or several effective-rule flags. The stored rules are only used to recognize the full or partial form;
    # migrated definitions are always rebuilt from the registry, so only decreasing years are rejected.
    $years = @($rules.Year)
    for ($index = 1; $index -lt $years.Count; $index++) {
        if ($years[$index] -lt $years[$index - 1]) { throw 'O12 rule years are not in ascending order.' }
    }
    [PSCustomObject]@{Id = $name; Rules = $rules.ToArray(); RuleCount = $count; Hash = Get-ExOPByteHash -Bytes $bytes }
}

function Get-ExOPO12Mode {
    param (
        $Stored,

        $Reference,

        [string]
        $KnownMode,

        [string]
        $KnownHash
    )
    if ($Stored.Id -ine $Reference.Id) { throw 'The O12 key name differs from the declared endpoint timezone.' }
    if ($KnownMode -in 'Full', 'Partial' -and $KnownHash -ceq $Stored.Hash) { return $KnownMode }
    if ($Stored.RuleCount -gt 1) { return 'Full' }
    if ($Stored.Rules[0].Year -gt 1 -and $Reference.Rules.Count -gt 1) {
        $matching = @($Reference.Rules | Where-Object {
                $_.Year -eq $Stored.Rules[0].Year -and $_.Rule.Signature -ceq $Stored.Rules[0].Rule.Signature
            })
        if ($matching.Count -eq 1) { return 'Partial' }
    }
    'Ambiguous'
}

function New-ExOPO12Definition {
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Serializes documented timezone data in memory; performs no I/O.')]
    param (
        $Definition,

        [DateTimeOffset]
        $EffectiveUtc,

        [ValidateSet('Full', 'Partial')]
        [string]
        $Mode,

        [switch]
        $Recurring
    )
    $effective = Get-ExOPRuleForYear -Definition $Definition -Year (Get-ExOPDefinitionLocalYear -Definition $Definition -Utc $EffectiveUtc)
    $rules = @($Definition.Rules)
    if ($Mode -eq 'Partial') { $rules = @($effective) }
    $name = [Text.Encoding]::Unicode.GetBytes($Definition.Id)
    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter($stream)
    try {
        $writer.Write([byte]2); $writer.Write([byte]1)
        $writer.Write([uint16](6 + $name.Length)); $writer.Write([uint16]2)
        $writer.Write([uint16]($name.Length / 2)); $writer.Write($name); $writer.Write([uint16]$rules.Count)
        foreach ($rule in $rules) {
            $flags = if ($rule.Year -eq $effective.Year) { if ($Recurring) { 3 } else { 2 } } else { 0 }
            $writer.Write([byte]2); $writer.Write([byte]1); $writer.Write([uint16]62); $writer.Write([uint16]$flags)
            foreach ($value in $rule.Year, 1, 0, 1, 0, 0, 0, 0) { $writer.Write([uint16]$value) }
            $writer.Write([byte[]]$rule.Rule.Bytes)
        }
        $writer.Flush()
        [Convert]::ToBase64String($stream.ToArray())
    } finally { $writer.Dispose(); $stream.Dispose() }
}

function New-ExOPO11Definition {
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Serializes documented timezone data in memory; performs no I/O.')]
    param (
        $Definition,

        [DateTimeOffset]
        $EffectiveUtc
    )
    $rule = Get-ExOPRuleForYear -Definition $Definition -Year (Get-ExOPDefinitionLocalYear -Definition $Definition -Utc $EffectiveUtc)
    $bytes = New-Object byte[] 48
    [Array]::Copy($rule.Rule.Bytes, 0, $bytes, 0, 12)
    [Array]::Copy($rule.Rule.Bytes, 12, $bytes, 12, 2)
    [Array]::Copy($rule.Rule.Bytes, 12, $bytes, 14, 16)
    [Array]::Copy($rule.Rule.Bytes, 28, $bytes, 30, 2)
    [Array]::Copy($rule.Rule.Bytes, 28, $bytes, 32, 16)
    [Convert]::ToBase64String($bytes)
}

function Assert-ExOPO12Coverage {
    param (
        $Stored,

        $Reference,

        [int]
        $FirstYear,

        [int]
        $LastYear
    )
    $years = @(@($FirstYear, $LastYear) + @($Stored.Rules.Year) + @($Reference.Rules.Year) |
            Where-Object { $_ -ge $FirstYear -and $_ -le $LastYear } | Sort-Object -Unique)
    foreach ($year in $years) {
        $actual = if ($Stored.RuleCount -eq 1) { $Stored.Rules[0] } else { Get-ExOPRuleForYear -Definition $Stored -Year $year }
        $expected = Get-ExOPRuleForYear -Definition $Reference -Year $year
        if ($actual.Rule.Signature -cne $expected.Rule.Signature) {
            throw "The preserved O12 representation cannot express '$($Reference.Id)' correctly in year $year."
        }
    }
}

function Get-ExOPTimezonePropertyMap {
    param (
        [string[]]
        $Properties
    )
    $map = @{}
    foreach ($text in $Properties) {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.LoadXml($text)
        $property = $document.DocumentElement
        $field = $property.SelectSingleNode('t:ExtendedFieldURI', (Get-ExOPNamespaceManager -Node $property))
        if ($null -eq $field) { throw 'A timezone property has no field definition.' }
        $key = if ($field.HasAttribute('PropertyId')) { $field.GetAttribute('PropertyId') } else { $field.GetAttribute('PropertyName') }
        if (-not $key -or $map.ContainsKey($key)) { throw 'Duplicate or invalid timezone property identity.' }
        $map[$key] = [PSCustomObject]@{
            Xml   = $property.OuterXml
            Field = $field.OuterXml
            Value = Get-ExOPText -Node $property -Path 't:Value'
        }
    }
    $map
}

function Get-ExOPMigrationReceipt {
    param (
        [Xml.XmlNode]
        $Item
    )
    $node = $Item.SelectSingleNode(
        "t:ExtendedProperty[t:ExtendedFieldURI[@PropertyName='CalendarTimeZoneMigrationReceipt']]/t:Value",
        (Get-ExOPNamespaceManager -Node $Item))
    if ($null -eq $node) { return $null }
    $receipt = $node.InnerText | ConvertFrom-Json -ErrorAction Stop
    if ($receipt.SchemaVersion -ne 1 -or -not $receipt.OperationId -or -not $receipt.StateHash) {
        throw 'An invalid migration receipt requires manual review.'
    }
    $receipt
}

function Get-ExOPPreparedTimeZoneProperties {
    param (
        $Properties,

        $Definitions,

        $Values,

        [Xml.XmlNode]
        $Item,

        $Receipt,

        [DateTimeOffset]
        $Now = [DateTimeOffset]::UtcNow
    )
    $map = Get-ExOPTimezonePropertyMap -Properties $Properties
    $modes = @{}
    $preparedValues = @{}
    $series = (Get-ExOPText -Node $Item -Path 't:CalendarItemType') -eq 'RecurringMaster'
    $changedStart = $Values.StartZone -ine $Values.NewStartZone
    $changedEnd = $Values.EndZone -ine $Values.NewEndZone
    # 33331 is derived from the prepared 33376 below, so it is handled after the O12 properties.
    foreach ($key in @($map.Keys | Sort-Object { $_ -eq '33331' }, { $_ })) {
        $old = $map[$key]
        $value = $old.Value
        if (($key -eq 'StartTimeZoneIanaName' -and $changedStart) -or ($key -eq 'EndTimeZoneIanaName' -and $changedEnd)) {
            throw 'IANA-stamped timezone metadata requires explicit review; no original item changes were made.'
        }
        if ($key -in '33374', '33375', '33376') {
            $end = $key -eq '33375'
            $from = if ($end) { $Values.EndZone } else { $Values.StartZone }
            $to = if ($end) { $Values.NewEndZone } else { $Values.NewStartZone }
            $instant = if ($end) { $Values.NewEndUtc } else { $Values.NewStartUtc }
            $stored = Read-ExOPO12Definition -Base64 $value
            $known = $null
            if ($null -ne $Receipt -and $null -ne $Receipt.PSObject.Properties['O12Modes']) {
                $property = $Receipt.O12Modes.PSObject.Properties[$key]
                if ($null -ne $property) { $known = $property.Value }
            }
            $knownMode = if ($null -ne $known) { $known.Mode } else { '' }
            $knownHash = if ($null -ne $known) { $known.Hash } else { '' }
            $mode = Get-ExOPO12Mode -Stored $stored -Reference $Definitions[$from] -KnownMode $knownMode -KnownHash $knownHash
            $sourceMode = $mode
            $assumed = $false
            if ($from -ine $to) {
                $effectiveUtc = ConvertTo-ExOPInstant -Value $instant
                if ($mode -eq 'Ambiguous') {
                    # A single-rule source looks the same in both forms. The full form is a superset that is
                    # correct in every year; the assumption is recorded when it changes the written bytes.
                    $fullValue = New-ExOPO12Definition -Definition $Definitions[$to] -EffectiveUtc $effectiveUtc -Mode Full -Recurring:($key -eq '33376')
                    $partialValue = New-ExOPO12Definition -Definition $Definitions[$to] -EffectiveUtc $effectiveUtc -Mode Partial -Recurring:($key -eq '33376')
                    $mode = 'Full'
                    $assumed = $fullValue -cne $partialValue
                }
                $value = New-ExOPO12Definition -Definition $Definitions[$to] -EffectiveUtc $effectiveUtc `
                    -Mode $mode -Recurring:($key -eq '33376')
                $prepared = Read-ExOPO12Definition -Base64 $value
                $localYear = Get-ExOPDefinitionLocalYear -Definition $Definitions[$to] -Utc (ConvertTo-ExOPInstant -Value $instant)
                $firstYear = $localYear
                $lastYear = $localYear
                if ($series -and $key -eq '33376') {
                    $ns = Get-ExOPNamespaceManager -Node $Item
                    $startDate = Get-ExOPText -Node $Item -Path 't:Recurrence/t:*/t:StartDate'
                    $firstYear = [int]$startDate.Substring(0, 4)
                    $endDate = Get-ExOPText -Node $Item -Path 't:Recurrence/t:EndDateRecurrence/t:EndDate'
                    $last = Get-ExOPText -Node $Item -Path 't:LastOccurrence/t:Start'
                    # EndDate is a local date, LastOccurrence a UTC instant. Local dates are preserved, so the local
                    # year in the series' current zone is the last year the target rules must cover.
                    $lastYear = if ($endDate) { [int]$endDate.Substring(0, 4) }
                    elseif ($last) { Get-ExOPDefinitionLocalYear -Definition $Definitions[$from] -Utc (ConvertTo-ExOPInstant -Value $last) }
                    else { 9999 }
                    if ($null -eq $Item.SelectSingleNode('t:Recurrence', $ns)) { throw 'The recurring timezone has no recurrence range.' }
                }
                Assert-ExOPO12Coverage -Stored $prepared -Reference $Definitions[$to] -FirstYear $firstYear -LastYear $lastYear
            } else { $prepared = $stored }
            $modes[$key] = [PSCustomObject]@{
                Mode = $mode; SourceMode = $sourceMode; AssumedFull = $assumed; BeforeHash = $stored.Hash; Hash = $prepared.Hash
                BeforeRules = $stored.RuleCount; Rules = $prepared.RuleCount; From = $from; To = $to
            }
        } elseif ($key -eq '33331' -and $changedStart) {
            # Exchange compares a changed 33331 with the rule that 33376 has at the server's current time and, if
            # they differ, treats the update as coming from a legacy client and deletes 33374 and 33376
            # (FixRecurringTimeZone). Write the same rule Exchange itself would write.
            $o11EffectiveUtc = ConvertTo-ExOPInstant -Value $Values.NewStartUtc
            if ($series -and $modes.ContainsKey('33376') -and $modes['33376'].Rules -ne 1) {
                $target = $Definitions[$Values.NewStartZone]
                $years = @($Now.AddDays(-1), $Now.AddDays(1) | ForEach-Object { Get-ExOPDefinitionLocalYear -Definition $target -Utc $_ })
                if ((Get-ExOPRuleForYear -Definition $target -Year $years[0]).Rule.Signature -cne
                    (Get-ExOPRuleForYear -Definition $target -Year $years[1]).Rule.Signature) {
                    throw "Recurring series are not migrated within one day of New Year in '$($Values.NewStartZone)' because its rules change at the new year; run the script again after January 2. No original item changes were made."
                }
                $o11EffectiveUtc = $Now
            }
            $value = New-ExOPO11Definition -Definition $Definitions[$Values.NewStartZone] -EffectiveUtc $o11EffectiveUtc
        } elseif ($key -eq '33332' -and $changedStart) {
            $value = $Definitions[$Values.NewStartZone].DisplayName
        }
        $preparedValues[$key] = '<t:ExtendedProperty xmlns:t="' + $script:TypesNamespace + '">' + $old.Field +
        '<t:Value>' + (ConvertTo-ExOPXmlText -Value $value) + '</t:Value></t:ExtendedProperty>'
    }
    $result = @(foreach ($key in @($map.Keys | Sort-Object)) { $preparedValues[$key] })
    [PSCustomObject]@{Properties = $result; O12Modes = $modes }
}

function Assert-ExOPTimeZoneProperties {
    param (
        [string[]]
        $Expected,

        [string[]]
        $Actual
    )
    $before = Get-ExOPTimezonePropertyMap -Properties $Expected
    $after = Get-ExOPTimezonePropertyMap -Properties $Actual
    foreach ($key in $before.Keys) {
        if (-not $after.ContainsKey($key)) { throw "Timezone property $key disappeared during migration." }
        if ($before[$key].Value -cne $after[$key].Value) {
            throw "Timezone property $key did not retain the required value/representation."
        }
    }
}
