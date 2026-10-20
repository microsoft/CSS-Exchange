# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Shared Calendar diagnostic infrastructure.

function Get-CalendarDiagnosticPermissionIdentity {
    param(
        [AllowNull()]
        [object]$PermissionUser
    )

    foreach ($propertyPath in @(
            @("ADRecipient", "PrimarySmtpAddress"),
            @("RecipientPrincipal", "PrimarySmtpAddress"),
            @("PrimarySmtpAddress")
        )) {
        $value = $PermissionUser
        foreach ($propertyName in $propertyPath) {
            if ($null -eq $value) {
                break
            }
            $property = $value.PSObject.Properties[$propertyName]
            $value = if ($null -ne $property) { $property.Value } else { $null }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            return ([string]$value).Trim().ToLowerInvariant()
        }
    }

    return ([string]$PermissionUser).Trim().ToLowerInvariant()
}

function ConvertTo-CalendarDiagnosticLogDateTime {
    param(
        [AllowNull()]
        [string]$Text,

        [switch]$PreferDayFirst
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    # Mailbox diagnostic logs use the administrator's regional format, so try both day-first and month-first layouts.
    [string[]]$dayFirstFormats = @("d/M/yyyy H:mm:ss", "d/M/yyyy h:mm:ss tt", "d/M/yyyy H:mm", "d/M/yyyy h:mm tt", "d/M/yyyy")
    [string[]]$monthFirstFormats = @("M/d/yyyy H:mm:ss", "M/d/yyyy h:mm:ss tt", "M/d/yyyy H:mm", "M/d/yyyy h:mm tt", "M/d/yyyy")
    $orderedFormats = if ($PreferDayFirst) { @($dayFirstFormats, $monthFirstFormats) } else { @($monthFirstFormats, $dayFirstFormats) }
    $invariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
    $parsedValue = [DateTime]::MinValue
    foreach ($formats in $orderedFormats) {
        if ([DateTime]::TryParseExact($Text.Trim(), $formats, $invariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedValue)) {
            return $parsedValue
        }
    }

    if ([DateTime]::TryParse($Text.Trim(), $invariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedValue)) {
        return $parsedValue
    }

    return $null
}

function Get-CalendarDiagnosticLogLineTimestamp {
    param(
        [AllowNull()]
        [string[]]$Line,

        [DateTime]$ReferenceTimeUtc = [DateTime]::UtcNow
    )

    $logLines = @($Line)
    $timestampPattern = '^\s*(?<Text>(?<First>\d{1,2})/(?<Second>\d{1,2})/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s+[AP]M)?),'
    $preferDayFirst = $false
    foreach ($logLine in $logLines) {
        # A first value above 12 can only be a day. Without such a value, month-first is assumed, as in the Exchange default.
        if (($logLine -match $timestampPattern) -and ([int]$Matches["First"] -gt 12)) {
            $preferDayFirst = $true
            break
        }
    }

    $timestamps = [object[]]::new($logLines.Count)
    for ($index = 0; $index -lt $logLines.Count; $index++) {
        if ($logLines[$index] -match $timestampPattern) {
            $timestampText = $Matches["Text"]
            $parsedValue = ConvertTo-CalendarDiagnosticLogDateTime -Text $timestampText -PreferDayFirst:$preferDayFirst
            if (($null -ne $parsedValue) -and ($parsedValue -gt $ReferenceTimeUtc.AddHours(1))) {
                # Prefer the reading that is not in the future when the day and month are ambiguous.
                $parsedValue = ConvertTo-CalendarDiagnosticLogDateTime -Text $timestampText -PreferDayFirst:(-not $preferDayFirst)
            }
            if (($null -ne $parsedValue) -and ($parsedValue -le $ReferenceTimeUtc.AddHours(1))) {
                $timestamps[$index] = [DateTime]::SpecifyKind($parsedValue, [System.DateTimeKind]::Utc)
            }
        }
    }

    return , $timestamps
}

function Get-CalendarDiagnosticLogLatestTimestamp {
    param(
        [AllowNull()]
        [string[]]$Line,

        [DateTime]$ReferenceTimeUtc = [DateTime]::UtcNow
    )

    $latestTimestamp = $null
    foreach ($timestamp in (Get-CalendarDiagnosticLogLineTimestamp -Line $Line -ReferenceTimeUtc $ReferenceTimeUtc)) {
        if (($null -ne $timestamp) -and (($null -eq $latestTimestamp) -or ($timestamp -gt $latestTimestamp))) {
            $latestTimestamp = $timestamp
        }
    }

    return $latestTimestamp
}

function Select-CalendarDiagnosticLogLineWithinDays {
    param(
        [AllowNull()]
        [string[]]$Line,

        [DateTime]$ReferenceTimeUtc = [DateTime]::UtcNow,

        [int]$MaximumAgeDays = 365
    )

    $logLines = @($Line)
    $timestamps = Get-CalendarDiagnosticLogLineTimestamp -Line $logLines -ReferenceTimeUtc $ReferenceTimeUtc
    $cutoff = $ReferenceTimeUtc.AddDays(-$MaximumAgeDays)
    $keptLines = [System.Collections.Generic.List[string]]::new()
    $omittedEntries = 0
    # Lines without a timestamp, such as stack traces, belong to the entry above them.
    $keepEntry = $true
    for ($index = 0; $index -lt $logLines.Count; $index++) {
        if ($null -ne $timestamps[$index]) {
            $keepEntry = ($timestamps[$index] -ge $cutoff)
            if (-not $keepEntry) {
                $omittedEntries++
            }
        }
        if ($keepEntry) {
            $keptLines.Add($logLines[$index])
        }
    }

    return [PSCustomObject]@{
        Line           = @($keptLines)
        OmittedEntries = $omittedEntries
    }
}

function ConvertTo-CalendarDiagnosticCommandLineValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return '$null'
    }

    if ($Value -is [array]) {
        $values = @($Value | ForEach-Object { ConvertTo-CalendarDiagnosticCommandLineValue -Value $_ })
        return "@($($values -join ', '))"
    }

    return "'$(([string]$Value).Replace("'", "''"))'"
}

function ConvertTo-CalendarDiagnosticFileNameStem {
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [ValidateRange(16, 128)]
        [int]$MaximumLength = 64
    )

    $trimCharacters = [char[]]@(' ', '.')
    $stem = ($Value.Split('@')[0] -replace '[<>:"/\\|?*\x00-\x1F]', '_').Trim($trimCharacters)
    if ([string]::IsNullOrWhiteSpace($stem) -or $stem -in @('.', '..')) {
        return "ResourceMailbox"
    }

    if ($stem.Length -gt $MaximumLength) {
        # Keep long identities (for example, distinguished names) within Windows path limits while staying unique per identity.
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant()))
        } finally {
            $sha256.Dispose()
        }
        $hashSuffix = ([System.BitConverter]::ToString($hashBytes, 0, 4) -replace '-', '').ToLowerInvariant()
        $prefix = $stem.Substring(0, $MaximumLength - $hashSuffix.Length - 1).TrimEnd($trimCharacters)
        $stem = "$prefix`_$hashSuffix"
    }
    return $stem
}

function ConvertTo-CalendarDiagnosticSafeErrorText {
    param(
        [AllowNull()]
        [object]$Value,

        [int]$MaximumLength = 2048
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        $text = [string]$Value
    } catch {
        return $null
    }

    $text = ($text -replace '[\r\n\t]+', ' ').Trim()
    if ($text.Length -gt $MaximumLength) {
        return $text.Substring(0, $MaximumLength)
    }
    return $text
}

function ConvertTo-CalendarDiagnosticPlainString {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return [string]$Value
    } catch {
        Write-Verbose "Unable to convert a report value of type '$($Value.GetType().FullName)' to a string."
        return $null
    }
}

function ConvertTo-CalendarDiagnosticPlainStringList {
    param(
        [AllowNull()]
        [object[]]$Value
    )

    return @($Value | ForEach-Object { ConvertTo-CalendarDiagnosticPlainString -Value $_ })
}

function ConvertTo-CalendarDiagnosticErrorInfo {
    param(
        [AllowNull()]
        [object]$ErrorRecord
    )

    $exception = $null
    if ($ErrorRecord -is [System.Exception]) {
        $exception = $ErrorRecord
    } elseif ($null -ne $ErrorRecord) {
        try {
            $exception = $ErrorRecord.PSObject.Properties['Exception'].Value
        } catch {
            $exception = $null
        }
    }

    $message = $null
    $exceptionType = $null
    $innerExceptionMessage = $null
    if ($null -ne $exception) {
        try {
            $message = ConvertTo-CalendarDiagnosticSafeErrorText -Value $exception.Message
        } catch {
            $message = $null
        }
        try {
            $exceptionType = ConvertTo-CalendarDiagnosticSafeErrorText -Value $exception.GetType().FullName -MaximumLength 256
        } catch {
            $exceptionType = $null
        }
        try {
            $innerExceptionMessage = ConvertTo-CalendarDiagnosticSafeErrorText -Value $exception.InnerException.Message -MaximumLength 1024
        } catch {
            $innerExceptionMessage = $null
        }
    }
    if ([string]::IsNullOrEmpty($message) -and $ErrorRecord -is [string]) {
        $message = ConvertTo-CalendarDiagnosticSafeErrorText -Value $ErrorRecord
    }
    if ([string]::IsNullOrEmpty($message)) {
        $message = "Unknown error."
    }

    $category = $null
    $fullyQualifiedErrorId = $null
    if ($null -ne $ErrorRecord) {
        try {
            $category = ConvertTo-CalendarDiagnosticSafeErrorText -Value $ErrorRecord.PSObject.Properties['CategoryInfo'].Value.Category -MaximumLength 256
        } catch {
            $category = $null
        }
        try {
            $fullyQualifiedErrorId = ConvertTo-CalendarDiagnosticSafeErrorText -Value $ErrorRecord.PSObject.Properties['FullyQualifiedErrorId'].Value -MaximumLength 256
        } catch {
            $fullyQualifiedErrorId = $null
        }
    }

    return [PSCustomObject]@{
        message               = $message
        exceptionType         = $exceptionType
        category              = $category
        fullyQualifiedErrorId = $fullyQualifiedErrorId
        innerExceptionMessage = $innerExceptionMessage
    }
}

function Get-CalendarDiagnosticFindingResult {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Detected", "NotDetected", "NotEvaluated", "NotApplicable")]
        [string]$Status,

        [Parameter(Mandatory)]
        [ValidateSet("Critical", "Error", "Warning", "Information")]
        [string]$Severity
    )

    switch ($Status) {
        "Detected" { if ($Severity -eq "Information") { return "Info" } else { return "Fail" } }
        "NotDetected" { return "Pass" }
        "NotEvaluated" { return "Inconclusive" }
        "NotApplicable" { return "Skipped" }
    }
}

function Add-CalendarDiagnosticFinding {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Findings,

        [Parameter(Mandatory)]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [ValidateSet("Critical", "Error", "Warning", "Information")]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet("Detected", "NotDetected", "NotEvaluated", "NotApplicable")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Title,

        [AllowNull()]
        [object]$Evidence
    )

    $effectiveEvidence = if ($Status -eq "NotEvaluated") { $null } else { $Evidence }
    $Findings.Add([PSCustomObject]@{
            ruleId   = $RuleId
            severity = $Severity
            status   = $Status
            result   = Get-CalendarDiagnosticFindingResult -Status $Status -Severity $Severity
            title    = $Title
            evidence = $effectiveEvidence
        })
}

function Write-CalendarDiagnosticJsonFile {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [int]$Depth = 8
    )

    $json = $InputObject | ConvertTo-Json -Depth $Depth -ErrorAction Stop
    # Windows PowerShell escapes the apostrophe, ampersand, and angle brackets as \uXXXX. Both forms are valid JSON, so use the readable
    # characters. An odd run of backslashes before the u means the backslash itself is escaped and must be left alone.
    $json = [regex]::Replace($json, '(?<!\\)((?:\\\\)*)\\u(0027|0026|003c|003e)', {
            param($match)
            $character = switch ($match.Groups[2].Value.ToLowerInvariant()) {
                "0027" { "'" }
                "0026" { "&" }
                "003c" { "<" }
                "003e" { ">" }
            }
            $match.Groups[1].Value + $character
        })
    $jsonFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($jsonFilePath, $json, [System.Text.UTF8Encoding]::new($false))
}
