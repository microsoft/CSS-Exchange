# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Generic Calendar diagnostic infrastructure; consider promoting this file to Shared in the future.

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
        [string]$Value
    )

    $stem = ($Value.Split('@')[0] -replace '[<>:"/\\|?*\x00-\x1F]', '_').Trim([char[]]@(' ', '.'))
    if ([string]::IsNullOrWhiteSpace($stem) -or $stem -in @('.', '..')) {
        return "ResourceMailbox"
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
    $jsonFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($jsonFilePath, $json, [System.Text.UTF8Encoding]::new($false))
}
