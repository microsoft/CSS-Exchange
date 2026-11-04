# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Render an already-redacted scalar as inert inline report text.

.DESCRIPTION
    Numeric character references neutralize HTML and Markdown punctuation
    before the value is wrapped in an inline code element. Redaction remains
    the caller's responsibility and must happen before invoking this function.

.PARAMETER RedactedText
    Scalar text with sensitive values already removed.
#>
function ConvertTo-DebugReportScalar {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RedactedText
    )

    $encoded = [regex]::Replace(
        $RedactedText,
        '[\x09\x0A\x0D\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]',
        { param($match) '&#' + [int][char]$match.Value + ';' })
    return '<code>' + $encoded + '</code>'
}
