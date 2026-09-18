# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cspell:ignore Goid

# .SYNOPSIS
# Collects and summarizes Resource Booking Assistant configuration, permissions, and diagnostic log evidence.
#
# .DESCRIPTION
# Collects Exchange resource-mailbox, CalendarProcessing, permission, inbox-rule, Place, and RBA diagnostic-log
# evidence. It produces a human-readable summary, a structured JSON report, and a readable RBA log file when
# diagnostic log evidence is available. Mailbox existence and resource type are validated before the remaining
# collectors run; after that validation, independent collectors continue after non-fatal failures.
#
# Use Subject to locate recent retained RBA processing by a case-insensitive subject substring. The script extracts
# meeting IDs from matching blocks and then correlates processing by meeting ID. If the subject resolves to multiple
# IDs, each meeting is reported separately. Use MeetingId to target one clean global object ID directly.
#
# .PARAMETER Identity
# Identity of the room or equipment mailbox to query. An SMTP address is recommended.
#
# .PARAMETER Subject
# Case-insensitive literal subject substring used to discover retained meeting processing. After meeting IDs are
# extracted, correlation uses those IDs. Subject cannot be combined with MeetingId. MeetingSubject remains an alias.
#
# .PARAMETER MeetingId
# Clean global object ID used to select retained RBA processing directly. A comma after the documented 040000008
# prefix is normalized for correlation. MeetingId cannot be combined with Subject.
#
# .PARAMETER IncludeSensitiveData
# Includes full-fidelity identities, complete RBA log content, and transcript content in the JSON report. Without
# this switch, identities are sanitized; Subject and MeetingId searches still include targeted sensitive evidence.
#
# .PARAMETER SkipVersionCheck
# Skips the automatic script update check. Intended primarily for controlled testing.
#
# .EXAMPLE
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com
#
# Collects a standard sanitized report for the resource mailbox.
#
# .EXAMPLE
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com -Verbose
#
# Collects a standard report and displays additional configuration explanations.
#
# .EXAMPLE
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com -Subject "Quarterly planning"
#
# Searches retained RBA logs for the subject, extracts meeting IDs, and reports each resolved meeting separately.
#
# .EXAMPLE
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com -MeetingId "04000000800E00074C5A7101A82E00700000000..."
#
# Searches retained RBA logs directly for one meeting ID.
#
# .EXAMPLE
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com -IncludeSensitiveData
#
# Includes complete identities, RBA log evidence, and transcript content in the JSON report. Handle the generated
# files as sensitive customer data.
#
# .OUTPUTS
# Creates timestamp-correlated text summary and JSON report files in the current directory. When RBA diagnostic log
# evidence is available, also creates a readable RBA log text file. The script writes progress to the host.
#
# .NOTES
# The targeted meeting and full reports can contain meeting subjects, identities, timestamps, and processing details.
# Review collectionErrors, evaluationErrors, and NotEvaluated findings before relying on a partial report.

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Identity,

    [Alias("MeetingSubject")]
    [ValidateNotNullOrEmpty()]
    [string]$Subject,

    [ValidateNotNullOrEmpty()]
    [string]$MeetingId,

    [switch]$IncludeSensitiveData,

    [switch]$SkipVersionCheck
)

. $PSScriptRoot\CalendarHelpers\CalendarDiagnosticHelpers.ps1
. $PSScriptRoot\RBAHelpers\RBACollectionHelpers.ps1
. $PSScriptRoot\RBAHelpers\RBAEvaluationHelpers.ps1
. $PSScriptRoot\RBAHelpers\RBALogHelpers.ps1
. $PSScriptRoot\RBAHelpers\RBAReportHelpers.ps1
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\RBAHelpers\Invoke-RbaSummary.ps1

Invoke-RbaSummary @PSBoundParameters
