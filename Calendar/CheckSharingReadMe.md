# Check-SharingStatus source layout

This developer reference describes the source organization of [Check-SharingStatus.ps1](./Check-SharingStatus.ps1). For requirements, usage, and diagnostic guidance, see the [user documentation](../docs/Calendar/Check-SharingStatus.md).

## Source layout

The development entry script contains parameters, run initialization, the rule catalog, and diagnostic orchestration. Diagnostic functions are organized by responsibility:

| Source | Responsibility |
| --- | --- |
| [SharingCollectionUtilities.ps1](./Helpers/SharingCollectionUtilities.ps1) | Collector execution and evaluation error handling. |
| [SharingEvidenceUtilities.ps1](./Helpers/SharingEvidenceUtilities.ps1) | Evidence conversion, error redaction, and identity sanitization. |
| [SharingFindings.ps1](./Helpers/SharingFindings.ps1) | Finding registration and final status classification. |
| [SharingPrerequisites.ps1](./Helpers/SharingPrerequisites.ps1) | Mailbox and selected owner-calendar prerequisites. |
| [SharingLogParsers.ps1](./Helpers/SharingLogParsers.ps1) | Sharing invite, accept, and InternetCalendar log parsing. |
| [SharingOwnerDiagnostics.ps1](./Helpers/SharingOwnerDiagnostics.ps1) | Owner permissions, flags, and active-sharing information. |
| [SharingReceiverDiagnostics.ps1](./Helpers/SharingReceiverDiagnostics.ps1) | Receiver folder matching, sharing-model classification, and synchronization diagnostics. This cohesive routine is the exception to the roughly 500-line source-file target. |
| [SharingRelationshipChecks.ps1](./Helpers/SharingRelationshipChecks.ps1) | Calendar statistics comparison and explicit receiver delegate checks. |
| [SharingDiagnosticLogs.ps1](./Helpers/SharingDiagnosticLogs.ps1) | Diagnostic log collection, freshness, and exception detection. |
| [SharingPathUtilities.ps1](./Helpers/SharingPathUtilities.ps1) and [SharingIdentityUtilities.ps1](./Helpers/SharingIdentityUtilities.ps1) | Shared path, folder, flag, and permission identity utilities. |
| [Write-SharingSummary.ps1](./Writers/Write-SharingSummary.ps1) | Console summary of findings and incomplete checks. |
| [Write-SharingResults.ps1](./Writers/Write-SharingResults.ps1) | Permission summaries and JSON report serialization. |

Permission identity, error normalization, log timestamp parsing, and JSON file writing use the same [CalendarDiagnosticHelpers.ps1](./CalendarHelpers/CalendarDiagnosticHelpers.ps1) infrastructure as RBA diagnostics, and the Exchange Online connection check uses [Test-CalendarExoConnection.ps1](./CalendarHelpers/Test-CalendarExoConnection.ps1). Sharing-specific error redaction, finding schemas, and collection failure behavior remain unchanged. The release build embeds the dependencies into the standalone script; users do not need to download the helper files separately.

Invitation logs are parsed by their field labels rather than as CSV, preserving commas and apostrophes in mailbox display names. Malformed invitation entries make the invite check unavailable instead of producing shifted columns or a confirmed missing-invite finding. The original log text remains available in sensitive-data JSON reports for investigation.
