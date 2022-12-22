# Clear-MailboxPermission

Download the latest release: [Get-MigrationReport.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-MigrationReport.ps1)

This is a PowerShell script that is used for generating reports related to mailbox migrations in Microsoft Exchange. The script accepts a mandatory parameter called -Identity, which should be an array of mailbox names. The script exports various types of reports as XML files, including:

- MoveRequest: A report containing information about the move request for the specified mailbox.
- MoveRequestStatistics: A report containing statistical information about the move request, including details about the number of items that were moved, failed, or are in a warning state.
- UserMigration
- UserMigrationStatistics
- MigrationBatch
- MigrationEndPoint
- MigrationConfig

The script also exports a report containing statistics for the specified mailbox, as well as a report containing the move history for the specified mailbox. Finally, the script logs any errors that occur during the export process to a log file called LogFile.txt.

## Common Usage

.EXAMPLE

`.\Get-MigrationReports -Identity Mustafa@contoso.com`

`.\Get-MigrationReports -Identity User1@contoso.com, user2@contoso.com, user3@contoso.com`




