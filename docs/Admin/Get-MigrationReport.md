# Get-MigrationReport

Download the latest release: [Get-MigrationReport.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-MigrationReport.ps1)

This is a PowerShell script that is used for generating reports related to mailbox migrations in Microsoft Exchange. The script accepts a mandatory parameter called -Identity, which should be an array of mailbox names. The script exports various types of reports as XML files, including:

- MoveRequest: A report containing information about the move request for the specified mailbox.
- MoveRequestStatistics: A report containing statistical information about the move request, including details about the number of items that were moved, failed, or are in a warning state.
- Summary report includes each unique failure and the detailed message for it.
- UserMigration
- UserMigrationStatistics
- MigrationBatch
- MigrationEndPoint
- MigrationConfig
- Summary report with the fialure and detailed message of each uniqe failure.

The script also exports a report containing statistics for the specified mailbox, as well as a report containing the move history for the specified mailbox. Finally, the script logs any errors that occur during the export process to a log file called LogFile.txt.

## How to Run
The script **must** be run as Administrator in PowerShell session on an Exchange Server or Exchange Online Powershell. Supported to run and collected logs against Exchange 2013 and greater and exchange Online. The intent of the script is to collect Migration logs only that you need from X move request quickly without needing to have to manually collect it yourself.

## Common Usage

.EXAMPLES:

`PS C:\> .\Get-MigrationReports -Identity Mustafa@contoso.com`

This command will run the script against the specified mailbox.

`PS C:\> .\Get-MigrationReports -Identity Mustafa@contoso.com, User2@contoso.com, User3@contoso.com`

This command will run the script against multiple mailboxes at once.