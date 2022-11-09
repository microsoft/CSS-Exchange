# Compare-MailboxStatistics

Download the latest release: [Compare-MailboxStatistics.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Compare-MailboxStatistics.ps1)

## Usage

This script compares two sets of mailbox statistics from the same database and highlights mailbox growth
that occurred between the two snapshots.

For a growing database, a typical approach would be to start by exporting the statistics for the database:

```powershell
Get-MailboxStatistics -Database DB1 | Export-CliXML C:\stats-before.xml
```

After the initial export is obtained, wait until significant growth is observed. That could mean
waiting an hour, or a day, depending on the scenario. At that point, compare the stats-before.xml
with the live data by using this script as follows:

```powershell
.\Compare-MailboxStatistics.ps1 -Before (Import-CliXml C:\stats-before.xml) -After (Get-MailboxStatistics -Database DB1)
```

This makes it easy to see which mailboxes grew the most.
