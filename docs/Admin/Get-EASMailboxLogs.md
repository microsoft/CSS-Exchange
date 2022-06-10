# Get-EASMailboxLogs

Download the latest release: [Get-EASMailboxLogs.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-EASMailboxLogs.ps1)

Used for when you need to get EAS Mailbox Logging over a long period of time. It will collect the logs and re-enable the Active Sync Logging enabled to avoid it being disabled after 72 hours.

## Syntax

```powershell
Get-EASMailboxLogs.ps1
  [-Mailbox <string[]>]
  [-OutputPath <string>]
  [-Interval <int>]
  [-EnableMailboxLoggingVerboseMode <bool>]
```

## Examples

The following example collects logs for two mailbox every hour:

```
.\Get-EASMailboxLogs.ps1 -mailbox @("jim","zeke") -OutputPath C:\EASLogs -interval 60
```

The following example collects logs for a mailbox:
```
.\Get-EASMailboxLogs.ps1 -Mailbox "jim" -OutputPath c:\EASLogs
```

The following example enables Verbose Logging on the current on premise server and collects logs for a mailbox:
```
.\Get-EASMailboxLogs.ps1 -Mailbox "jim" -OutputPath c:\EASLogs -EnableMailboxLoggingVerboseMode $true
```
