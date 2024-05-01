# Get-CalendarDiagnosticObjectsSummary

Download the latest release: [Get-CalendarDiagnosticObjectsSummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-CalendarDiagnosticObjectsSummary.ps1)


This script runs the Get-CalendarDiagnosticObjects script and returns a summarized timeline of actions into clear english.
To run the script, you will need a valid SMTP Address for a user and a meeting Subject or MeetingID.

The script will display summarized timeline of actions and save the logs returned is csv format in the current directory.


#### Syntax:

Example to return timeline for a user with MeetingID
```PowerShell
.\Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -MeetingID 040000008200E00074C5B7101A82E0080000000010E4301F9312D801000000000000000010000000996102014F1D484A8123C16DDBF8603E
```

Example to return timeline for a user with Subject

```PowerShell
.\Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -Subject Test_OneTime_Meeting_Subject
```

