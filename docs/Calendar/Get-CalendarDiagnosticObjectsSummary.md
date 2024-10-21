# Get-CalendarDiagnosticObjectsSummary

Download the latest release: [Get-CalendarDiagnosticObjectsSummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-CalendarDiagnosticObjectsSummary.ps1)


This script runs the Get-CalendarDiagnosticObjects cmdlet and returns a summarized timeline of actions into clear English. It will also output an easier to read version of the CalLogs (enhanced) as well as a Raw copy of the logs for Developers. 

To run the script, you will need a valid SMTP Address for a user and a meeting Subject or MeetingID.

The script will display summarized timeline of actions and save the logs returned in csv format in the current directory.
New **-ExportToExcel** highly recommended for ease of use (all logs in one file, color coding, etc.). First time use will request installing the ImportExcel module. See https://github.com/dfinke/ImportExcel for more information on the ImportExcel module.

| Parameters:    | Explanation: |
|:-------------- | :-----|
| **-Identity**  | One (or more) SMTP Address of EXO User Mailbox to query.|
| **-Subject**   | Subject of the meeting to query, only valid if Identity is a single user. 
| **-MeetingID** | MeetingID of the meeting to query. <BR> - Preferred way to get CalLogs.
| **-TrackingLogs** | Populate attendee tracking columns in the output. <BR> - Only useable with the MeetingID parameter.
| **-Exceptions** | Include Exception objects in the output. <br> - Only useable with the MeetingID parameter. <br> 
| **-ExportToExcel**|   - `[NEW Feature]` Export the output to an Excel file with formatting.  <BR> - Running the script for multiple users will create three tabs in the Excel file for each user. <BR> If you want to add more users to the Excel file, close the file and rerun with new user. <BR>        - one tab for Enhanced CalLog         <BR>  - one tab for the TimeLine        <BR>  - Tab one for Raw CalLog 
| **-CaseNumber** | Case Number to include in the Filename of the output. <BR> - PrePend `<CaseNumber>_` to filename.
| **-ShortLogs**| Limit Logs to 500 instead of the default 2000, in case the server has trouble responding with the full logs.
---

#### Syntax:

Example to return timeline for a user with MeetingID:
```PowerShell
.\Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -MeetingID 040000008200E00074C5B7101A82E0080000000010E4301F9312D801000000000000000010000000996102014F1D484A8123C16DDBF8603E
```

Example to return timeline for a user with Subject:

```PowerShell
.\Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -Subject Test_OneTime_Meeting_Subject
```
Get CalLogs for 3 users:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity User1, User2, Delegate -MeetingID $MeetingID
```
Add Tracking Logs and Exceptions:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -TrackingLogs -Exceptions
```
Export CalLogs to Excel:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -TrackingLogs -Exceptions -ExportToExcel -CaseNumber 123456
```
Will create file like  `.\123456_CalLogSummary_<MeetingID>.xlsx` in current directory.


More Documentation on collecting CalLogs and Analyzing them:
 [How to Get Calendar Logs](https://aka.ms/GetCalLogs)
 [How to Analyze Calendar Logs](https://aka.ms/AnalyzeCalLogs)
