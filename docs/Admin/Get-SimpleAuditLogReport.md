---
title: Get-SimpleAuditLogReport.ps1
parent: Admin
---

## Get-SimpleAuditLogReport

Download the latest release: [Get-SimpleAuditLogReport.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-SimpleAuditLogReport.ps1)

Exchange admin audit logs are not readily human readable.  All of the data needed to understand what Cmdlet has been run is in the data but it is not very easy to read.  Get-SimpleAuditLogReport will take the results of an audit log search and provide a significantly more human readable version of the data.

It will parse the audit log and attempt to reconstruct the actual Cmdlet that was run.

# Common Usage
`$Search = Search-AdminAuditLog`

`$search | C:\Scripts\Get-SimpleAuditLogReport.ps1 -agree`

# How to use
1. Gather admin audit log results using [Search-AdminAuditLog](https://docs.microsoft.com/en-us/powershell/module/exchange/search-adminauditlog?view=exchange-ps).
2. Pipe the results into the Get-SimpleAuditLogReport script.
3. Open the CSV file created in the same directory with the script.
