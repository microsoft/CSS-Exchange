# Check-SharingStatus

Download the latest release: [Check-SharingStatus.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Check-SharingStatus.ps1)

This script runs a variety of PowerShell cmdlets to validate the sharing relationship between two users.

Terminology:
    Owner - this is the mailbox that owns the Calendar being shared.
    Receiver - this is the mailbox 'viewing' the owner calendar. 

First item is to determine what kind of sharing relationship the users have.
    Modern Sharing (New Model Sharing) - Recipient gets a replicated copy of the Owners Calendar in their MB
    Old Model Sharing – Recipient is granted rights but have so connect to the Owners server to get Calendar information. 
    External Sharing – Can be New or Old Model sharing, but outside of the Exchange Online Tenant / Organization. 
    Publishing – Owner publishes a link to their calendar, which clients can pull. 

Next you need to determine if the relationship is healthy. 
    Look at the logs and output included in the script.

Last you need to look at how it is working.  Generally, you will get Calendar Logs from Owner and Receiver for a copied meeting and check replication times, etc.
    See [CalLogSummaryScript](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-CalendarDiagnosticObjectsSummary.ps1) 
