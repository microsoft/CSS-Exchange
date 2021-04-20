---
title: Get-MRMDetails.ps1
parent: Retention
---

## Get-MRMDetails.ps1

Download the latest release: [Get-MRMDetails.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-MRMDetails.ps1)

This script will gather the MRM configuration for a given user. It will collect the current MRM Policy and Tags for the Exchange Organization, the current MRM Policy and Tags applied to the user, the current Exchange Diagnostics Logs for the user, and Exchange Audit logs for the mailbox selected.  The resulting data will allow you to see what tags are applied to the user and when the Managed Folder Assistant has run against the user. It also will grab the Admin Audit log so that we can tell if the Tags or Polices have been modified and who modified them.

To run the script, at minimum you will need a valid SMTP Address for a user. Then you can review the associated logs that are generated from the script.

Syntax:

```PowerShell
.\Get-MRMDetails.ps1 -Mailbox <user>
```

Example to collect the MRM Details from rob@contoso.com:

```PowerShell
.\Get-MRMDetails.ps1 -Mailbox rob@contoso.com
```
