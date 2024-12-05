# Remove-DuplicateEntriesFromIanaMappings

Download the latest release: [Remove-DuplicateEntriesFromIanaMappings.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Remove-DuplicateEntriesFromIanaMappings.ps1)

## Description

After installing the Exchange Server November 2024 Security Update (SU) Version 1 or Version 2, you may encounter issues when the Exchange Server processes calendar-related information and files, such as `.iCal` or `.ics` attachments. Specifically, you may be unable to preview these files or add them to your calendar. This issue affects users who utilize Outlook on the Web (OWA) and the Exchange Active Sync (EAS) mail client on mobile devices. Additionally, this problem may impact Exchange Transport when processing emails that include `.iCal` or `.ics` file attachments.

More information about the issue can be found in the [Time zone exception occurs after installing Exchange Server November 2024 SU (Version 1 or Version 2)](https://support.microsoft.com/topic/time-zone-exception-occurs-after-installing-exchange-server-november-2024-su-version-1-or-version-2-851b3005-6d39-49a9-a6b5-5b4bb42a606f) knowledge base article. The `Remove-DuplicateEntriesFromIanaMappings.ps1` PowerShell script can be used to apply the workaround on one or multiple servers at once.

## Syntax

```powershell
Remove-DuplicateEntriesFromIanaMappings.ps1
  [-Server <string[]>]
  [-RestartServices <bool>]
  [-ScriptUpdateOnly <switch>]
  [-SkipVersionCheck <switch>]
```

## Usage

Copy the script to an Exchange server. Then, run it from there using an elevated Windows PowerShell or Exchange Management Shell (EMS).

**Examples:**

When you run the script in this manner, it will validate the `IanaTimeZoneMappings.xml` file located on the server `exch1.contoso.com`. The script will then identify and remove any duplicate entries found within the file:

```powershell
.\Remove-DuplicateEntriesFromIanaMappings.ps1 -Server exch1.contoso.com
```

When you run the script in this manner, it will validate and correct the `IanaTimeZoneMappings.xml` file on all Exchange servers that are returned by the `Get-ExchangeServer` command. The script will ensure that any duplicate entries within the file are identified and removed:

```powershell
Get-ExchangeServer | .\Remove-DuplicateEntriesFromIanaMappings.ps1
```

When you run the script in this manner, it will validate the `IanaTimeZoneMappings.xml` file on the server `exch1.contoso.com` and remove any duplicate entries. Additionally, it will restart the `W3SVC`, `WAS`, and `MSExchangeTransport` services:

```powershell
.\Remove-DuplicateEntriesFromIanaMappings.ps1 -Server exch1.contoso.com -RestartServices $true
```
