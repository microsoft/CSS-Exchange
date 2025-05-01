# Update-OutlookLink

Download the latest release: [Update-OutlookLink.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Update-OutlookLink.ps1)

## Usage

Starting in July 2024, Microsoft changed the app name of Outlook for Windows as it appears in the Start menu from "Outlook" to "Outlook (classic)". This change became available starting in classic Outlook version 2407 and higher. Additional information is available for Tenant Admins in the M365 Service Health Dashboard in reference to message center post MC803006 and on [support.microsoft.com](https://support.microsoft.com/office/outlook-icon-on-the-start-menu-is-not-updated-to-outlook-classic-8e10e5c7-a33d-4c7e-8ca3-213fba1eff10).

The PowerShell Script will update the icon in both %ProgramData% and %AppData% automatically if needed. This makes it an option to run before updating to Office version 2407+.

PowerShell Script Options:

```powershell
.\Update-OutlookLink.ps1
```

If the user is not running elevated, it will warn them and ask if they want to continue.

It will attempt to lookup the users install language to use the correct translation of "classic".

After it runs it will describe what it did:

List of successful renames

List of unsuccessful renames

If you want to run this on a remote computer on the local network, you can use the following command:

```powershell
.\Update-OutlookLink.ps1 -ComputerName <ComputerName>
```
