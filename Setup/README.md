# [SetupAssist.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupAssist.ps1)

Download the latest release here: [https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupAssist.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupAssist.ps1)

This script is meant to be run on the system where you are running setup from. It currently checks and displays the following when just running it:

- Current Logged on User and SID
- Are you running as an Administrator
- Member of `Domain Admins`
- Member of `Schema Admins`
- Member of `Enterprise Admins`
- Member of `Organization Management`
- Current PowerShell Execution Policy setting
- Checks to see if you are missing files in the installer cache (only checks to see if they are there, not if they are valid)
- More than 1 powershell.exe process up and running
- If reboot pending. (Add -Verbose to see where)
- The current AD level of readiness for CU upgrading. Displays warnings if a mismatch is detected.

Additional Parameters are used for when they are called out from the `SetupLogReviewer.ps1`

Parameter | Description
----------|------------
[string]OtherWellKnownObjects | Tests for deleted objects in the otherWellKnownObjects attribute

# [SetupLogReviewer.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupLogReviewer.ps1)

Download the latest release here: [https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupLogReviewer.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupLogReviewer.ps1)

This script is meant to be run against the Exchange Setup Logs located at `C:\ExchangeSetupLogs\ExchangeSetup.log`. You can run this on the server, or on a personal computer.

It currently checks for common prerequisite issues, clearly calling out if you need up run /PrepareAD in your environment and calls out where it needs to be run. It also checks for some other common issue that we have seen in support that we call out and display the actions to the screen.

Parameter | Description
----------|------------
[string]SetupLog | The location of the Exchange Setup Log that needs to be reviewed
[switch]DelegatedSetup | Use this switch if you are troubleshooting Prerequisites of a Delegated Setup issue

# [CopyMissingDlls.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/CopyMissingDlls.ps1)

Download the latest release here: [https://github.com/microsoft/CSS-Exchange/releases/latest/download/CopyMissingDlls.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/CopyMissingDlls.ps1)

This script is used to copy over missing dlls that might have occurred during a CU install. This script has a mapping of the location of where the .dll should be on the server and where it should be on the ISO and will attempt to copy it over if the file is detected to be missing on the install location.

Parameter | Description
----------|------------
[string]IsoRoot | The Root location of the ISO. Example: `D:`