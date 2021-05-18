---
title: SetupAssist.ps1
parent: Setup
has_children: true
---

## SetupAssist.ps1

Download the latest release: [SetupAssist.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupAssist.ps1)

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

Parameter | Type | Description
-|-|-
OtherWellKnownObjects | switch | Tests for deleted objects in the otherWellKnownObjects attribute
