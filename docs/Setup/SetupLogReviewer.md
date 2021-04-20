---
title: SetupLogReviewer.ps1
parent: Setup
---

## SetupLogReviewer.ps1

Download the latest release: [SetupLogReviewer.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetupLogReviewer.ps1)

This script is meant to be run against the Exchange Setup Logs located at `C:\ExchangeSetupLogs\ExchangeSetup.log`. You can run this on the server, or on a personal computer.

It currently checks for common prerequisite issues, clearly calling out if you need up run /PrepareAD in your environment and calls out where it needs to be run. It also checks for some other common issue that we have seen in support that we call out and display the actions to the screen.

Parameter | Description
----------|------------
[string]SetupLog | The location of the Exchange Setup Log that needs to be reviewed
[switch]DelegatedSetup | Use this switch if you are troubleshooting Prerequisites of a Delegated Setup issue
