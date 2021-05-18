---
title: CopyMissingDlls.ps1
parent: Setup
---

## CopyMissingDlls.ps1

Download the latest release: [CopyMissingDlls.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/CopyMissingDlls.ps1)

This script is used to copy over missing dlls that might have occurred during a CU install. This script has a mapping of the location of where the .dll should be on the server and where it should be on the ISO and will attempt to copy it over if the file is detected to be missing on the install location.

Parameter | Type | Description
-|-|-
IsoRoot | string | The Root location of the ISO. Example: `D:`
