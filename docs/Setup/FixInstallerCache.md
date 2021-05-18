---
title: FixInstallerCache.ps1
parent: Setup
---

## FixInstallerCache.ps1

Download the latest release: [FixInstallerCache.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/FixInstallerCache.ps1)

This script is used to copy over the missing MSI files from the installer cache.

Parameter | Type | Description
-|-|-
CurrentCuRootDirectory | string | The root location of the current CU that you are on.
MachineName | string array | One or more machine names from which to copy the required MSI files.
