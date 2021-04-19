# [FixInstallerCache.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/FixInstallerCache.ps1)

Download the latest release here: [https://github.com/microsoft/CSS-Exchange/releases/latest/download/FixInstallerCache.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/FixInstallerCache.ps1)

This script is used to copy over the missing MSI files from the installer cache.

Parameter | Description
----------|------------
[string]CurrentCuRootDirectory | The root location of the current CU that you are on.
[string[]]MachineName | The name of the machine that we are waiting to try to copy the MSI files over from, if any are there.
