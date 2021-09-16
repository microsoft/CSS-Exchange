---
title: Test-ExchAVExclusions.ps1
parent: Diagnostics
---

## Test-ExchAVExclusions.ps1

Download the latest release: [Test-ExchAVExclusions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ExchAVExclusions.ps1)

Assists with testing Exchange Servers to determine if AV Exclusions have been properly set according to our documentation.

[AV Exclusions](https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019)

## Usage

Writes an [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) to all paths specified in our AV Exclusions documentation.

If the file is removed then the path is not properly excluded from AV Scanning.
IF the file is not removed then it should be properly excluded.

Once the files are created it will wait 60 seconds for AV to "see" and remove the file.

...
.\Test-ExchAVExclusions.ps1
...


## Parameters

Parameter | Description |
----------|-------------|
Recurse | Places an EICAR file in all subfolders as well as the root.
OpenLog | Opens the script log file.

## Outputs

Log file:
$env:LOCALAPPDATA\ExchAvExclusions.log

List of Folders Scanned by AV:
$env:LOCALAPPDATA\BadFolders.txt
