# Test-ExchAVExclusions

Download the latest release: [Test-ExchAVExclusions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ExchAVExclusions.ps1)

Assists with testing Exchange Servers to determine if AV Exclusions have been properly set according to our documentation.

[AV Exclusions Exchange 2016/2019](https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019)
[AV Exclusions Exchange 2013](https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help)

## Usage

Writes an [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) to all paths specified in our AV Exclusions documentation, verifies all extensions in the documentation in a temporary folder and checks all Exchange processes for 3rd party DLLs.

If the file is removed then the path is not properly excluded from AV Scanning.
If the file is not removed then it should be properly excluded.

Once the files are created it will wait 5 minutes for AV to "see" and remove the file.

```
.\Test-ExchAVExclusions.ps1
```


## Parameters

Parameter | Description |
----------|-------------|
DisableDirectoriesAnalysis | Disable the Directories Analysis exclusions.
Recurse | Places an EICAR file in all SubFolders in the Exclusions list as well as the root.
DisableProcessesAnalysis | Disable the Processes Analysis exclusions.
IncludeW3wpProcesses | Includes w3wp processes in the analysis.
DisableExtensionsAnalysis | Disable the Extension Analysis exclusions.
OpenLog | Opens the script log file.

## Outputs

Log file:
$env:LOCALAPPDATA\ExchAvExclusions.log

List of Folders and extensions Scanned by AV:
$env:LOCALAPPDATA\BadExclusions.txt
