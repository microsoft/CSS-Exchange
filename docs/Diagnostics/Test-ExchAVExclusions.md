# Test-ExchAVExclusions

Download the latest release: [Test-ExchAVExclusions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ExchAVExclusions.ps1)

Assists with testing Exchange Servers to determine if AV Exclusions have been properly set according to our documentation.

[AV Exclusions Exchange 2016/2019](https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019)

[AV Exclusions Exchange 2013](https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help)

## Usage

Writes an [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) to all paths specified in our AV Exclusions documentation and verifies all extensions in the documentation in a temporary folder.

If the file is removed then the path is not properly excluded from AV Scanning.
IF the file is not removed then it should be properly excluded.

Once the files are created it will wait 5 minutes for AV to "see" and remove the file.

After finishing testing directories it will test Exchange Processes.
Pulls all Exchange processes and their modules.
Excludes known modules and reports all Non-Default modules.

Non-Default modules should be reviewed to ensure they are expected.
AV Modules loaded into Exchange Processes indicate that AV Process Exclusions are NOT properly configured.

...
.\Test-ExchAVExclusions.ps1
...

## Understanding the Output

### File Output
Review the BadExclusions.txt file to see any file paths were identified as being scanned by AV.
Work with the AV Vendor to determine the best way to exclude these file paths according to our documentation:

[AV Exclusions Exchange 2016/2019](https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019)

### Process Output
Review NonDefaultModules.txt to determine if any Non-Default modules are loaded into Exchange processes.  The output should have sufficient information to identity the source of the flagged modules.

```[FAIL] - PROCESS: ExchangeTransport MODULE: scanner.dll COMPANY: Contoso Security LTT.```

If the Module is from an AV or Security software vendor it is a strong indication that process exclusions are not properly configured on the Exchange server.  Please work with the vendor to ensure that they are properly configured according to:

[AV Exclusions Exchange 2016/2019](https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019)

[AV Exclusions Update](https://techcommunity.microsoft.com/t5/exchange-team-blog/update-on-the-exchange-server-antivirus-exclusions/ba-p/3751464)


## Parameters

Parameter | Description |
----------|-------------|
WaitingTimeForAVAnalysisInMinutes | Set the waiting time for AV to analyze the EICAR files. Default is 5 minutes.
Recurse | Places an EICAR file in all SubFolders as well as the root.
SkipVersionCheck | Skip script version verification.
ScriptUpdateOnly | Just update script version to latest one.


## Outputs

Log file:
$PSScriptRoot\Test-ExchAvExclusions-#DateTime#.txt

List of Folders, extensions Scanned by AV and List of Non-Default Processes:
$PSScriptRoot\BadExclusions-#DateTime#.txt
