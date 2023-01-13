# Reset-ScanEngineVersion

Download the latest release: [Reset-ScanEngineVersion.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Reset-ScanEngineVersion.ps1)

## Syntax

```powershell
Reset-ScanEngineVersion.ps1
  [-Force <switch>]
  [-EngineUpdatePath <string>]
```

## Usage

Copy the script to an affected Exchange server and run it with no parameters. It can be run from EMS or plain PowerShell.

In scenarios where centralized distribution of scan engines is used, add the -EngineUpdatePath switch to point to the share containing the engines. For example:

```powershell
.\Reset-ScanEngineVersion.ps1 -EngineUpdatePath \\FileServer1\ScanEngineUpdates
```
