# Update-Engines

Download the latest release: [Update-Engines.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Update-Engines.ps1)

The UpdateEngines script can be used to download the engine packages to be used by the Forefront Protection engine on Exchange Server and Sharepoint Server products.

## Description

Follow the steps given below to manually update the scan engines in Exchange Server. You may need to do so if you experience issues with accessing anti-malware updates online and want to download those definitions to a central location.

The manual update involves running the `Update-Engines.ps1` PowerShell script. This script can be changed according to your needs.

The update path, list of engines, and list of platforms can be passed as parameters when the script is executed.

!!! warning "Note:"

    The script will default the engine update path to `https://forefrontdl.microsoft.com/server/scanengineupdate/`. If this endpoint isn't available, you can change the script to use the failover endpoint `https://amupdatedl.microsoft.com/server/scanengineupdate/`. If the previous endpoints aren't available, you can use `http://amupdatedl.microsoft.com/server/amupdate/` as an alternative download location. By default, all engines will be downloaded for the 64-bit (amd64) platform.

## Syntax

```powershell
Update-Engines.ps1
  [-EngineDirPath <string>]
  [-UpdatePathUrl <string>]
  [-FailoverPathUrl <string>]
  [-EngineDownloadUrlV2 <string>]
  [-Engines <string[]>]
  [-Platforms <string[]>]
  [-ScriptUpdateOnly <switch>]
  [-SkipVersionCheck <switch>]
```

## Steps to update scan engines

1. Create a local directory structure on the computer on which you want to download the scan engine updates.

    a. Create a directory. For example, create a directory named `ScanEngineUpdates`. This directory must be passed via `-EngineDirPath` parameter to the script.

    b. Set the NTFS file system and share permissions on the directory so that the target Exchange servers have access to it.

2. Download the latest version of the script from [here](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Update-Engines.ps1)

3. Execute the `Update-Engines.ps1` PowerShell script, providing any necessary parameters.

4. You can now configure the servers to download updates from the directory created in step 1) by using the UNC path of a share name, such as `\\server_name\share_name`.

## Examples

The following syntax uses the directory `C:\ScanEngineUpdates\` as the root engine's directory to store the update pattern.

```powershell
Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\
```

The following syntax uses the directory `C:\ScanEngineUpdates\` as the root engine's directory. It also tries to download the latest updates for the `Microsoft` engine using the `amd64` platform from `http://forefrontdl.microsoft.com/server/scanengineupdate/`.

```powershell
Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\ -UpdatePathUrl http://forefrontdl.microsoft.com/server/scanengineupdate/ -Engines Microsoft -Platforms amd64
```

## Found a bug or want to update the script?

Please open a new work item [here](https://github.com/microsoft/CSS-Exchange/issues) or reach out to us via: ExToolsFeedback@microsoft.com
