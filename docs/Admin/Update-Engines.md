<!-- cspell:ignore Kaspersky Cloudmark -->
# Update-Engines

Download the latest release: [Update-Engines.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Update-Engines.ps1)

The UpdateEngines script can be used to download the engine packages to be used by the Forefront Protection engine on Exchange Server and Sharepoint Server products.

## Description

Follow the steps given below to manually update the scan engines in Exchange Server. You may need to do so if you experience issues with accessing anti-malware updates online and want to download those definitions to a central location.

The manual update involves running the `Update-Engines.ps1` PowerShell script. This script can be changed according to your needs.

The update path and list of engines can be passed as parameters when the script is executed.

!!! warning "Note:"

    The script will default the engine update path to `http://forefrontdl.microsoft.com/server/scanengineupdate/`. If this endpoint isn't available, you can change the script to use the failover endpoint `https://amupdatedl.microsoft.com/server/scanengineupdate/`. If the previous endpoints aren't available, you can use `http://amupdatedl.microsoft.com/server/amupdate/` as an alternative download location. Only the 64-bit (amd64) platform is served today; older 32-bit (x86) packages have been retired at the update endpoints. Only the `Microsoft` and `Command` engines return content at the current endpoints; other engines listed in the Universal Manifest (Kaspersky, Norman, Symantec, Cloudmark, WormList, Kaspersky5) return 404 and are no longer downloadable. Payload integrity is verified independently of the transport: signed Universal Manifest and per-engine manifests are checked via Authenticode, and the full-package CAB is checked against the SHA256 published in the signed per-engine manifest.

## Syntax

```powershell
Update-Engines.ps1
  [-EngineDirPath <string>]
  [-UpdatePathUrl <string>]
  [-FailoverPathUrl <string>]
  [-EngineDownloadUrlV2 <string>]
  [-Engines <string[]>]
  [-ScriptUpdateOnly <switch>]
  [-SkipVersionCheck <switch>]
  [-CleanUp <switch>]
  [-VersionsToKeep <int>]
```

## Steps to update scan engines

1. Create a local directory on the computer where you want to download the scan engine updates. For example, `C:\ScanEngineUpdates`. This directory must be passed via the `-EngineDirPath` parameter to the script.

    !!! warning "Local storage required for `-EngineDirPath`"

        `-EngineDirPath` must point to a directory on local storage. UNC paths (for example `\\server\share`) and mapped network drives are rejected by the script. Drive-letter-only values such as `C:` are also rejected — always provide a full path such as `C:\ScanEngineUpdates`. Reparse points (junctions, symbolic links) at the target directory or any of its ancestors are rejected as well, to prevent an attacker from redirecting extraction outside the tree between the safety check and the write. Stage the updates on a local disk first; once the script finishes, copy the completed directory to a file share for the Exchange servers to consume.

    !!! warning "Restrict write access to the staging directory"

        The staging directory and everything beneath it must be writable only by the account running the script and by trusted administrators. The script performs signature and hash checks on downloaded files and then reads those same files back from disk to extract them; a lower-privileged principal with write access to the staging tree can replace verified content between the check and the read, defeating the integrity checks even when they individually pass.

2. Download the latest version of the script from [here](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Update-Engines.ps1)

3. Execute the `Update-Engines.ps1` PowerShell script, providing any necessary parameters.

4. When the script completes, copy the contents of the local staging directory to a file share that your Exchange servers can access. Set NTFS file system and share permissions on that share so the target Exchange servers have read access to it.

5. Configure the Exchange servers to download updates from the UNC path of that share, such as `\\server_name\share_name`.

## Examples

The following syntax uses the directory `C:\ScanEngineUpdates\` as the root engine's directory to store the update pattern.

```powershell
Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\
```

The following syntax uses the directory `C:\ScanEngineUpdates\` as the root engine's directory. It also tries to download the latest updates for the `Microsoft` engine on the `amd64` platform from `http://forefrontdl.microsoft.com/server/scanengineupdate/`. The platform is fixed to `amd64` (the only platform served today); the engine list can also include `Command`.

```powershell
Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\ -UpdatePathUrl http://forefrontdl.microsoft.com/server/scanengineupdate/ -Engines Microsoft
```

## Found a bug or want to update the script?

Please open a new work item [here](https://github.com/microsoft/CSS-Exchange/issues) or reach out to us via: ExToolsFeedback@microsoft.com
