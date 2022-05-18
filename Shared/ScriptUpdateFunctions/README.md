# AutoUpdate Options

## Test-ScriptVersion

### Update without prompting

The -VersionsUrl parameter is optional, and is used for directing update checks to a specific
URL for that script to allow measurement of script usage.

```powershell
if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/SA-VersionsUrl" -Confirm:$false)) {
    Write-Host "Script was updated. Please rerun the script."
    return
}
```

Example output:

```powershell
PS C:\> .\SetupAssist.ps1
File signed by CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
AutoUpdate: Signature validated.
AutoUpdate: Succeeded.
Script was updated. Please rerun the script.
```

### Update with prompt

Same as above, but drop the -Confirm:$false. Example output:

```powershell
PS C:\> .\SetupAssist.ps1

Confirm
Are you sure you want to perform this action?
Performing the operation "Update script to latest version" on target "SetupAssist.ps1".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"):
File signed by CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
AutoUpdate: Signature validated.
AutoUpdate: Succeeded.
Script was updated. Please rerun the script.
```

### Notify of update only

Same as above, but drop -AutoUpdate. Example output:

```powershell
[PS] C:\>.\SetupAssist.ps1
WARNING: SetupAssist.ps1 22.05.17.1249 is outdated. Please download the latest, version 22.05.17.0056.
```

### Verbose output

Both of the above options produce additional output with -Verbose. This is especially useful
when the script isn't updating and you want to see why.

```powershell
[PS] C:\>.\SetupAssist.ps1 -Verbose
VERBOSE: GET https://aka.ms/SA-VersionsUrl with 0-byte payload
VERBOSE: received 3523-byte response of content type application/octet-stream
VERBOSE: Current version: 22.05.17.1249 Latest version: 22.05.17.0056 Update found: True

Confirm
Are you sure you want to perform this action?
Performing the operation "Update script to latest version" on target "SetupAssist.ps1".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"):
```

```powershell
[PS] C:\>.\SetupAssist.ps1 -Verbose
VERBOSE: GET https://aka.ms/SA-VersionsUrl with 0-byte payload
VERBOSE: Unable to check for updates: System.Net.WebException: The remote name could not be resolved: 'aka.ms'
   at Microsoft.PowerShell.Commands.WebRequestPSCmdlet.GetResponse(WebRequest request)
   at Microsoft.PowerShell.Commands.WebRequestPSCmdlet.ProcessRecord()
Setup Assist Version 22.05.17.1249
VERBOSE: Working on test Test-ExchangeADSetupLevel
```

## Get-ScriptUpdateAvailable and Invoke-ScriptUpdate

If a script uses Test-ScriptVersion without -AutoUpdate, that script has a lot of code in
it that will never be called, including Confirm-Signature and Invoke-ScriptUpdate. If that
functionality is not needed, the script can be trimmed down by calling Get-ScriptUpdateAvailable
directly, instead of the Test-ScriptVersion wrapper.

Example code:

```powershell
$updateInfo = Get-ScriptUpdateAvailable $VersionsUrl
```

$updateInfo object has the following shape:

```powershell
[PSCustomObject]@{
    ScriptName
    CurrentVersion
    LatestVersion
    UpdateFound
    Error
}
```

You can use that result to give the user any information you like and to determine if you want to
call Invoke-ScriptUpdate.
