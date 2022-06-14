# SetUnifiedContentPath

Download the latest release: [SetUnifiedContentPath.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetUnifiedContentPath.ps1)

Sets the CleanupFolderREsponderFolderPaths in the AntiMalware.xml file that is responsible for having Exchange automatically clean up the Unified Content that is left behind.

If this isn't properly set, you can have large amount of files left on the computer that is just using up space and can cause issues with Exchange.

The script will keep the default values of `D:\ExchangeTemp\TransportCts\UnifiedContent`, `C:\Windows\Temp\UnifiedContent`, and `$ExInstall\TransportRoles\data\Temp\UnifiedContent` within the value and will include `TemporaryStoragePath` from the `EdgeTransport.exe.config` if different from the install path.

In order for the new settings to take effect right away, use the `-RestartService` switch to have the MSExchangeHM service take in the new changes right away.

## Common Usage

The easiest way to run the script is against all the servers and restart the service.

```powershell
Get-ExchangeServer | .\SetUnifiedContentPath.ps1 -RestartService
```

If you don't want to change anything just yet, use the `-WhatIf` switch to see what servers will have something changed.

```powershell
Get-ExchangeServer | .\SetUnifiedContentPath.ps1 -WhatIf
```

Or you can just run it locally on the server

```powershell
.\SetUnifiedContentPath.ps1 -RestartService
```

**NOTE:** The switch `-RestartService` is only going to restart the service if a change has been detected and done. Otherwise, it will not restart the service.
