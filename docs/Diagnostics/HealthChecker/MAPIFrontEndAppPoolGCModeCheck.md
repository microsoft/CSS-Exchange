# MAPI Front End App Pool GC Mode Check

**Description:**

We validate the Garbage Collection (GC) configuration for `MSExchangeMapiFrontEndAppPool` App Pool if the check is executed against an Exchange 2013 server that is not running the EdgeTransport role.

We check if:

- The server has a total memory of `21474836480 MB` and `gcServer.Enabled` set to `false`\
In this case we recommend to enable `Server GC`.

- `gcServer.Enabled` is neither `true` nor `false`\
This case should be investigated.

- `gcServer.Enabled` is `false`
In this case we're running Workstation GC.\
You could be seeing some GC issues within the `MSExchangeMapiFrontEndAppPool` App Pool. However, you don't have enough memory installed on the system to recommend switching the GC mode by default without consulting a support professional.

How to fix this:

1. Go into the file `MSExchangeMapiFrontEndAppPool_CLRConfig.config`\
You can find the file by running ``%winDir%\system32\inetSrv\AppCmd.exe list AppPool "MSExchangeMapiFrontEndAppPool" /text:"CLRConfigFile"`` via `cmd.exe`\
It should be located here: `%ExchangeInstallPath%\bin\MSExchangeMapiFrontEndAppPool_CLRConfig.config`
2. Open the file by using an elevated `notepad.exe` and change the `gcServer Enabled` value from `false` to `true`
3. Recycle the `MAPI Front End App Pool` by running: `Restart-WebAppPool MSExchangeMapiFrontEndAppPool` via `PowerShell` or by running:\
 ``%winDir%\system32\inetSrv\AppCmd.exe RECYCLE AppPool "MSExchangeMapiFrontEndAppPool"`` via `cmd.exe`

**Included in HTML Report?**

Yes

**Additional resources:**

[Fundamentals of garbage collection](https://docs.microsoft.com/dotnet/standard/garbage-collection/fundamentals)

[Workstation and server garbage collection](https://docs.microsoft.com/dotnet/standard/garbage-collection/workstation-server-gc)

