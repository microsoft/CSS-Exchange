# UnifiedContent Automatic Cleanup

Within Exchange Monitoring, we have a probe that will attempt to clear out the old temp data that is generated from EdgeTransport.exe process. However, this probe definition is defined in the `%ExchangeInstallPath%\Bin\Monitoring\Config\AntiMalware.xml` with a hardcoded path options to look. By default, we are only looking at `"D:\ExchangeTemp\TransportCts\UnifiedContent;C:\Windows\Temp\UnifiedContent;C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\data\Temp\UnifiedContent"`. Therefore, if Exchange is not installed in at `C:\Program Files\Microsoft\Exchange Server\V15\` or if the `TemporaryStoragePath` of the `EdgeTransport.exe.config` value is anything other than `C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\data\Temp` the probe will not work as intended to clean up the data files.

The only way to get the probe to automatically clean up the temp files is to add the correct location to the `%ExchangeInstallPath%\Bin\Monitoring\Config\AntiMalware.xml` file.

**Included in HTML Report?**

Yes

**Additional resources:**

[Exchange UnifiedContent folder fills up the drive](https://learn.microsoft.com/en-us/exchange/troubleshoot/administration/unifiedcontent-folder-fills-up-drive)
