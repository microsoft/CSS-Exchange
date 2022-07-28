# FIP-FS Check

**Description:**

We have addressed the issue causing messages to be stuck in transport queues of on-premises `Exchange Server 2016` and `Exchange Server 2019`. The problem relates to a date check failure with the change of the new year and it not a failure of the AV engine itself. This is not an issue with malware scanning or the malware engine, and it is not a security-related issue.

The version checking performed against the signature file is causing the malware engine to crash, resulting in messages being stuck in transport queues.

This check validates if the problematic signature file has already downloaded and processed. It shows a red warning indicating that the FIP-FS scan engine should be reset to avoid running into the transport or pattern update issue.

- Exchange 2013 is **not affected** by the transport queue issue, however, if invalid patterns has been applied, no newer update pattern with a lower version number (like `2112330001`) will be applied.
- We check if a folder with number `2201010000` or greater exists under `ExchangeInstallPath\FIP-FS\Data\Engines\amd64\Microsoft\Bin`.
- We also check if the server runs a fixed Exchange build (March 2022 Security Update or higher) that does not crash when the problematic version is used.

- If we detect the problematic version folder and the server doesn't run a fixed build, we recommend to reset the scan engine version (see `Email Stuck in Exchange On-premises Transport Queues` in the "Additional resources" section).

- If we detect the problematic version folder but the server runs a fixed build, it should be safe to delete the folder without performing a scan engine reset. If the directory cannot be deleted, it means that the problematic version is in use. This is a problem because in this case, no new scan engine version will be applied. In this case, a reset of the scan engine must be performed.

Please follow the instructions in the references below to reset the scan engine.

**Included in HTML Report?**

Yes

**Additional resources:**

[Email Stuck in Exchange On-premises Transport Queues](https://techcommunity.microsoft.com/t5/exchange-team-blog/email-stuck-in-exchange-on-premises-transport-queues/ba-p/3049447)

