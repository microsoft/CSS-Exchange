# FIP-FS Check

**Description:**

We have addressed the issue causing messages to be stuck in transport queues of on-premises `Exchange Server 2016` and `Exchange Server 2019`. The problem relates to a date check failure with the change of the new year and it not a failure of the AV engine itself. This is not an issue with malware scanning or the malware engine, and it is not a security-related issue.

The version checking performed against the signature file is causing the malware engine to crash, resulting in messages being stuck in transport queues.

This check validates if the problematic signature file has already downloaded and processed. It shows a red warning indicating that the FIP-FS scan engine should be reset to avoid running into the transport issue.

- Exchange 2013
    - Exchange 2013 is **not affected** by the transport queue issue, however, if invalid patterns has been applied, no newer update pattern with a lower version number (like `2112330001`) will be applied
    - We check if a folder with number `2201010000` or greater exists under `ExchangeInstallPath\FIP-FS\Data\Engines\amd64\Microsoft\Bin`
    - If that's the case, we point out that the scan engine should be reset

- Exchange 2016 & Exchange 2019
    - We validate the product version of `pipeline2.dll`
    - If `pipeline2.dll` is known to be faulty, we perform further testings by checking if a folder `2201010000` or greater exists under `ExchangeInstallPath\FIP-FS\Data\Engines\amd64\Microsoft\Bin`
    - If `pipeline2.dll` is known to be safe, we perform testings by checking if a folder between `2201010000` and `2202010000` exists. If that's the case, we point out that the scan engine should be reset to make sure that upcoming pattern updates will be applied

Please follow the instructions in the references below to reset the scan engine.

**Included in HTML Report?**

Yes

**Additional resources:**

[Email Stuck in Exchange On-premises Transport Queues](https://techcommunity.microsoft.com/t5/exchange-team-blog/email-stuck-in-exchange-on-premises-transport-queues/ba-p/3049447)