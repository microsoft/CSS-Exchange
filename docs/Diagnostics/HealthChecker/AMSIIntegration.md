# AMSI Check

The Windows AntiMalware Scan Interface (AMSI) is a versatile standard that allows applications and services to integrate with any AntiMalware product present on a machine. AMSI is vendor agnostic and designed to allow for the most common malware scanning and protection techniques provided by today's products to be integrated into applications.

It only scans the HTTP protocol, and is not meant to be a replacement to existing server-level or message hygiene protections.

AMSI integration is available on the following Operating System / Exchange Server version combinations:
- Windows Server 2016, or higher
- Exchange Server 2016 CU21, or higher
- Exchange Server 2019 CU10, or higher
- AMSI is not available on Edge Transport Servers

If you use Microsoft Defender, AV engine version at or higher than 1.1.18300.4 is also required.
Alternatively, a compatible AMSI capable third-party AV provider.

This check verifies if an override exists which disables the AMSI integration with Exchange Server. It does that, by running the following query:

`Get-SettingOverride | Where-Object { ($_.ComponentName -eq "Cafe") -and ($_.SectionName -eq "HttpRequestFiltering") }`

AMSI Body Scanning Feature, was introduced in Exchange Server November 2024 Security Update. This is disabled by default and can be enabled with a New-SettingOverride cmdlet. In order to properly function, it does require that AMSI is enabled as well. There will be a configuration issue/warning for the following scenarios:
- Body Scanning is enabled, but AMSI is disabled
- Block Request Greater than Max scan size is configured
- Body Scanning is enabled, but not on the correct version to have the setting applicable


**Included in HTML Report?**

Yes

**Additional resources:**

[Released: June 2021 Quarterly Exchange Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-june-2021-quarterly-exchange-updates/ba-p/2459826)

[More about AMSI integration with Exchange Server](https://techcommunity.microsoft.com/t5/exchange-team-blog/more-about-amsi-integration-with-exchange-server/ba-p/2572371)

[Exchange Server AMSI Integration](https://learn.microsoft.com/Exchange/antispam-and-antimalware/amsi-integration-with-exchange)
