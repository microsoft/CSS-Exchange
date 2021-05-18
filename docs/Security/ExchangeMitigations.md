---
title: ExchangeMitigations.ps1
parent: Security
---

## ExchangeMitigations.ps1

Download the latest release: [ExchangeMitigations.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeMitigations.ps1)

This script contains 4 mitigations to help address the following vulnerabilities:

* CVE-2021-26855
* CVE-2021-26857
* CVE-2021-27065
* CVE-2021-26858

For more information on each mitigation please visit https://aka.ms/exchangevulns

**This should only be used as a temporary mitigation until your Exchange Servers can be fully patched, recommended guidance is to apply all of the mitigations at once.**

For this script to work you must have the IIS URL Rewrite Module installed which can be done via this script using the -FullPathToMSI parameter.

For IIS 10 and higher URL Rewrite Module 2.1 must be installed, you can download version 2.1 here:

* x86 & x64 -https://www.iis.net/downloads/microsoft/url-rewrite

For IIS 8.5 and lower Rewrite Module 2.0 must be installed, you can download version 2.0 here:

* x86 - https://www.microsoft.com/en-us/download/details.aspx?id=5747

* x64 - https://www.microsoft.com/en-us/download/details.aspx?id=7435

Installing URL Rewrite version 2.1 on IIS versions 8.5 and lower may cause IIS and Exchange to become unstable. If there is a mismatch between the URL Rewrite module and IIS version, ExchangeMitigations.ps1 will not apply the mitigation for CVE-2021-26855. You must uninstall the URL Rewrite module and reinstall the correct version.

Script requires PowerShell 3.0 and later and must be executed from an elevated PowerShell Session.

Download the latest release here:

[Download ExchangeMitigations.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeMitigations.ps1)

To apply all mitigations with MSI install

`.\ExchangeMitigations.ps1 -FullPathToMSI "FullPathToMSI" -WebSiteNames "Default Web Site" -ApplyAllMitigations`

To apply all mitigations without MSI install

`.\ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -ApplyAllMitigations -Verbose`

To rollback all mitigations

`.\ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -RollbackAllMitigation`

To apply multiple or specific mitigations (out of the 4)

`.\ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -ApplyECPAppPoolMitigation -ApplyOABAppPoolMitigation`

To rollback multiple or specific mitigations

`.\ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -RollbackECPAppPoolMitigation -RollbackOABAppPoolMitigation`
