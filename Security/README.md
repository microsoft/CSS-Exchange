# Security scripts

## Test-ProxyLogon.ps1

Formerly known as Test-Hafnium, this script automates all four of the commands found in the [Hafnium blog post](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/). It also has a progress bar and some performance tweaks to make the CVE-2021-26855 test run much faster.

Download the latest release here:

[Download Test-ProxyLogon.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ProxyLogon.ps1)

The most typical usage of this script is to check all Exchange servers and save the output,
by using the following syntax from Exchange Management Shell:

`Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs`

To check the local server only, just run the script:

`.\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs`

To display the results without saving them, pass -DisplayOnly:

`.\Test-ProxyLogon.ps1 -DisplayOnly`

## ExchangeMitigations.ps1
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

Installing URL Rewrite version 2.1 on IIS versions 8.5 and lower may cause IIS and Exchange to become unstable. If there is a mismatch between the URL Rewrite module and IIS version, ExchangeMitigations.ps1 will not apply the mitigation for CVE-2021-26855. You must uninstall the URL Rewrite module and reinstall the correct version. We do not recommend completely uninstalling the URL rewrite module once it is installed. Uninstalling may cause issues with IIS and Exchange.

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

## BackendCookieMitigation.ps1

This mitigation will filter https requests that contain malicious X-AnonResource-Backend and malformed X-BEResource cookies which were found to be used in CVE-2021-26855.

This will help with defense against the known patterns observed but not the SSRF as a whole. For more information please visit https://aka.ms/exchangevulns.

For this script to work you must have the IIS URL Rewrite Module installed which can be done via this script using the -FullPathToMSI parameter.

For IIS 10 and higher URL Rewrite Module 2.1 must be installed, you can download version 2.1 here:

* x86 & x64 -https://www.iis.net/downloads/microsoft/url-rewrite

For IIS 8.5 and lower Rewrite Module 2.0 must be installed, you can download version 2.0 here:

* x86 - https://www.microsoft.com/en-us/download/details.aspx?id=5747

* x64 - https://www.microsoft.com/en-us/download/details.aspx?id=7435

Installing URL Rewrite version 2.1 on IIS versions 8.5 and lower may cause IIS and Exchange to become unstable. If there is a mismatch between the URL Rewrite module and IIS version, ExchangeMitigations.ps1 will not apply the mitigation for CVE-2021-26855. You must uninstall the URL Rewrite module and reinstall the correct version. We do not recommend completely uninstalling the URL rewrite module once it is installed. Uninstalling may cause issues with IIS and Exchange.

Script requires PowerShell 3.0 and later and must be executed from an elevated PowerShell Session.

Download the latest release here:

[Download BackendCookieMitigation.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/BackendCookieMitigation.ps1)

To apply with MSI install of the URL Rewrite module - Note: version may vary depending on system info

`PS C:\> BackendCookieMitigation.ps1 -FullPathToMSI "C:\temp\rewrite_amd64_en-US.msi" -WebSiteNames "Default Web Site" -Verbose `

To apply without MSI install

`PS C:\> BackendCookieMitigation.ps1 -WebSiteNames "Default Web Site" -Verbose`

To rollback - Note: This does not remove the IIS Rewrite module, only the rules.

`PS C:\> BackendCookieMitigation.ps1 -WebSiteNames "Default Web Site" -RollbackMitigation -Verbose`

## http-vuln-cve2021-26855.nse

This file is for use with nmap. It detects whether the specified URL is vulnerable to the Exchange Server SSRF Vulnerability (CVE-2021-26855).
For usage information, please read the top of the file.

Download the latest release here:

[Download http-vuln-cve2021-26855.nse](https://github.com/microsoft/CSS-Exchange/releases/latest/download/http-vuln-cve2021-26855.nse)
