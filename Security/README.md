# Security scripts

## BackendCookieMitigation.ps1

This mitigation will filter https requests that contain malicious X-AnonResource-Backend and malformed X-BEResource cookies which were found to be used in the SSRF attacks in the wild.
This will help with defense against the known patterns observed but not the SSRF as a whole. For more information, see the comments at the top of the script.

Download the latest release here:

[Download BackendCookieMitigation.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/BackendCookieMitigation.ps1)

## http-vuln-cve2021-26855.nse

This file is for use with nmap. It detects whether the specified URL is vulnerable to the Exchange Server SSRF Vulnerability (CVE-2021-26855).
For usage information, please read the top of the file.

Download the latest release here:

[Download http-vuln-cve2021-26855.nse](https://github.com/microsoft/CSS-Exchange/releases/latest/download/http-vuln-cve2021-26855.nse)

## Test-ProxyLogon.ps1

Formerly known as Test-Hafnium, this script automates all four of the commands found in the [Hafnium blog post](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/). It also has a progress bar and some performance tweaks to make the CVE-2021-26855 test run much faster. Download the latest release here:

Download the latest release here:

[Download Test-ProxyLogon.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ProxyLogon.ps1)
