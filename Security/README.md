Script|More Info|Download
-|-|-
EOMT | [More Info](https://github.com/microsoft/CSS-Exchange/tree/main/Security#exchange-on-premises-mitigation-tool-eomt) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/EOMT.ps1)
CompareExchangeHashes.ps1 | [More Info](https://github.com/microsoft/CSS-Exchange/tree/main/Security#compareexchangehashesps1) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/CompareExchangeHashes.ps1)
ExchangeMitigations.ps1 | [More Info](https://github.com/microsoft/CSS-Exchange/tree/main/Security#exchangemitigationsps1) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeMitigations.ps1)
http-vuln-cve2021-26855.nse | [More Info](https://github.com/microsoft/CSS-Exchange/tree/main/Security#http-vuln-cve2021-26855nse) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/http-vuln-cve2021-26855.nse)
Test-ProxyLogon.ps1 | [More Info](https://github.com/microsoft/CSS-Exchange/tree/main/Security#test-proxylogonps1) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ProxyLogon.ps1)

# Security scripts

## Exchange On-premises Mitigation Tool (EOMT)
This script contains mitigations to help address the following vulnerabilities.

* CVE-2021-26855

This is the most effective way to help quickly protect and mitigate your Exchange Servers prior to patching. **We recommend this script over the previous ExchangeMitigations.ps1 script.** EOMT automatically downloads any dependencies and runs the Microsoft Safety Scanner. This a better approach for Exchange deployments with Internet access and for those who want an attempt at automated remediation. We have not observed any impact to Exchange Server functionality via these mitigation methods. EOMT.ps1 is completely automated and uses familiar mitigation methods previously documented. This script has three operations it performs:

* Mitigation of CVE-2021-26855 via a URL Rewrite configuration. Note: This mitigates the known methods of this exploit.
* Malware scan of the Exchange Server via the Microsoft Safety Scanner (https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)
* Attempt to remeidate compromises detected by the Microsoft Safety Scanner.

This a better approach for Exchange deployments with Internet access and for those who want an attempt at automated remediation. We have not observed any impact to Exchange Server functionality via these mitigation methods nor do these mitigation methods make any direct changes that disable features of Exchange.

### Requirements to run EOMT

* External Internet Connection from your Exchange server (required to download the safety scanner and the IIS URL Rewrite Module).
* PowerShell script must be run as Administrator.

### System Requirements
* PowerShell 3 or later
* IIS 7.5 and later
* Exchange 2013, 2016, or 2019
* Windows Server 2008 R2, Server 2012, Server 2012 R2, Server 2016, Server 2019

### Who should run EOMT

Situation | Guidance
-|-
If you have done nothing to date to patch or mitigate this issue… | Run EOMT.PS1 as soon as possible.This will both attempt to remediate as well as mitigate your servers against further attacks. Once complete, follow patching guidance to update your servers on http://aka.ms/exchangevulns
If you have mitigated using any/all of the mitigation guidance Microsoft has given (Exchangemitigations.Ps1, Blog post, etc..) | Run EOMT.PS1 as soon as possible.  This will both attempt to remediate as well as mitigate your servers against further attacks.   Once complete, follow patching guidance to update your servers on http://aka.ms/exchangevulns
If you have already patched your systems and are protected, but did NOT investigate for any adversary activity, indicators of compromise, etc…. | Run EOMT.PS1 as soon as possible.   This will attempt to remediate any existing compromise that may not have been full remediated before patching.
If you have already patched and investigated your systems for any indicators of compromise, etc…. | No action is required

### Important note regarding Microsoft Safety Scanner
 EOMT runs the Microsoft Safety Scanner in a quick scan mode. If you suspect any compromise, we highly recommend you run it in the FULL SCAN mode. FULL SCAN mode can take a long time but if you are not running Mirosoft Defender AV as your default AV, FULL SCAN will be required to remediate threats.

### EOMT Examples
The default recommended way of using of EOMT.ps1. This will determine if your server is vulnerable, mitigate if vulnerable, and run MSERT in quick scan mode. If the server is not vulnerable only MSERT quick scan will run.

`.\EOMT.ps1`

To run a Full MSERT Scan -  We only recommend this option only if the initial quick scan discovered threats. The full scan may take hours or days to complete.

`.\EOMT.ps1 -RunFullScan -DoNotRunMitigation`

To roll back EOMT mitigations

`.\EOMT.ps1 -Rollbackmitigation`

Note: If ExchangeMitigations.ps1 was used previously to apply mitigations, Use ExchangeMitigations.ps1 for rollback.

## [Test-ProxyLogon.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ProxyLogon.ps1)

Formerly known as Test-Hafnium, this script automates all four of the commands found in the [Hafnium blog post](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/). It also has a progress bar and some performance tweaks to make the CVE-2021-26855 test run much faster.

Download the latest release here:

[Download Test-ProxyLogon.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ProxyLogon.ps1)

The most typical usage of this script is to check all Exchange servers and save the reports,
by using the following syntax from Exchange Management Shell:

`Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs`

To check the local server only, just run the script:

`.\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs`

To check the local server and copy the identified logs and files to the OutPath:

`.\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs -CollectFiles`

To display the results without saving them, pass -DisplayOnly:

`.\Test-ProxyLogon.ps1 -DisplayOnly`

## [ExchangeMitigations.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeMitigations.ps1)
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

## [CompareExchangeHashes.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/CompareExchangeHashes.ps1)

This script provides a mechanism for malicious file detection on Exchange servers running E13, E16 or E19 versions.
For more information please go to [https://aka.ms/exchangevulns](https://aka.ms/exchangevulns).

[Download CompareExchangeHashes.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/CompareExchangeHashes.ps1)

`.\CompareExchangeHashes.ps1`

The script currently only validates files in exchange virtual directories only, it does not check any files in the IIS root.
**This script needs to be run as administrator on all the exchange servers separately**.

The script determines the version of exchange installed on the server and then downloads the hashes for known exchange files from the [published known good hashes of exchange files](https://github.com/microsoft/CSS-Exchange/releases/latest).

The result generated is stored in a file locally with the following format: <ExchangeVersion>_result.csv
If potential malicious files are found during comparision there is an error generated on the cmdline.

To read the output, open the result csv file in excel or in powershell:

`$result = Import-Csv <Path to result file>`

Note: If the server does not have internet connectivity, run the script which would output the exchange versions discovered on the server. The baselines can be downloaded from [published known good hashes of exchange files](https://github.com/microsoft/CSS-Exchange/releases/latest) and re-run the script.

Submitting files for analysis:
* Please submit the output file for analysis in the malware analysis portal [here](https://www.microsoft.com/en-us/wdsi/filesubmission). Please add the text "ExchangeMarchCVE" in "Additional Information" field on the portal submission form.
* Instructions on how to use the portal can be found [here](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/submission-guide).

## [http-vuln-cve2021-26855.nse](https://github.com/microsoft/CSS-Exchange/releases/latest/download/http-vuln-cve2021-26855.nse)

This file is for use with nmap. It detects whether the specified URL is vulnerable to the Exchange Server SSRF Vulnerability (CVE-2021-26855).
For usage information, please read the top of the file.

Download the latest release here:

[Download http-vuln-cve2021-26855.nse](https://github.com/microsoft/CSS-Exchange/releases/latest/download/http-vuln-cve2021-26855.nse)
