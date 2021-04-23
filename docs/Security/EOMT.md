---
title: EOMT.ps1
parent: Security
---

## Exchange On-premises Mitigation Tool (EOMT)

Download the latest release: [EOMT.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/EOMT.ps1)

This script contains mitigations to help address the following vulnerabilities.

* CVE-2021-26855

This is the most effective way to help quickly protect and mitigate your Exchange Servers prior to patching. **We recommend this script over the previous ExchangeMitigations.ps1 script.** The Exchange On-premises Mitigation Tool automatically downloads any dependencies and runs the Microsoft Safety Scanner. This a better approach for Exchange deployments with Internet access and for those who want an attempt at automated remediation. We have not observed any impact to Exchange Server functionality via these mitigation methods. EOMT.ps1 is completely automated and uses familiar mitigation methods previously documented. This script has four operations it performs:

* ***+NEW*** Check for the latest version of EOMT and download it.
* Mitigate against current known attacks using CVE-2021-26855 via a URL Rewrite configuration
* Scan the Exchange Server using the [Microsoft Safety Scanner](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)
* Attempt to remediate compromises detected by the Microsoft Safety Scanner.

This a better approach for Exchange deployments with Internet access and for those who want an attempt at automated remediation. We have not observed any impact to Exchange Server functionality via these mitigation methods nor do these mitigation methods make any direct changes that disable features of Exchange.

Use of the Exchange On-premises Mitigation Tool and the Microsoft Saftey Scanner are subject to the terms of the Microsoft Privacy Statement: https://aka.ms/privacy

### Requirements to run the Exchange On-premises Mitigation Tool

* External Internet Connection from your Exchange server (required to download the Microsoft Safety Scanner and the IIS URL Rewrite Module).
* PowerShell script must be run as Administrator.

### System Requirements
* PowerShell 3 or later
* IIS 7.5 and later
* Exchange 2013, 2016, or 2019
* Windows Server 2008 R2, Server 2012, Server 2012 R2, Server 2016, Server 2019
* ***+New*** If Operating System is older than Windows Server 2016, must have [KB2999226](https://support.microsoft.com/en-us/topic/update-for-universal-c-runtime-in-windows-c0514201-7fe6-95a3-b0a5-287930f3560c) for IIS Rewrite Module 2.1 to work.

### Who should run the Exchange On-premises Mitigation Tool

Situation | Guidance
-|-
If you have done nothing to date to patch or mitigate this issue… | Run EOMT.PS1 as soon as possible.This will both attempt to remediate as well as mitigate your servers against further attacks. Once complete, follow patching guidance to update your servers on http://aka.ms/exchangevulns
If you have mitigated using any/all of the mitigation guidance Microsoft has given (Exchangemitigations.Ps1, Blog post, etc..) | Run EOMT.PS1 as soon as possible.  This will both attempt to remediate as well as mitigate your servers against further attacks.   Once complete, follow patching guidance to update your servers on http://aka.ms/exchangevulns
If you have already patched your systems and are protected, but did NOT investigate for any adversary activity, indicators of compromise, etc…. | Run EOMT.PS1 as soon as possible.   This will attempt to remediate any existing compromise that may not have been full remediated before patching.
If you have already patched and investigated your systems for any indicators of compromise, etc…. | No action is required

### Important note regarding Microsoft Safety Scanner
 The Exchange On-premises Mitigation Tool runs the Microsoft Safety Scanner in a quick scan mode. If you suspect any compromise, we highly recommend you run it in the FULL SCAN mode. FULL SCAN mode can take a long time but if you are not running Microsoft Defender AV as your default AV, FULL SCAN will be required to remediate threats.

### Exchange On-premises Mitigation Tool Examples
The default recommended way of using EOMT.ps1. This will determine if your server is vulnerable, mitigate if vulnerable, and run MSERT in quick scan mode. If the server is not vulnerable only MSERT quick scan will run.

`.\EOMT.ps1`

To run a Full MSERT Scan -  We only recommend this option only if the initial quick scan discovered threats. The full scan may take hours or days to complete.

`.\EOMT.ps1 -RunFullScan -DoNotRunMitigation`

To run the Exchange On-premises Mitigation Tool with MSERT in detect only mode - MSERT will not remediate detected threats.

`.\EOMT.ps1 -DoNotRemediate`

To roll back the Exchange On-premises Mitigation Tool mitigations

`.\EOMT.ps1 -Rollbackmitigation`

Note: If ExchangeMitigations.ps1 was used previously to apply mitigations, Use ExchangeMitigations.ps1 for rollback.

***+NEW*** EOMT will now autoupdate by downloading the latest version from GitHub. To prevent EOMT from fetching updates to EOMT.ps1 from the internet.

`.\EOMT.ps1 -DoNotAutoUpdateEOMT`

### Exchange On-premises Mitigation Tool Q & A

**Question**: What mode should I run EOMT.ps1 in by default?

**Answer**: By default, EOMT.ps1 should be run without any parameters:

This will run the default mode which does the following:
1. Checks if your server is vulnerable based on the presence of the SU patch or Exchange version.
2. Downloads and installs the IIS URL rewrite tool **(only if vulnerable)**.
3. Applies the URL rewrite mitigation **(only if vulnerable)**.
4. Runs the Microsoft Safety Scanner in "Quick Scan" mode **(vulnerable or not)**.

**Question**:  What if I run a full scan and it’s affecting the resources of my servers?

**Answer**:  You can terminate the process of the scan by running the following command in an Administrative PowerShell session.

`Stop-Process -Name msert`

**Question**:  What is the real difference between this script (EOMT.PS1) and the previous script Microsoft released (ExchangeMitigations.Ps1).

**Answer**:  The Exchange On-premises Mitigation Tool was released to help pull together multiple mitigation and response steps, whereas the previous script simply enabled mitigations. Some details on what each do:

#### EOMT.PS1
* Mitigation of CVE-2021-26855 via a URL Rewrite configuration.
* Mitigation does not impact Exchange functionality.
* Malware scan of the Exchange Server via the Microsoft Safety Scanner
* Attempt to reverse any changes made by identified threats.
#### ExchangeMitigations.ps1:
* Does mitigations for all 4 CVE’s - CVE-2021-26855, CVE-2021-26857, CVE-2021-27065 & CVE-2021-26858.
* Some of the mitigation methods impact Exchange functionality.
* Does not do any scanning for existing compromise or exploitation.
* Does not take response actions to existing active identified threats.

**Question:**  What if I do not have an external internet connection from my Exchange server?

**Answer:**  If you do not have an external internet connection, you can still use the legacy script (ExchangeMitigations.ps1) and other steps from the mitigation blog post:  [Microsoft Exchange Server Vulnerabilities Mitigations – March 2021](https://msrc-blog.microsoft.com/2021/03/05/microsoft-exchange-server-vulnerabilities-mitigations-march-2021/)

**Question:** If I have already ran the mitigations previously, will the Exchange On-premises Mitigation Tool roll back any of the mitigations?

**Answer:** No, please use the legacy script (ExchangeMitigations.ps1) to do rollback. The legacy script supports rollback for the mitigations the Exchange On-premises Mitigation Tool applied.
