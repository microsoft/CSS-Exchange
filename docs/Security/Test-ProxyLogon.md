---
title: Test-ProxyLogon.ps1
parent: Security
---

## Test-ProxyLogon.ps1

Download the latest release: [Test-ProxyLogon.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ProxyLogon.ps1)

Formerly known as Test-Hafnium, this script automates all four of the commands found in the [Hafnium blog post](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/). It also has a progress bar and some performance tweaks to make the CVE-2021-26855 test run much faster.

### Usage

The most typical usage of this script is to check all Exchange servers and save the reports,
by using the following syntax from Exchange Management Shell:

`Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs`

To check the local server only, just run the script:

`.\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs`

To check the local server and copy the identified logs and files to the OutPath:

`.\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs -CollectFiles`

To display the results without saving them, pass -DisplayOnly:

`.\Test-ProxyLogon.ps1 -DisplayOnly`

### Frequently Asked Questions

**The script says it found suspicious files, and it lists a bunch of zip files. What does this mean?**

The script will flag any zip/7x/rar files that it finds in ProgramData. As noted in
[this blog post](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/), web
shells have been observed using such files for exfiltration. An administrator should review the files to
determine if they are valid. Determining if a zip file is a valid part of an installed
product is outside the scope of this script, and whitelisting files by name would only encourage
the use of those specific names by attackers.

**I'm having trouble running the script on Exchange 2010.**

If PowerShell 3 is present, the script can be run on Exchange 2010. It will not run-on PowerShell 2. One can
also enable PS Remoting and run the script remotely against Exchange 2010. However,
the script has minimal functionality in these scenarios, as Exchange 2010 is only affected by one of the
four announced exploits - CVE-2021-26857. Further, this exploit is only available if the Unified Messaging role
is present. As a result, it is often easier to simply run the Get-EventLog command from the
[blog post](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/),
rather than using Test-ProxyLogon.
