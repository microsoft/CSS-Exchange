---
title: Test-AMSI.ps1
parent: Admin
---

# Test-AMSI

The Windows Antimalware Scan Interface (AMSI) is a versatile standard that allows applications and services to integrate with any antimalware product present on a machine. Seeing that Exchange administrators might not be familiar with AMSI, we wanted to provide a script that would make life a bit easier to test, enable, disable, or Check your AMSI Providers.

## Download

Download the latest release: [Test-AMSI.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-AMSI.ps1)

## Common Usage

After you download the script, you will need to run it within an elevated Exchange Management Shell Session  

If you want to test to see if AMSI integration is working you can run: `.\Test-AMSI.ps1 -ExchangeServerFQDN mail.contoso.com`  

If you want to see what AMSI Providers are installed on the local machine you can run: `.\Test-AMSI.ps1 -CheckAMSIProviders`  

If you want to enable AMSI on the Exchange Server, you can run: `.\Test-AMSI.ps1 -EnableAMSI`  

If you want to disable AMSI on the Exchange Server, you can run: `.\Test-AMSI.ps1 -DisableAMSI`  

If you want to restart the Internet Information Services (IIS) you can run: `.\Test-AMSI.ps1 -RestartIIS`  

If you need to test and ignoring the certificate check you can run: `.\Test-AMSI.ps1 -IgnoreSSL`  

## More to come

1. We will be adding the ability to review the web.config to make sure that the HttpRequestFilteringModule line is present

2. We will be working on better output for PowerShell 7
