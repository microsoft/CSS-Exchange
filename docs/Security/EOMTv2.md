# Exchange On-premises Mitigation Tool v2 (EOMTv2)

!!! warning "Please read carefully"

      The vulnerability addressed by this mitigation script has been addressed in [latest Exchange Server Security Updates](https://aka.ms/LatestExchangeServerUpdate) (starting with November 2022 SU). Mitigations can become insufficient to protect against all variations of an attack. Thus, installation of an applicable SU is the only way to protect your servers. Once you install the updates, you can rollback the mitigation as described in the [Exchange On-premises Mitigation Tool v2 Examples](#exchange-on-premises-mitigation-tool-v2-examples) section.

Download the latest release: [EOMTv2.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/EOMTv2.ps1)

The Exchange On-premises Mitigation Tool v2 script (EOMTv2.ps1) can be used to mitigate **CVE-2022-41040**. This script does the following:

- Check for the latest version of EOMTv2.ps1 and download it.
- Mitigate against current known attacks using **CVE-2022-41040** via a URL Rewrite configuration

Use of the Exchange On-premises Mitigation Tool v2 is subject to the terms of the Microsoft Privacy Statement: https://aka.ms/privacy

## Requirements to run the Exchange On-premises Mitigation Tool v2

- PowerShell 3 or later
- PowerShell script must be run as Administrator.
- IIS 7.5 and later
- Exchange 2013 Client Access Server role, Exchange 2016 Mailbox role, or Exchange 2019 Mailbox role
- Windows Server 2008 R2, Server 2012, Server 2012 R2, Server 2016, Server 2019
   - If Operating System is older than Windows Server 2016, must have [KB2999226](https://support.microsoft.com/en-us/topic/update-for-universal-c-runtime-in-windows-c0514201-7fe6-95a3-b0a5-287930f3560c) for IIS Rewrite Module 2.1 to work.
- [Optional] External Internet Connection from your Exchange server (required to update the script and install IIS URL rewrite module).

**NOTE:** The script has to be executed individually for each server.

## Exchange On-premises Mitigation Tool v2 Examples

The default recommended way of using EOMTv2.ps1. This will apply the URL rewrite mitigation. If IIS URL rewrite module is not installed, this will also download and install the module.

```powershell
.\EOMTv2.ps1
```

To roll back EOMTv2 mitigations run

```powershell
.\EOMTv2.ps1 -RollbackMitigation
```
