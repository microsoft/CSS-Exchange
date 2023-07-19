# Test-AMSI

The Windows AntiMalware Scan Interface (AMSI) is a versatile standard that allows applications and services to integrate with any AntiMalware product present on a machine. Seeing that Exchange administrators might not be familiar with AMSI, we wanted to provide a script that would make life a bit easier to test, enable, disable, or Check your AMSI Providers.

## Download

Download the latest release: [Test-AMSI.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-AMSI.ps1)

## Parameters

Parameter | Description |
----------|-------------|
TestAMSI | If you want to test to see if AMSI integration is working. You can use a server, server list or FQDN of load balanced array of Client Access servers.
IgnoreSSL | If you need to test and ignoring the certificate check.
CheckAMSIConfig | If you want to see what AMSI Providers are installed. You can combine with ServerList, AllServers or Sites.
EnableAMSI | If you want to enable AMSI. Without any additional parameter it will apply at Organization Level. If combine with ServerList, AllServers or Sites it will apply at server level.
DisableAMSI | If you want to disable AMSI. Without any additional parameter it will apply at Organization Level. If combine with ServerList, AllServers or Sites it will apply at server level.
RestartIIS | If you want to restart the Internet Information Services (IIS). You can combine with ServerList, AllServers or Sites.
Force | If you want to restart the Internet Information Services (IIS) without confirmation.
ServerList | If you want to apply to some specific servers.
AllServers | If you want to apply to all server.
Sites | If you want to apply to all server on a sites or list of sites.

## Common Usage

After you download the script, you will need to run it within an elevated Exchange Management Shell Session

If you want to test to see if AMSI integration is working in a LB Array, you can run: `.\Test-AMSI.ps1 mail.contoso.com`

If you want to test to see if AMSI integration is working in list of servers, you can run: `.\Test-AMSI.ps1 -ServerList server1, server2`

If you want to test to see if AMSI integration is working in all server, you can run: `.\Test-AMSI.ps1 -AllServers`

If you want to test to see if AMSI integration is working in all server in a list of sites, you can run: `.\Test-AMSI.ps1 -AllServers -Sites Site1, Site2`

If you need to test and ignoring the certificate check, you can run: `.\Test-AMSI.ps1 -IgnoreSSL`

If you want to see what AMSI Providers are installed on the local machine you can run: `.\Test-AMSI.ps1 -CheckAMSIConfig`

If you want to enable AMSI at organization level, you can run: `.\Test-AMSI.ps1 -EnableAMSI`

If you want to enable AMSI in an Exchange Server or Server List at server level, you can run: `.\Test-AMSI.ps1 -EnableAMSI -ServerList Exch1, Exch2`

If you want to enable AMSI in all Exchange Server at server level, you can run: `.\Test-AMSI.ps1 -EnableAMSI -AllServers`

If you want to enable AMSI in all Exchange Server in a site or sites at server level, you can run: `.\Test-AMSI.ps1 -EnableAMSI -AllServers -Sites Site1, Site2`

If you want to disable AMSI on the Exchange Server, you can run: `.\Test-AMSI.ps1 -DisableAMSI`

If you want to disable AMSI in an Exchange Server or Server List at server level, you can run: `.\Test-AMSI.ps1 -DisableAMSI -ServerList Exch1, Exch2`

If you want to disable AMSI in all Exchange Server at server level, you can run: `.\Test-AMSI.ps1 -DisableAMSI -AllServers`

If you want to disable AMSI in all Exchange Server in a site or sites at server level, you can run: `.\Test-AMSI.ps1 -DisableAMSI -AllServers -Sites Site1, Site2`

If you want to restart the Internet Information Services (IIS), you can run: `.\Test-AMSI.ps1 -RestartIIS`

If you want to restart the Internet Information Services (IIS) without confirmation, you can run: `.\Test-AMSI.ps1 -RestartIIS -Force`
