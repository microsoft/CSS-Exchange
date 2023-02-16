---
hide:
  - toc
---

# Emerging Issues for Exchange On-Premises

This page lists emerging issues for Exchange On-Premises deployments, possible root cause and solution/workaround to fix the issues. The page will be consistently updated with new issues found and reflect current status of the issues mentioned.

**Updated on 2/16/2023**
**Following is list of known issues that can occur after installing [February 2023 Security Update](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-february-2023-exchange-server-security-updates/ba-p/3741058) on Exchange Servers**
**Issue** |**Products impacted** | **Possible reason**| **Workaround/Solution**
-|-|-|-
After installing [February 2023 Security Update](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-february-2023-exchange-server-security-updates/ba-p/3741058), you may observe EWS application pool crash with Event ID 4999 with following error <BR><BR> E12IIS, c-RTL-AMD64, 15.01.2507.021, w3wp#MSExchangeServicesAppPool, M.Exchange.Diagnostics, M.E.D.ChainedSerializationBinder.EnforceBlockReason, M.E.Diagnostics.BlockedDeserializeTypeException, 437c-dumptidset, 15.01.2507.021. <BR><BR> The issue also may cause connectivity issues to EWS based clients like Outlook for Mac | Exchange 2016, Exchange 2019| Still under investigation | Follow these steps to workaround the issue: <BR> <BR> 1. Create the string type (Reg_SZ) regkey named **"DisableBaseTypeCheckForDeserialization"** with value of **1** under **HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics\** <BR> 2. Use following steps to create setting override:<BR> a.	**New-SettingOverride -Name "Adding learning location ClientExtensionCollectionFormatter" -Component Data -Section DeserializationBinderSettings -Parameters @("LearningLocations=ClientExtensionCollectionFormatter") -Reason "Deserialization failed"** <BR>b.  Use following command to force the setting or wait for 30 minutes <BR>**Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh** |

**Updated on 2/15/2023**

**Following is list of known issues that can occur after installing [January 2023 Security Update](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-january-2023-exchange-server-security-updates/ba-p/3711808) on Exchange Servers**

**Issue** |**Products impacted** | **Possible reason**| **Workaround/Solution**
-|-|-|-
You may find  various Exchange commands and scripts (example: RedistributeActiveDatabases.ps1) that use deserialization failing with the error similar to : <BR> Error: "Cannot convert the value of type.....to type". | Exchange 2016 <BR> Exchange 2019 | The issue occurs if the [certificate signing for serialization of PowerShell](https://aka.ms/HC-SerializedDataSigning) is enabled and if the auth certificate is not present or has expired | Option 1: <BR> Use the [MonitorExchangeAuthCertificate.ps1](https://aka.ms/MonitorExchangeAuthCertificate) script to update the auth certificate. <BR> Option 2:<BR> Use the steps [here](https://aka.ms/AuthCertRenew) to correct the issue with auth certificate |
RecoverServer may fail at pre-requisites check with following error: <BR> "Exchange Server version Version 15.1 (Build 2507.17) or later must be used to perform a recovery of this server." | Exchange 2016 <BR> Exchange 2019 | Resolved | [February 2023](https://support.microsoft.com/help/5023038) and newer SUs will not cause this issue (but modifications made by the January 2023 SU might still require manual action during a server recovery operation). Follow steps on [this article](https://learn.microsoft.com/exchange/troubleshoot/setup/version-error-in-recover-server-mode-install) to fix the issue. |
The Exchange services in Automatic start-up mode will not start after reboot of the server. The services start successfully if started manually | Exchange 2016 installed on Windows 2012 R2, other versions are not affected | Resolved | Install the [February 2023 Exchange Server Security Updates](https://support.microsoft.com/help/5023038) to fix the issue |
The Exchange toolbox may start crashing on launch after [certificate Serialization for PowerShell](https://aka.ms/HC-SerializedDataSigning) is enabled. The error noticed is "Deserialization fails: System.Reflection.TargetInvocationException".|Exchange 2016 <BR> Exchange 2019 | Under investigation | Use one of the workarounds described in [this article](https://support.microsoft.com/help/5023352)
Get-ExchangeCertificate command may not list any certificates | Exchange 2016 <BR> Exchange 2019 <BR> | Under investigation | Launch the Exchange management shell in elevated mode and then use Get-ExchangeCertificate command






**Updated on 11/8/2022**

**Issue** |**Possible reason**| **Workaround/Solution**
-|-|-
Zero-day vulnerabilities reported in Microsoft Exchange Server, CVE-2022-41040 and  CVE-2022-41082 | N/A| Install [November 2022 Exchange Server Security Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-november-2022-exchange-server-security-updates/ba-p/3669045) to address the vulnerability

**Updated on 5/11/2022**

**Issue** |**Possible reason**| **Workaround/Solution**
-|-|-
After installing [March 2022 Security Update For Exchange Server 2013, 2016, 2019](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2022-exchange-server-security-updates/ba-p/3247586), the Microsoft Exchange Service Host service may crash repeatedly with Event ID 7031 in system log and Event ID 4999 in application log. <BR><BR>  Event ID 4999 <BR> Watson report about to be sent for process id: 4564, with parameters: E12IIS, c-RTL-AMD64, 15.01.2375.024, M.Exchange.ServiceHost, M.Exchange.Diagnostics, M.E.D.ChainedSerializationBinder.LoadType, M.E.Diagnostics.BlockedDeserializeTypeException, c0e9-DumpTidSet, 15.01.2375.024.|The issue can occur if there are any expired certificates present on or any certificates nearing expiry on the server| Install [May 2022 Exchange Server Security Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-may-2022-exchange-server-security-updates/bc-p/3356108) to resolve the issue


**Updated on 3/16/2022**

**Issue** |**Possible reason**| **Workaround/Solution**
-|-|-
After installing [March 2022 Security Update For Exchange Server 2013, 2016, 2019](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2022-exchange-server-security-updates/ba-p/3247586), the Microsoft Exchange Service Host service may crash repeatedly with Event ID 7031 in system log and Event ID 4999 in application log. <BR><BR>  Event ID 4999 <BR> Watson report about to be sent for process id: 4564, with parameters: E12IIS, c-RTL-AMD64, 15.01.2375.024, M.Exchange.ServiceHost, M.Exchange.Diagnostics, M.E.D.ChainedSerializationBinder.LoadType, M.E.Diagnostics.BlockedDeserializeTypeException, c0e9-DumpTidSet, 15.01.2375.024.|The issue can occur if there are any expired certificates present on or any certificates nearing expiry on the server| **Update 3/16/2022** <BR><BR> Follow the steps from [KB 5013118](https://support.microsoft.com/kb/5013118) to resolve the issue | NA | 1) Run the Get-MailboxDatabaseCopyStatus command from Exchange 2016/2019 servers <BR> 2) For Exchange Admin Center issue, make sure the mailbox of admin account is on Exchange 2016/2019 servers.

## Old Issues

### [Email Stuck in Transport Queues](https://techcommunity.microsoft.com/t5/exchange-team-blog/email-stuck-in-transport-queues/ba-p/3049447)
**Issue** | **Possible reason** | **Workaround/Solution**
-|-|-
You may observe emails building up in the transport queues of Exchange Server 2016 and Exchange Server 2019. The issue does not impact Exchange 2013 servers.<BR><BR>Following events may be noticed in the application log:<BR><BR> Log Name: Application<BR>Source: FIPFS<BR>Logged: 1/1/2022 1:03:42 AM <BR> Event ID: 5300 <BR> Level: Error <BR>Computer: server1.contoso.com<BR>Description: The FIP-FS "Microsoft" Scan Engine failed to load. PID: 23092, Error Code: 0x80004005.<BR>Error Description: Can't convert "2201010001" to long. <BR><BR> Log Name: Application <BR> Source: FIPFS <BR> Logged: 1/1/2022 11:47:16 AM <BR> Event ID: 1106 <BR> Level: Error <BR> Computer: server1.contoso.com <BR> Description: The FIP-FS Scan Process failed initialization. Error: 0x80004005. Error Details: Unspecified error. | The problem relates to a date check failure with the change of the new year and it not a failure of the AV engine itself. This is not an issue with malware scanning or the malware engine, and it is not a security-related issue. The version checking performed against the signature file is causing the malware engine to crash, resulting in messages being stuck in transport queues. | Run [this script](https://aka.ms/ResetScanEngineVersion) on each Exchange server in your organization. You can run this script on multiple servers in parallel. Check [this article](https://techcommunity.microsoft.com/t5/exchange-team-blog/email-stuck-in-transport-queues/ba-p/3049447) for detailed steps.




### November 2021 Security Update
Following are the known issues after installing [November 2021 Security Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-november-2021-exchange-server-security-updates/ba-p/2933169) for Exchange On-Premises servers

**Issue** | **Possible reason** | **Workaround/Solution**
-|-|-
Hybrid OWA Redirect is broken after application of November SU for Exchange 2013/2016 and 2019. <BR><BR> Users using Exchange 2016 and 2019 server will see error ":-( Something went wrong. We can't get that information right now. Please try again later. <BR><BR> Exchange 2013 users will see error "External component has thrown an exception." <BR><BR> Some On-Premises environments, that are not using FBA, may also see cross-site OWA redirection fail with similar errors.| After installing November SU, the OWA redirection URL for hybrid users is providing an encoded URL for &., causing the redirect to fail |**Update 1/12/2022** <BR><BR> The OWA redirection issue is fixed in [January 2022 security updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-january-2022-exchange-server-security-updates/ba-p/3050699). Please install the relevant update to fix the issue. <BR> <BR> Alternatively, you can also use the workarounds provided in  [KB article 5008997](https://support.microsoft.com/en-us/help/5008997) | Email clients might see repeated password prompts after the installation of Windows November Security Update for [CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) is installed on the Domain Controllers.| -- | Please see [KB5008720](https://support.microsoft.com/help/5008720).

### September Cumulative Updates
Following are the known issues after installing September 2021 Cumulative Updates for Exchange On-Premises servers

**Issue** | **Possible reason** | **Workaround/Solution**
-|-|-
After installing the September 2021 CU, the Microsoft Exchange Transport Services will continue to crash. You can see the following message for the 4999 crash event <BR><BR> `Watson report about to be sent for process id: 10072, with parameters: E12IIS, c-RTL-AMD64, 15.02.0986.005, MSExchangeDelivery, M.Exchange.Transport, M.E.T.AcceptedDomainTable..ctor, System.FormatException, 28d7-DumpTidSet, 15.02.0986.005.` | Having a Wild Card Only (*) Accepted Domain Set on an Internal Relay. This is an open relay and is very bad to have set. | Remove the Accepted Domain that is set to `*` and properly configure an anonymous relay on a receive connector or change to an External Relay. <BR><BR>More Information: [Allow anonymous relay on Exchange servers](https://docs.microsoft.com/en-us/Exchange/mail-flow/connectors/allow-anonymous-relay?view=exchserver-2019)

### July 2021 Security Update/Cumulative Updates
Following are the known issues after installing July 2021 Security Updates/Cumulative Updates for Exchange On-Premises servers

**Issue** | **Possible reason** | **Workaround/Solution**
-|-|-
OWA/ECP stops working after installing July Security Update with following error: <BR> **ASSERT: HMACProvider.GetCertificates:protectionCertificates.Length<1** | The issue occurs if OAuth certificate is missing or expired | Follow steps on [this](https://docs.microsoft.com/en-us/exchange/troubleshoot/administration/cannot-access-owa-or-ecp-if-oauth-expired) article to re-publish the Oauth certificate. Do note it takes up to an hour for certificate to change place
OWA/ECP stops working when accessed from load balanced URL, but works if directly accessed from the server URL | The root cause for the issue is under investigation | Follow steps in [this article](https://support.microsoft.com/en-us/help/5005341) to fix the issue
PrepareAD with Exchange 2016 CU21/Exchange 2019 CU10 error: <BR> Used domain controller dc1.contoso.com to read object CN=AdminSDHolder,CN=System,DC=Contoso,DC=COM. [ERROR] Object reference not set to an instance of an object. | The issue is under investigation | Follow steps in [this article](https://support.microsoft.com/kb/5005319) to fix the issue
PrepareSchema in environments that have empty root AD domain | July Security Update for Exchange 2013 have shipped schema changes and needs Exchange role installed for PrepareSchema, this makes it difficult for environments that have Exchange 2013 as the highest installed Exchange server and do not have an Exchange server installed in the same AD site as that of root AD domain. | Option 1 <BR>	Introduce a new server that meets system requirements for Exchange 2013 Management tools, in the root AD domain. Install just the Exchange 2013 Management Tools role on this server. <BR> Install the July security fix, perform Schema update. <BR> <BR> Option 2 <BR>	PrepareSchema using Exchange 2016 21/Exchange 2019 CU10 media, as the CU’s have the changes. <BR> However, once Exchange 2016/2019 media is used to perform schema update, you will need to continue using Exchange 2016/2019 media in the future as well.
The Schema Version number for Exchange 2013 environment remains on 15312, even after installing SU and performing PrepareSchema | This is expected behavior. The schema version is going to remain 15312 after installing Security Update and performing PrepareSchema
After installing Exchange 2016 CU21/Exchange 2019 CU10, the values added to custom attributes using EAC are not retained. The scenario works fine in Exchange 2016 CU20/Exchange 2019 CU9 | The issue is under investigation | **Workaround 1:** <BR> Use EAC from Internet Explorer <BR><BR> **Workaround 2:**<BR> Add the values using Exchange Management Shell
