---
title: Emerging Issues
nav_order: 2
---

# Emerging Issues for Exchange On-Premises

This page lists emerging issues for Exchange On-Premises deployments, possible root cause and solution/workaround to fix the issues. The page will be consistently updated with new issues found and reflect current status of the issues mentioned.

Following are the known issues with July 2021 security updates/cumulaive updates for Exchange On-Premises servers

**Issue** | **Possible reason** | **Workaround/Solution**
-|-|-
OWA/ECP stops working after installing July Security update with following error: <BR> **ASSERT: HMACProvider.GetCertificates:protectionCertificates.Length<1** | The issue occurs if OAuth certificate is missing or expired | Follow steps on [this](https://docs.microsoft.com/en-us/exchange/troubleshoot/administration/cannot-access-owa-or-ecp-if-oauth-expired) article to re-publish the Oauth certificate. Do note it takes up to an hour for certificate to change place
OWA/ECP stops working when accessed from load balanced URL, but works if directly accessed from the server URL | The root cause for the issue is under investigation | Follow steps in [this article](https://support.microsoft.com/en-us/help/5005341) to fix the issue
PrepareAD with Exchange 2016 CU21/Exchange 2019 CU10 error: <BR> Used domain controller dc1.contoso.com to read object CN=AdminSDHolder,CN=System,DC=Contoso,DC=COM. [ERROR] Object reference not set to an instance of an object. | The issue is under investigation | Follow steps in [this article](https://support.microsoft.com/kb/5005319) to fix the issue
PrepareSchema in environments that have empty root AD domain | July secruity update for Exchange 2013 have shipped schema changes and needs Exchange role installed for PrepareSchema, this makes it difficult for environments that have Exchange 2013 as the highest installed Exchange server and do not have an Exchange server installed in the same AD site as that of root AD domain. | Option 1 <BR>	Introduce a new server that meets system requirements for Exchange 2013 Management tools, in the root AD domain. Install just the Exchange 2013 Management Tools role on this server. <BR> Install the July security fix, perform Schema update. <BR> <BR> Option 2 <BR>	PrepareSchema using Exchange 2016 21/Exchange 2019 CU10 media, as the CU’s have the changes. <BR> However, once Exchange 2016/2019 media is used to perform schema update,you will need to continue using Exchange 2016/2019 media in the future as well.
The Schema Version number for Exchange 2013 environment remains on 15312, even after installing SU and performing PrepareSchema | This is expected behavior. The schema version is going to remain 15312 after installing Security Update and performing PrepareSchema
After installing Exchange 2016 CU21/Exchange 2019 CU10, the values added to custom attributes using EAC are not retained. The scenario works fine in Exchange 2016 CU20/Exchange 2019 CU9 | The issue is under investigation  |**Workaround 1:** <BR> Use EAC from Internet Explorer <BR><BR> **Workaround 2:**<BR> Add the values using Exchange Management Shell
