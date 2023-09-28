# Exchange Server Support for Windows Extended Protection

## Overview

[Windows Extended Protection](https://docs.microsoft.com/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/) enhances the existing authentication in Windows Server and mitigates authentication relay or "man in the middle" (MitM) attacks. This mitigation is accomplished by using security information that is implemented through Channel-binding information specified through a Channel Binding Token (CBT) which is primarily used for SSL connections.

Windows Extended Protection is supported on Exchange Server 2013, 2016 and 2019 starting with the [August 2022 Exchange Server Security Update (SU) releases](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-august-2022-exchange-server-security-updates/ba-p/3593862).

While Extended Protection can be enabled on each virtual directory manually, we have provided a script that can help you accomplish this in bulk. Windows Extended Protection is supported on Exchange Server 2013, 2016 and 2019 starting with the [August 2022 Exchange Server Security Update (SU) releases](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-august-2022-exchange-server-security-updates/ba-p/3593862).

## Terminology used in this document

**Virtual Directory, or vDir,** is used by Exchange Server to allow access to web applications such as Exchange ActiveSync, Outlook on the Web, and the Autodiscover service. Several virtual directory settings can be configured by an admin, including authentication, security, and reporting settings. Extended Protection is one such authentication setting.

**The Extended Protection setting** controls the behavior for checking of CBTs. Possible values for this setting are listed in the following table:

| **Extended Protection Setting** | **Description**                                                                                                                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| None                            | Specifies that IIS will not perform CBT checking.                                                                                                                                                                               |
| Allow                           | Specifies that CBT checking is enabled, but not required. This setting allows secure communication with clients that support extended protection, and still supports clients that are not capable of using extended protection. |
| Require                         | This value specifies that CBT checking is required. This setting blocks clients that do not support extended protection.                                                                                                        |

**SSL Flags**: Configuration of SSL settings is required to ensure that clients connect to IIS virtual directories in a specific way with client certificates. To enable Extended Protection, the required SSL flags are SSL and SSL128.

**SSL offloading** terminates the connection on a device between the client and the Exchange Server and then uses a non-encrypted connection to connect to the Exchange Server.

Example:

```mermaid
flowchart LR
    A[Client] ==>|HTTPS| B
    B["Device (e.g., Load Balancer) terminates the connection"] ==>|HTTP| C["Web Server"]
```

**SSL bridging** is a process where a device, usually located at the edge of a network, decrypts SSL traffic, and then re-encrypts it before sending it on to the Web server.

Example:

```mermaid
flowchart LR
    A[Client] ==>|HTTPS| B
    B["Device (e.g., Load Balancer) terminates the connection"] ==>|HTTPS| C["Web Server"]
```

**Modern Hybrid** or **Hybrid Agent** is a mode of configuring Exchange Hybrid that removes some of the configuration requirements for Classic Hybrid (like Inbound network connections through your firewall) to enable Exchange hybrid features. You can learn more about this [here](https://docs.microsoft.com/exchange/hybrid-deployment/hybrid-agent).

**Public Folders** are designed for shared access and to help make content in a deep hierarchy easier to browse. You can learn more about Public Folders [here](https://docs.microsoft.com/exchange/collaboration/public-folders/public-folders?view=exchserver-2019).

## Prerequisites for enabling Extended Protection on Exchange servers

### Make sure you are on the correct versions

Extended Protection is supported on Exchange Server 2013 CU23 and Exchange Server 2016 CU22 and Exchange Server 2019 CU11 or later with the August 2022 Security Updates installed.

If your organization has Exchange Server 2016 or Exchange Server 2019 installed, it must be running either the [September 2021 Quarterly Exchange Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-september-2021-quarterly-exchange-updates/ba-p/2779883) (CU) with the August 2022 Security Update (SU) or later installed or the [2022 H1 Cumulative Update](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-2022-h1-cumulative-updates-for-exchange-server/ba-p/3285026) (CU) with the August 2022 Security Update (SU) or later installed.

If your organization has Exchange Server 2013 installed, it must be running [CU23](https://www.microsoft.com/download/details.aspx?id=58392) with the August 2022 SU (or later) installed.

You **must** ensure **all** your Exchange servers are on the required CU and have the August 2022 SU (or later) before you proceed further.

### Extended Protection cannot be enabled on Exchange Server 2013 servers with Public Folders in a coexistence environment

To enable Extended Protection on Exchange Server 2013, ensure you do not have any Public Folders on Exchange Server 2013. If you have coexistence of Exchange Server 2013 with Exchange Server 2016 or Exchange Server 2019, you must migrate your Public Folders to 2016 or 2019 **before** enabling Extended Protection. After enabling Extended Protection, if there are Public Folders on Exchange 2013, they will no longer appear to end users.

### Extended Protection cannot be enabled on Exchange Server 2016 CU22 or Exchange Server 2019 CU11 or older that hosts a Public Folder Hierarchy

If you have an environment containing Exchange Server 2016 CU22 or Exchange Server 2019 CU11 or older and are utilizing Public Folders, before enabling extended protection **you must confirm the version of the server hosting the Public Folder hierarchy**. Ensure the server hosting the Public Folder hierarchy is upgraded to Exchange Server 2016 CU23 or Exchange Server 2019 CU12 with the latest Security Updates or move the hierarchy to one with these latest versions and updates.

The following table should help clarify:

| Exchange version  | CU installed    | SU installed         | Hosts PF mailboxes     | Is EP supported? |
| ----------------- | --------------- | -------------------- | ---------------------- | ---------------- |
| Exchange 2013     | CU23            | Aug 2022 (or higher) | No                     | Yes              |
| Exchange 2016     | CU22            | Aug 2022 (or higher) | No hierarchy mailboxes | Yes              |
| Exchange 2016     | CU23+ (2022 H1) | Aug 2022 (or higher) | Any                    | Yes              |
| Exchange 2019     | CU11            | Aug 2022 (or higher) | No hierarchy mailboxes | Yes              |
| Exchange 2019     | CU12+ (2022 H1) | Aug 2022 (or higher) | Any                    | Yes              |
| Any other version | Any other CU    | Any other SU         | Any                    | No               |

### Extended Protection does not work with hybrid servers using Modern Hybrid configuration

Extended Protection cannot be enabled on Hybrid Servers which uses Modern Hybrid configuration. In Modern Hybrid configuration, Hybrid Server are published to Exchange Online via Hybrid Agent which proxies the Exchange Online call to Exchange Server.

Enabling Extended Protection on Hybrid servers using Modern Hybrid configuration will lead to disruption of hybrid features like mailbox migrations and Free/Busy. Hence, it is important to identify all the Hybrid Servers in the organization published via Hybrid Agent and not enable Extended Protection specifically on these servers.

#### Identifying hybrid Exchange servers published using Hybrid Agent

!!! warning "Note"

      This step is not required if you are using classic Hybrid configuration.

In case you don’t have a list of servers published via Hybrid Agent, you can use the following steps to identify them:

1. Log into a machine where the Hybrid Agent is installed and running. Open the [PowerShell module](https://docs.microsoft.com/exchange/hybrid-deployment/hybrid-agent#hybrid-agent-powershell-module) of the Hybrid Agent and run _Get-HybridApplication_ to identify the _TargetUri_ used by the Hybrid Agent.
2. The _TargetUri_ parameter gives you the FQDN of the Exchange Server that is configured to use Hybrid Agent.
   1. Deduce the Exchange Server identity using the FQDN and make a note of this Exchange Server.
   2. If you are using a Load Balancer URL in _TargetUri_, you need to identify all the Exchange servers running the Client Access role behind the load balancer URL.

Extended Protection **should not be enabled for hybrid servers that are published using Hybrid Agent**. You need to identify these hybrid servers and ensure you skip enabling Extended Protection on them using the SkipExchangeServerNames parameter of the script.

#### Steps to safeguard hybrid servers using Modern Hybrid

1. Inbound connections to Exchange servers in a Modern Hybrid configuration should be restricted via firewall to allow connections only from Hybrid Agent machines.
2. No mailboxes should be hosted on the hybrid server, and if any mailbox exists, they should be migrated to other mailbox servers.
3. You can enable Extended Protection on all virtual directories except Front End EWS on the hybrid Exchange server.

!!! warning "Note"

      Specifically skipping extended protection on Front End EWS of Exchange Server is not supported via script. So, you would need to change this setting manually.

### NTLMv1 is not supported when Extended Protection is enabled

!!! warning "Note"

      To increase security, we recommend that you review and configure this setting regardless of whether you experience problems or not.

NTLMv1 is weak and doesn't provide protection against man-in-the-middle (MitM) attacks. It should be [considered as vulnerable](https://support.microsoft.com/topic/security-guidance-for-ntlmv1-and-lm-network-authentication-da2168b6-4a31-0088-fb03-f081acde6e73) and so, no longer be used. Therefore NTLMv1 should not be used together with Extended Protection. Additionally, if you enforce a client to use NTLMv1 instead of NTLMv2 and you have Extended Protection enabled on your Exchange server, this will lead to password prompts on the client side without a way to authenticate successfully against Exchange.

If you experience password prompts on your clients once Extended Protection is enabled, you should check the following registry key and value on client and Exchange server side:

Registry key: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`

Registry value: `LmCompatibilityLevel`

It must be set to at least `3` or higher (best practice is to set it to `5` which is: _Send NTLMv2 response only. Refuse LM & NTLM_). It's also possible to delete this value to enforce the system default. If it's not set, we treat it as if it is set to `3` (on Windows Server 2008 R2 and later) which is: _Send NTLMv2 response only_.
If you want to manage the setting centrally, you can do so via Group Policy:

Policy location: `Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options`

More information: [Network security: LAN Manager authentication level](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)

### SSL Offloading scenarios are not supported

Extended Protection is not supported in environments that use SSL offloading. SSL termination during SSL offloading causes Extended Protection to fail. To enable Extended Protection in your Exchange environment, **you must not be using SSL offloading** with your Load Balancers.

### SSL Bridging supported scenarios

Extended Protection is supported in environments that use SSL Bridging under certain conditions. To enable Extended Protection in your Exchange environment using SSL Bridging, **you must use the same SSL certificate on Exchange and your Load Balancers**. If not this will cause Extended Protection to fail.

### TLS configuration must be consistent across all Exchange servers

Before enabling Extended Protection, you must ensure that all TLS configurations are consistent across all Exchange servers. For example, if one of the servers uses TLS 1.2, you must ensure that all the servers in the organization are configured using TLS 1.2. Any variation in TLS version use across servers can cause client connections to fail.

In addition to this, the value of _SchUseStrongCrypto_ registry value must be set to 1 across all the Exchange Servers in the organization.
If this value is not explicitly set to 1, the default value of this key may be interpreted as 0 or 1 depending on the .NET version in use by the Exchange binaries.
The same applies to the _SystemDefaultTlsVersions_ registry value which must also be explicitly set to 1. If they aren't set as expected, this can cause TLS mismatch and so, leading to client connectivity issues.

Please refer to this [guide](https://docs.microsoft.com/Exchange/exchange-tls-configuration?view=exchserver-2019) to configure the required TLS settings on your Exchange servers.

### Third-party software compatibility

Please ensure to test all third-party products in your Exchange Server environment to ensure that they work properly when Extended Protection is enabled. For example we have seen AntiVirus solutions send connections through a proxy in order to protect the client machine, this would prevent communication to the Exchange Server and would need to be disabled.

## Enabling Extended Protection

Extended Protection can be enabled manually through IIS Manager or via a script (strongly recommended). To correctly configure Extended Protection, each virtual directory on all Exchange servers in the organization (excluding Edge Transport servers) should be set to prescribed value of Extended Protection as well as sslFlags. The following table summarizes the settings needed for each virtual directory on the supported versions of Microsoft Exchange.

Enabling Extended Protection involves making many changes on all Exchange servers, so **we strongly recommend using the ExchangeExtendedProtectionManagement.ps1 script** that can be downloaded from <https://aka.ms/ExchangeEPScript>.

| IIS Website      | Virtual Directory           | Recommended Extended Protection | Recommended sslFlags        |
| ---------------- | --------------------------- | ------------------------------- | --------------------------- |
| Default Website  | API                         | Required                        | Ssl,Ssl128                  |
| Default Website  | AutoDiscover                | Off                             | Ssl,Ssl128                  |
| Default Website  | ECP                         | Required                        | Ssl,Ssl128                  |
| Default Website  | EWS                         | Accept (UI) /Allow (Script)     | Ssl,Ssl128                  |
| Default Website  | MAPI                        | Required                        | Ssl,Ssl128                  |
| Default Website  | Microsoft-Server-ActiveSync | Accept (UI) /Allow (Script)     | Ssl,Ssl128                  |
| Default Website  | OAB                         | Accept (UI) /Allow (Script)     | Ssl,Ssl128                  |
| Default Website  | OWA                         | Required                        | Ssl,Ssl128                  |
| Default Website  | PowerShell                  | Required                        | SslNegotiateCert            |
| Default Website  | RPC                         | Required                        | Ssl,Ssl128                  |
| Exchange Backend | API                         | Required                        | Ssl,Ssl128                  |
| Exchange Backend | AutoDiscover                | Off                             | Ssl,Ssl128                  |
| Exchange Backend | ECP                         | Required                        | Ssl,Ssl128                  |
| Exchange Backend | EWS                         | Required                        | Ssl,Ssl128                  |
| Exchange Backend | Microsoft-Server-ActiveSync | Required                        | Ssl,Ssl128                  |
| Exchange Backend | OAB                         | Required                        | Ssl,Ssl128                  |
| Exchange Backend | OWA                         | Required                        | Ssl,Ssl128                  |
| Exchange Backend | PowerShell                  | Required                        | Ssl,SslNegotiateCert,Ssl128 |
| Exchange Backend | RPC                         | Required                        | Ssl,Ssl128                  |
| Exchange Backend | PushNotifications           | Required                        | Ssl,Ssl128                  |
| Exchange Backend | RPCWithCert                 | Required                        | Ssl,Ssl128                  |
| Exchange Backend | MAPI/emsmdb                 | Required                        | Ssl,Ssl128                  |
| Exchange Backend | MAPI/nspi                   | Required                        | Ssl,Ssl128                  |

!!! warning "Note"

      After initial release, we have updated `Default Website/OAB` to be `Accept/Allow` instead of `Required`. This is because of Outlook for Mac clients not being able to download the OAB any longer with the `Required` setting.

SSL offloading for Outlook Anywhere is enabled by default and must be disabled for extended protection by following the steps shown [here](https://docs.microsoft.com/powershell/module/exchange/set-outlookanywhere?view=exchange-ps#example-3).

### Enabling Extended Protection using the script

Before enabling Extended Protection in your Exchange environment, ensure you meet all the prerequisites listed in this document.

To enable Extended Protection on all your Exchange Servers, you can use the [ExchangeExtendedProtectionManagement.ps1](https://aka.ms/ExchangeEPScript) script, which is hosted on the Microsoft Exchange-CSS repository on GitHub.

It’s not required to run the script directly on any specific Exchange Server in your environment. Just copy it to a machine that has the Exchange Management Shell (EMS) installed.

!!! warning "Note"

      Over time, we will be updating the script and documentation. The script will attempt to auto-update when it is run. If the computer where the script is run is not connected to the Internet, this update check will fail. You should always check for the latest version of the script before running it.

#### Parameters

If the script is executed without any parameters, it will enable Extended Protection on any Exchange Server that can be reached from the machine where the script was run. You can use the following parameters to specify the scope of script operations:

| Parameter                     | Usage                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ExchangeServerNames           | Used to specify which Exchange servers should be **included in the scope of script execution**. It can be either a single Exchange server hostname or a comma separated list of hostnames. Parameter values: **Exchange Server Hostname (NetBIOS or FQDN)**                                                                                                                                  |
| SkipExchangeServerNames       | Used to specify which Exchange servers should be **excluded from the scope of script execution**. It can be either a single Exchange Server hostname or a comma separated list of hostnames. Parameter values: **Exchange Server Hostname (NetBIOS or FQDN)**                                                                                                                                |
| RollbackType                  | Used to revert changes made by the Extended Protection script. Parameter Values: **"RestoreIISAppConfig, RestrictTypeEWSBackend"**"                                                                                                                                                                                                                                                                                   |
| ShowExtendedProtection        | Used to display the current Extended Protection configuration state in your organization or on a specific computer (use the _ExchangeServerNames_ or _SkipExchangeServerNames_ parameter to show the configuration for a subset of Exchange servers).                                                                                                                                        |
| RestrictType                  | Used to restrict incoming IP connections on specified vDir Parameter Value: **EWSBackend**: This parameter should be used to restrict incoming IP connections to a specified allow list of IP addresses or Subnets. This will also turn off EP on EWSBackend. **Note:** This parameter should no longer be used. |
| IPRangeFilePath               | This is a mandatory parameter which must be used to provide an allow list of IP ranges when RestrictType parameter is used. The filepath provides should be of a .TXT file with IP addresses or subnets.                                                                                                                                                                                     |
| ValidateType                  | Used to cross check allow list of IP addresses on vDir against IPList file provided in IPRangeFilePath. Parameter Value: **RestrictTypeEWSBackend**: should be used to cross check allow list of IP addresses on EWS Backend vDir against IPList file provided in IPRangeFilePath.                                                                                                           |
| FindExchangeServerIPAddresses | Used to create list of IPv4 and IPv6 addresses of all Exchange Servers in the organization.                                                                                                                                                                                                                                                                                                  |

#### Enabling Extended Protection on all Exchange servers

After copying the script to a suitable machine, create a directory to store the script and move the script there. Then open the Exchange Management Shell (EMS) and go to the respective directory where the script is stored.

Make sure that the account you are using is a member of the **Organization Management** role group.

Execute the script as follows:

`.\ExchangeExtendedProtectionManagement.ps1`

In case that you have Modern Hybrid configuration, you need to skip Exchange servers published using the Hybrid Agent. This can be done by using the _SkipExchangeServerNames_ parameter:

`.\ExchangeExtendedProtectionManagement.ps1 -SkipExchangeServerNames HybridServer1, HybridServer2`

The script will check to ensure that all Exchange servers in scope have the minimum CU and SU required to enable Extended Protection.

The script will also check if all Exchange servers in scope have the same TLS configuration. An inconsistent (or invalid) TLS configuration will cause client connections or connections to Exchange Online to fail.

After the prerequisites checks have been passed, the script will enable Extended Protection and add the required SSL flags on all virtual directories of all Exchange servers in scope.

![Text Description automatically generated](attachments/9a4e6863e860e064d2831d7d714c95ce.png)

#### Scenario 1: Using Modern Hybrid Configuration or Hybrid Agent

In case you have Modern Hybrid configuration, you need to skip Exchange servers published using the Hybrid Agent. This can be done by using the _SkipExchangeServerNames_ parameter:

`.\ExchangeExtendedProtectionManagement.ps1 -SkipExchangeServerNames HybridServer1, HybridServer2`

Or

`.\ExchangeExtendedProtectionManagement.ps1 -RestrictType EWSBackend -IPRangeFilePath "IPList.txt" -SkipExchangeServerNames HybridServer1, HybridServer2`

#### Troubleshooting warnings and errors during script execution

1. Script gives a cursory warning of known issues before enabling Extended Protection:

      To prevent a scenario where existing Exchange functions are disrupted due to enabling Extended Protection, the script provides a list of scenarios that have known issues. You should **read and evaluate this list carefully** before enabling Extended Protection.
      You can proceed to turn on Extended Protection by pressing Y.

      ![Text Description automatically generated](attachments/7f3e88c6e5ca34c25c0e1ca9e684cb6a.png)

2. Script does not enable Extended Protection because of Failed Prerequisite Check:

      1. No Exchange server runs an Extended Protection supported build:

         If no Exchange server in the organization is running a CU that supports Extended Protection, the script will not enable Extended Protection on unsupported servers thereby ensuring server-to-server communication does not fail.
         To resolve this, upgrade all servers to the latest CU and SU and re-run the script to enable Extended Protection.

      2. TLS mismatch:

         A valid and consistent TLS configuration is required on all Exchange servers in scope. If the TLS settings on all servers in scope are not the same, enabling Extended Protection will disrupt client connections to mailbox servers.

         ![Text Description automatically generated](attachments/fca12d63a89e230c7f3cfaf67b642330.png)
         To resolve this, configure the TLS settings on all servers in the organization to be the same and then re-run the script. You can find an overview of the Exchange Server TLS configuration best practices [here](https://docs.microsoft.com/Exchange/exchange-tls-configuration).

3. Some Exchange servers are not reachable:

      The script performs multiple tests against all Exchange servers in scope. If one or more of these servers aren’t reachable, the script will exclude them and not configure Extended Protection on them.

      ![Text Description automatically generated](attachments/3095edc994a8aa4bb79f90fe519a0e36.png)
      If the server is offline, you should enable Extended Protection on it once it is back online. If the server was unreachable for other reasons, you should run the script directly on the servers to enable Extended Protection.

#### Rolling back Extended Protection settings

You can also use the script to roll back the **Extended Protection settings and any IP restriction rules** added via script from one or more servers. When Extended Protection settings are modified by the script, an applicationHost.cep.\*.bak file is created on each server, which contains a backup of pre-existing settings before the script is run. Those files are going to be local to each individual server that the script modifies. Therefore, the rollback of Extended Protection settings can be rolled back from any machine where the script will run using the _earliest_ version of the .bak file to roll back the changes.

The following command initiates a full rollback of **Extended Protection settings** and **IP restriction rules** on any Exchange server where it was enabled using the script:

`.\ExchangeExtendedProtectionManagement.ps1 –RollbackType RestoreIISAppConfig`

#### Rolling back IP Restriction settings

You can use the script to **only** roll back **Allow and Deny rules** set in Backend EWS vDir’s IP Address and Domain Restriction module in the following way.

`.\ExchangeExtendedProtectionManagement.ps1 -RollbackType RestrictTypeEWSBackend`

!!! warning "Note"

      To safeguard Backend EWS vDir against NTLM relay, executing above command will set Extended Protection setting back to Required.

### Enabling Extended Protection manually via IIS settings

If you want to enable Extended Protection in your environment manually without using the script, you can use the following steps.

!!! warning "Note"

      When manually enabling Extended Protection, ensure that all virtual directories on the Exchange servers have Extended Protected configured according to the table above.

#### Set Extended Protection to either Required or Accept for an Exchange Virtual Directory

1. Launch IIS Manager on the Exchange server where you want to configure Extended Protection.
2. Go to Sites and select either the _Default Web Site_ or _Exchange Back End._
3. Select the Virtual Directory for which you want to change.
4. Go to _Authentication._
5. If Windows Authentication is enabled, then select _Windows Authentication._
   ![Graphical user interface, application Description automatically generated](attachments/001f52d47d532f8ac8aa1aa3edb97520.png)
6. Select _Advanced Settings_ (on the right side) and in Advanced Settings window, select the suitable value from the _Extended Protection Dropdown._
   ![Graphical user interface, text, application Description automatically generated](attachments/4794e9f5b4d1e129ea38c0d2c2bd89fa.png)

#### Set Require SSL settings to either Required or Accept for an Exchange Virtual Directory

1. Go to the Virtual Directory’s home page.
   ![Graphical user interface, text, application, Word Description automatically generated](attachments/0d05a67039245dde885522e84ca74bc3.png)
2. Go to _SSL Settings_.
3. Check the _Require SSL_ checkbox to make sure that Require SSL is enabled for this Virtual Directory.
4. Click _Apply_.
   ![Graphical user interface, text, application, Word Description automatically generated](attachments/1663e8c2fdea930b47f01c6ab30b3aa8.png)

## Known issues and workarounds

**Issue:**

Changing the permissions for Public Folders by using an Outlook client will fail with the following error, if Extended Protection is enabled:

`The modified Permissions cannot be changed.`

**Cause:**

This happens if the Public Folder for which you try to change the permissions, is hosted on a secondary Public Folder mailbox while the primary Public Folder mailbox is on a different server.

**Status:**

!!! success "Fixed"

      The issue has been fixed with the [latest Exchange Server update](https://aka.ms/LatestExchangeServerUpdate).
      You'll need to create an override to enable the fix. Please follow the instructions as outlined in [this KB](https://support.microsoft.com/topic/bd2037b5-40e0-413a-b368-746b3f5439ee).

**Issue:**

Customers using a _Retention Policy_ containing _Retention Tags_ which perform _Move to Archive_ can now configure Extended Protection with this update. We are actively working on a permanent solution to resolve this issue. Once we ship the solution you will be required to run this script again and rollback the changes.

**Status:**

!!! success "Fixed"

      The archiving issue has been fixed with the [latest Exchange Server update](https://aka.ms/LatestExchangeServerUpdate).
      We recommend rolling back the mitigation by following the steps outlined in the [rollback section](#rolling-back-ip-restriction-settings).

**Issue:**

In Exchange Server 2013, 2016 and 2019 the following probes will show _FAILED_ status after running the script which switches on Extended Protection with required SSL flags on various vDirs as per recommended guidelines:

   1. OutlookMapiHttpCtpProbe
   2. OutlookRpcCtpProbe
   3. OutlookRpcDeepTestProbe
   4. OutlookRpcSelfTestProbe
   5. ComplianceOutlookLogonToArchiveMapiHttpCtpProbe
   6. ComplianceOutlookLogonToArchiveRpcCtpProbe

You will also notice that some Health Mailbox logins fail with event ID: 4625 and failure reason "_An Error occurred during Logon_" and status _0xC000035B_ which is related to the failed probes. [**Get-ServerHealth**](https://docs.microsoft.com/exchange/high-availability/managed-availability/health-sets?view=exchserver-2019#use-the-exchange-management-shell-to-view-a-list-of-monitors-and-their-current-health) command will also show RPC and Mapi monitors as Unhealthy.

**Impact of these failures:**

Due to this probe failure, the Mapi and Rpc App pools will get restarted once. There should be no other impact.

You can also turn off any of the above probes temporarily (till the fix is provided) by going through steps mentioned in [Configure managed availability overrides \| Microsoft Docs](https://docs.microsoft.com/exchange/high-availability/managed-availability/configure-overrides?view=exchserver-2019).

**Status:**

!!! success "Fixed"

      This issue has been addressed with the [October 2022 (and later) Exchange Server Security Updates](https://aka.ms/LatestExchangeServerUpdate).

## Troubleshooting issues after enabling Extended Protection

### Users cannot access their mailbox through one or more clients

There may be multiple reasons why some or all clients may start giving authentication errors to users after enabling Extended Protection. If this happens, check the following:

1. If the TLS configuration across the Exchange organization is not the same (e.g., the TLS configuration was changed on one of the Exchange servers after Extended Protection was enabled), this may cause client connections to fail. To resolve this, refer to earlier instructions to configure the same TLS version across all Exchange servers and then use the script to configure Extended Protection again.
2. Check if SSL offload is enabled. Any SSL termination causes the Extended Protection to fail for client connections. Usually if this is the case, users will be able to access their mailbox using Outlook on the Web but Outlook for Windows, Mac or mobile will fail.
   To resolve this issue, disable SSL offloading and then use the script to configure Extended Protection.
3. Users can access their emails using Outlook for Windows and Outlook on the Web, but not through non-Windows clients like Outlook for Mac, Outlook on iOS, the iOS native email app, etc. This can happen if the Extended Protection setting for EWS and/or Exchange ActiveSync is set to **Required** on one or all Front-End servers.
   To resolve this issue, either run the ExchangeExtendedProtectionManagement.ps1 script with the –ExchangeServerNames parameter and pass the name of the Exchange server which has the problem. You can also run the script without any parameter and configure Extended Protection for all servers.

   `.\ExchangeExtendedProtectionManagement.ps1`

   or

   `.\ExchangeExtendedProtectionManagement.ps1 -ExchangeServerNames Server1, Server2`

   Alternatively, you can also use INetMgr.exe and change the Extended Protection setting for those virtual Directories to the "Accept" value. However, we recommend using the script as it checks for the correct values and automatically performs a reconfiguration if the values are not set as expected.

4. If after doing the above, some clients are still not working properly, you can rollback Extended Protection temporarily and report the issue to us. If script was used to configure Extended Protection, you can use the _-RollbackType "RestoreIISAppConfig"_ parameter to revert any changes. If Extended Protection was enabled manually (through IIS Manager) you need to revert the settings manually.

### Hybrid Free/Busy or mailbox migration is not working

If you are using Modern Hybrid or the Hybrid Agent enabling Extended Protection will cause Hybrid features like Free/Busy and mailbox migration to stop working. To resolve this issue, identify the hybrid servers that are published using Hybrid Agent and disable Extended Protection on the Front-End EWS endpoints for these servers.

### Public Folders are not accessible

There are two issues that currently impact Public Folders Connectivity:

#### Exchange 2013

If Public Folders exist on Exchange 2013 servers and Extended Protection is enabled, they will no longer appear and end users will be unable to access them. To resolve the issue in a coexistence environment, migrate all Public Folders to Exchange Server 2016 or Exchange Server 2019. If you have an environment containing only Exchange 2013 servers with Public Folders, you can manually remove the SSL flag from the Backend RPC virtual directory to make Public Folders accessible.

#### Exchange Server 2016 CU22 / Exchange Server 2019 CU11 or older

If you have an environment containing Exchange Server 2016 CU22 or Exchange Server 2019 CU11 or older and are utilizing Public Folders, before enabling extended protection you must confirm the version of the server hosting the Public Folder hierarchy. **Ensure the server hosting the Public Folder hierarchy is upgraded to Exchange Server 2016 CU23 or Exchange Server 2019 CU12 with the latest Security Updates** or move the hierarchy to one with these latest versions and updates.

## FAQs

**Q:** Is it required to install the August 2022 Security Update (SU) if it was already installed on the previous Cumulative Update (CU)?<br>
**A:** Yes, it's required to install the August 2022 SU again if you update to a newer CU build (e.g., Exchange Server 2019 CU11 --> Exchange Server 2019 CU12).
Please remember:
If you plan to do the update immediately (means CU + SU installation) Extended Protection does not need to be switched off.
If you plan to stay on the CU without installing the SU immediately, you must disable Extended Protection (find the required steps above) as the CU without the SU being installed doesn't support Extended Protection and therefore, you'll experience client connectivity issues.

**Q:** Is it safe to enable Windows Extended Protection on an environment that uses Active Directory Federation Services (ADFS) for OWA?<br>
**A:** Yes, ADFS is not impacted by this change.


**Q:** Is it safe to enable Windows Extended Protection on an environment that uses Hybrid Modern Auth (HMA)?<br>
**A:** Yes, HMA is not impacted by this change. While EP does not further enhance HMA, windows auth may still be used for applications that do not support Hybrid Modern Auth. Considering this, the enablement of Extended Protection would be recommended in any environment eligible that still has Exchange on-premises services.

**Q:** Does Extended Protection Impact Hybrid Modern Auth or Teams Integration?<br>
**A:** Extended Protection will not influence Teams Integration or Hybrid Modern Auth.

**Q:** While we understand that preventing MitM attacks is important, can we have our own devices in the middle with our own certificates?<br>
**A:** If the device uses the same certificate as the Exchange Server, they can be used.
