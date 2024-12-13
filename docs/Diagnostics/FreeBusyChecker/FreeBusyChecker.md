# Hybrid-Free-Busy-Configuration-Checker

View this Project at GitHub! [GitHub Repository](https://github.com/microsoft/CSS-Exchange/Diagnostics/FreeBusyChecker)

Download the latest release: [FreeBusyChecker.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/FreeBusyChecker.ps1)

To Provide Feedback about this tool: [Feedback Form](https://forms.office.com/pages/responsepage.aspx?id=v4j5cvGGr0GRqy180BHbR2LVru-UswhJmHot_XEUrVVURFVMRkE5VUg4QUU0MEpNRjgxUExPVlBVOS4u)


- This script does not make changes to current settings. It collects relevant configuration information regarding Hybrid Free Busy configurations on Exchange On Premises Servers and on Exchange Online, both for OAuth and DAuth.

- This is a Beta Version. Please double check on any information provided by this script before proceeding to address any changes to your Environment. Be advised that there may be incorrect content in the provided output.

Use: Collects OAuth and DAuth Hybrid Availability Configuration Settings Both for Exchange On Premises and Exchange Online if connected to Exchange Online using -Prefix EO before executing this script (see Usage bellow).

Example Screen Output:

![image](./image1.png)

Example TXT Output:

![image](./image2.png)

Example HTML Output

![image](./image3.png)

Supported Exchange Server Versions:

The script can be used to validate the Availability configuration for:

- Exchange Server
- Exchange Online

Required Permissions:

- Organization Management
- Domain Admins

Please make sure that the account used is a member of the Local Administrator group. This should be fulfilled on Exchange servers by being a member of the Organization Management group. However, if the group membership was adjusted or in case the script is executed on a non-Exchange system like a management server, you need to add your account to the Local Administrator group.

Other Pre Requisites:

AD management Tools:

If not available, they can be installed with the following command:

```powershell
  Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
```
Imports and Installs the following Modules (if not available):

PSSnapin: microsoft.exchange.management.powershell.snapin

Module  : ActiveDirectory Module
Module  : ExchangeOnlineManagement Module


## Syntax:

```powershell
    FreeBusyChecker.ps1
        [-Auth <string>]
        [-Org <string>]
        [-OnPremUser <string>]
        [-OnlineUser <string>]
        [-OnPremDomain <string>]
        [-OnPremEWSUrl <string>]
        [-OnPremLocalDomain <string>]
        [-Help <string>]
```

## Output

The script will generate the following files on the folder that contains the script file:

- Html File Output with Script Results, example: FreeBusyChecker_timestamp.html;
- txt File Output with Script Results, example: FreeBusyChecker_timestamp.txt;


## Usage:

- This script must be run as Administrator in Exchange Management Shell on an Exchange Server. You can provide no parameters and the script will just run against Exchange On Premises and Exchange Online (if connected to Exchange Online using -Prefix EO before executing this script) to query for OAuth and DAuth configuration setting. It will compare existing values with standard values and provide detail of what may not be correct.

- To connect to Exchange Online:

```powershell
          Connect-ExchangeOnline -Prefix EO
```

- Please take note that though this script may output that a specific setting is not a standard setting, it does not mean that your configurations are incorrect. For example, DNS may be configured with specific mappings that this script can not evaluate.


Valid Input Option Parameters:

  Parameter               : Auth
    Options               : All; DAuth; OAUth; Null

        All               : Collects information both for OAuth and DAuth;
        DAuth             : DAuth Authentication
        OAuth             : OAuth Authentication
        Default Value.    : Null. No switch input means the script will collect information for the current used method. If OAuth is enabled only OAuth is checked.

  Parameter               : Org
    Options               : ExchangeOnPremise; ExchangeOnline; Null

        ExchangeOnPremise : Use ExchangeOnPremise parameter to collect Availability information in the Exchange On Premise Tenant
        ExchangeOnline    : Use ExchangeOnline parameter to collect Availability information in the Exchange Online Tenant
        Default Value.    : Null. No switch input means the script will collect both Exchange On Premise and Exchange OnlineAvailability configuration Detail

  Parameter               : Help
    Options               : Null; True; False

        True              : Use the $True parameter to use display valid parameter Options.

  Parameter               : OnPremUser
    Options               : Exchange On premise Email Address

        OnPremUser        : Use OnPremUser parameter to run script using a specific Exchange on premises mailbox

  Parameter               : OnlineUser
    Options               : Exchange Online Hybrid Email Address

        OnlineUser        : Use OnlineUser parameter to run script using a specific Exchange Online Hybrid mailbox

  Parameter               : OnPremEWSUrl
    Options               : Exchange On Premises EWS url

        OnPremEWSUrl      : Use OnPremEWSUrl parameter to run script specifying the Exchange On Premises EWS url

  Parameter               : OnPremLocalDomain
    Options               : Exchange On Premises EWS url

        OnPremLocalDomain : Use OnPremLocalDomain parameter to run script specifying the Exchange On Premises local Domain


## Examples:

- This cmdlet will establish connection to Exchange Online using a Prefix to assure cmdlet independence between Exchange On Premises and Exchange Online. If connection to Exchange online is not established with "EO" Prefix script will collect Exchange On Premises Information only-

```powershell
          Connect-ExchangeOnline -Prefix EO
```

- This cmdlet will run Free Busy Checker script and check Availability for Exchange On Premises and Exchange Online for the currently used method, OAuth or DAuth. If OAuth is enabled OAUth is checked. If OAUth is not enabled, DAuth Configurations are collected.

```powershell
            PS C:\> .\FreeBusyChecker.ps1
```

- This cmdlet will run Free Busy Checker script and check Availability OAuth and DAuth Configurations both for Exchange On Premises and Exchange Online.

```powershell
            PS C:\> .\FreeBusyChecker.ps1 -Auth All
```

- This cmdlet will run the Free Busy Checker Script against for OAuth Availability Configurations only.

```powershell
            PS C:\> .\FreeBusyChecker.ps1 -Auth OAuth
```

- This cmdlet will run the Free Busy Checker Script against for DAuth Availability Configurations only.

```powershell
            PS C:\> .\FreeBusyChecker.ps1 -Auth DAuth
```

- This cmdlet will run the Free Busy Checker Script for Exchange Online Availability Configurations only.

```powershell
            PS C:\> .\FreeBusyChecker.ps1 -Org ExchangeOnline
```

- This cmdlet will run the Free Busy Checker Script for Exchange On Premises OAuth and DAuth Availability Configurations only.

```powershell
            PS C:\> .\FreeBusyChecker.ps1 -Org ExchangeOnPremise
```

- This cmdlet will run the Free Busy Checker Script for Exchange On Premises Availability OAuth Configurations using a specific On Premises mailbox

```powershell
            PS C:\> .\FreeBusyChecker.ps1 -Org ExchangeOnPremise -Auth OAuth -OnPremUser John.OnPrem@Contoso.com
```
