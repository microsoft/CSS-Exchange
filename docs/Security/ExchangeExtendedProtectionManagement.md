# ExchangeExtendedProtectionManagement

Download the latest release: [ExchangeExtendedProtectionManagement.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeExtendedProtectionManagement.ps1)

The Exchange Extended Protection Management is a script to help automate the Extended Protection feature on the Windows Authentication Module on Exchange Servers. Prior to configuration, it validates that all servers that we are trying to enable Extended Protection on and the servers that already have Extended Protection enabled have the same TLS settings and other prerequisites that are required for Extended Protection to be enabled successfully.

## Requirements

The user must be in `Organization Management` and must run this script from an
elevated Exchange Management Shell (EMS) command prompt.

## How To Run

#### Examples:

This syntax enables Extended Protection on all Exchange Servers that are online that we can reach.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1
```

This syntax enables Extended Protection on only the Exchange Servers specified
in the -ExchangeServerNames parameter. However, TLS checks will still occur against all
servers, and the script will confirm that the TLS settings are correct on all servers
with Extended Protection enabled and all servers specified in the -ExchangeServerNames parameter.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -ExchangeServerNames <Array_of_Server_Names>
```

This syntax enables Extended Protection on all Exchange Servers that are online that we
can reach, excluding any servers specified in the -SkipExchangeServerNames parameter.
As above, TLS checks will still occur against all servers, and the script will confirm
that the TLS settings are correct on all servers with Extended Protection enabled and all
servers being enabled.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -SkipExchangeServerNames <Array_of_Server_Names>
```

This syntax collects the possible IP addresses to be used for the IP restriction for a virtual directory. Plus the location to store the file.

**NOTE:** This is only to assist you with the IP collections. You must verify the list to make sure it is accurate and contains all the required IP addresses.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -FindExchangeServerIPAddresses -OutputFilePath "C:\temp\ExchangeIPs.txt"
```

This syntax will enable Extended Protection for all virtual directories and set EWS Backend virtual directory to None and then proceed to set IP restriction for the EWS Backend virtual directory for all servers online, while providing the IP address list.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -RestrictType "EWSBackend" -IPRangeFilePath "C:\temp\ExchangeIPs.txt"
```

This syntax will verify the IP restrictions for the EWS Backend virtual directory.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -ValidateType "RestrictTypeEWSBackend" -IPRangeFilePath "C:\temp\ExchangeIPs.txt"
```

This syntax rolls back the Extended Protection configuration for all the Exchange Servers that are online where Extended Protection was previously configured.

**NOTE:** This is done by restoring the applicationHost.config file back to the previous state before Extended Protection was configured. If other changes occurred after this configuration, those changes will be lost.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -RollbackType "RestoreIISAppConfig"
```

This syntax rolls back the Extended Protection mitigation of IP restriction for the EWS Backend virtual directory of all the Exchange Server that are online where Extended Protection was previously configured.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -RollbackType "RestrictTypeEWSBackend"
```

This syntax displays the current Extended Protection configuration for all the Exchange Servers that are online.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -ShowExtendedProtection
```

## Parameters

Parameter | Description
----------|------------
ExchangeServerNames | A list of servers to pass that you want to run the script against. This can be used for configuration or rollback.
SkipExchangeServerNames | A list of server to pass that you don't want to execute the script for configuration or rollback.
ShowExtendedProtection | Show the current configuration of Extended Protection for the passed server list.
FindExchangeServerIPAddresses | Use this to collect a list of the Exchange Server IPs that should be used for IP Restriction.
OutputFilePath | Is a custom file path to be used to export the list of Exchange Server IPs collected from `FindExchangeServerIPAddresses`. Default value is the local location `IPList.txt`.
IPRangeFilePath | Is the path to the file that contains all the IP Addresses or subnets that are needed to be in the IP Allow list for Mitigation.
RestrictType | To enable a IP Restriction on a virtual directory. Must be used with `IPRangeFilePath`. The following values are allowed: `EWSBackend`
ValidateType | To verify if the IP Restrictions have been applied correctly. Must be used with `IPRangeFilePath`. The following values are allowed: `RestrictTypeEWSBackend`
RollbackType | Using this parameter will allow you to rollback using the type you specified. The following values are allowed: `RestoreIISAppConfig`, `RestrictTypeEWSBackend`
SkipAutoUpdate | Skips over the Auto Update feature to download the latest version of the script.
