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

This syntax rolls back the Extended Protection configuration for all the Exchange Servers that are online where Extended Protection was previously configured.

**NOTE:** This is done by restoring the applicationHost.config file back to the previous state before Extended Protection was configured. If other changes occurred after this configuration, those changes will be lost.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -RollbackType "RestoreIISAppConfig"
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
RollbackType | Using this parameter will allow you to rollback using the type you specified. The follow values are allowed: `RestoreIISAppConfig`
RestrictType | Using this parameter to restrict incoming IP connections on specified vDir.
IPRangeFilePath | This is a mandatory parameter which must be used to provide an allow list of IP ranges when `RestrictType` parameter is used.
ValidateType | Used to cross check allow list of IP addresses on vDir against IPList file provided in `IPRangeFilePath`.
FindExchangeServerIPAddresses | Used to create list of IPv4 and IPv6 addresses of all Exchange Servers in the organization.
