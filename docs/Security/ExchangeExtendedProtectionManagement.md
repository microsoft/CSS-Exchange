# ExchangeExtendedProtectionManagement

Download the latest release: [ExchangeExtendedProtectionManagement.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeExtendedProtectionManagement.ps1)

The Exchange Extended Protection Management is a script to help automate the Extended Protection feature on the Windows Authentication Module on Exchange Servers. Prior to configuration, it validates that all servers that we are trying to enable Extended Protection on and the servers that already have Extended Protection enabled have the same TLS settings and other prerequisites that are required for Extended Protection to be enabled successfully.

## Requirements
#### Required Permissions:
However, if the group membership was adjusted or in case the script is executed on a non-Exchange system like a management server, you need to add your account to the `Local Administrator` group. You also need to be a member of the group `Organization Management`


## How To Run
This script **must** be run as Administrator in Exchange Management Shell on an Exchange Server or already in an Exchange Management Shell session.

#### Examples:

This cmdlet will run Exchange Extended Protection Management by default and try to configure all the Exchange Servers that are online that we can reach.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1
```

This cmdlet will run Exchange Extended Protection Management and configure only the ExchangeServerNames that are passed. However, TLS checks will still occur against all online servers that have Extended Protection already enabled on.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -ExchangeServerNames <Array_of_Server_Names>
```

This cmdlet will run Exchange Extended Protection Management and remove the Exchange Servers within the list of servers passed with the `SkipExchangeServerNames` parameter. However, TLS checks will still occur against these servers if Extended Protection is already enabled on them.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -SkipExchangeServerNames <Array_of_Server_Names>
```

This cmdlet will run Exchange Extended Protection Management rollback for all the Exchange Servers that are online where Extended Protection was previously configured. **NOTE:** This is done by restoring the applicationHost.config file back to the previous state before Extended Protection was configured. If other changes occurred after this configuration, those changes will be lost.

```powershell
PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -RollbackType "RestoreIISAppConfig"
```

This cmdlet will show the current Extended Protection configuration for all the Exchange Servers that are online.

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
