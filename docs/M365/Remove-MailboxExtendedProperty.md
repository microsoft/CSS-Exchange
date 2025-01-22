# Remove-MailboxExtendedProperty

Download the latest release: [Remove-MailboxExtendedProperty.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Remove-MailboxExtendedProperty.ps1)

## Description

This script removes the named property from the message.

Initially get a list of named properties that you are interested in by running the `Get-MailboxExtendedProperty` cmdlet and filtering the results to a specific pattern e.g. on property name.

Then run `Search-MailboxExtendedProperty.ps1` supplying the set of filtered named properties.

Then run `Remove-MailboxExtendedProperty.ps1` with a list of mailbox items and their named property, that are to be removed.

Lastly, repeat the search to check the named properties no longer appear in the results.

### Syntax:

Example to search the mailbox for messages with any named properties matching the specific pattern and remove them from the messages.
```PowerShell
    $mailboxExtendedProperty = Get-MailboxExtendedProperty -Identity fred@contoso.com | Where-Object { $_.PropertyName -like '*Some Pattern*' }
    $messagesWithExtendedProperty = .\Search-MailboxExtendedProperty.ps1 -MailboxExtendedProperty $mailboxExtendedProperty
    .\Remove-MailboxExtendedProperty.ps1 -MessagesWithExtendedProperty $messagesWithExtendedProperty
```

## Prerequisites

This script uses the [ExchangeOnlineManagement PowerShell module](Search-MailboxExtendedProperty.md#install-exchangeonlinemanagement-powershell-module) and an Exchange Online connection to be successfully established by a Tenant Admin.

```PowerShell
    Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
```

This script uses [Microsoft Graph PowerShell modules](Search-MailboxExtendedProperty.md#install-microsoft-graph-powershell-modules) and requires a connection to already be established. Use of Microsoft Graph requires an [Azure App registration](Search-MailboxExtendedProperty.md#azure-app-registration).

To connect to Graph, using delegated access, and you know the credentials of the mailbox you want to search.

```PowerShell
    Connect-MgGraph -TenantId 2bbb42ba-e564-4f7b-9765-e19bc80c6123 -ClientId 8af900d8-db73-4918-81ef-3d35a873b6b2 -Scopes "User.Read Mail.ReadWrite"
```

    TenantId is that of the tenant.
    ClientId was provided during App registration.
    Scopes are the ones specified during App registration.

To connect to Graph, using delegated access, and you don't know the credentials of the mailbox you want to search. This generates a Url and device code, which is given to the end user and the end user performs the login on your behalf.

```PowerShell
    Connect-MgGraph -TenantId 2bbb42ba-e564-4f7b-9765-e19bc80c6123 -ClientId 8af900d8-db73-4918-81ef-3d35a873b6b2 -Scopes "User.Read Mail.ReadWrite" -UseDeviceCode
```
