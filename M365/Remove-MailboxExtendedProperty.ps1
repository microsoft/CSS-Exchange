# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Modules @{ ModuleName="ExchangeOnlineManagement"; RequiredVersion="3.4.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Users"; RequiredVersion="2.24.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Mail"; RequiredVersion="2.24.0" }

<#
.SYNOPSIS
    Removes the extended property (aka named property) the message.

.DESCRIPTION
    Takes as input the result from Search-MailboxExtendedProperty.ps1 and removes the extended property from the message.

.PARAMETER MessagesWithExtendedProperty
    A list of mailbox items and their extended property, that are to be removed.

.EXAMPLE
    $mailboxExtendedProperty = Get-MailboxExtendedProperty -Identity fred@contoso.com | Where-Object { $_.PropertyName -like '*Some Pattern*' }
    $messagesWithExtendedProperty = .\Search-MailboxExtendedProperty.ps1 -MailboxExtendedProperty $mailboxExtendedProperty
    .\Remove-MailboxExtendedProperty.ps1 -MessagesWithExtendedProperty $messagesWithExtendedProperty

#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    $MessagesWithExtendedProperty
)

process {
    # Get the current Microsoft Graph context
    $context = Get-MgContext
    if ($null -eq $context) {
        Write-Host -ForegroundColor Red "No valid context. Please connect to Microsoft Graph first."
        return
    }

    # Get the user information for the context
    $user = Get-MgUser -UserId $context.Account -Select 'displayName, id, mail, userPrincipalName'
    if ($null -eq $user) {
        Write-Host -ForegroundColor Red "No valid user. Please check the Microsoft Graph connection."
        return
    }

    Write-Host "Attempting to remove $($MessagesWithExtendedProperty.Count) extended properties from the mailbox of $($user.UserPrincipalName)."

    foreach ($message in $MessagesWithExtendedProperty) {
        if ($message.SingleValueExtendedProperties.Count -eq 1) {
            # Url encode the extended property
            $extendedProperty = [System.Uri]::EscapeDataString($message.SingleValueExtendedProperties.Id)

            # Construct the URL to remove the extended property from the message
            $url = "https://graph.microsoft.com/v1.0/users/$($user.UserPrincipalName)/messages/$($message.ID)/singleValueExtendedProperties/$extendedProperty"

            # Remove the extended property from the message (fire and forget)
            Invoke-MgGraphRequest -Method DELETE -Uri $url -Headers @{ Authorization = "Bearer $($context.AccessToken)" }

            Write-Host -ForegroundColor Green "Removed the extended property $($message.SingleValueExtendedProperties.Id) from the message '$($message.Subject)'."
        } else {
            Write-Host -ForegroundColor Red "Invalid extended property format: $($message.SingleValueExtendedProperties)."
        }
    }
}
