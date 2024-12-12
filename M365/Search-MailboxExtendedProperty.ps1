# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Modules @{ ModuleName="ExchangeOnlineManagement"; ModuleVersion="3.4.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Users"; ModuleVersion="2.24.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Mail"; ModuleVersion="2.24.0" }

<#
.SYNOPSIS
    Searches for mailbox items with a specified extended property (aka named property).

.DESCRIPTION
    For each of the specified mailbox extended properties, this script searches for mailbox items that have the property set.
    It returns a list of mailbox items and information about the item and the extended property.
    The list of mailbox items returned can be used to further process the items, such as removing the extended property.
    There are some limitations: the search is limited to messages (extended properties can exist on folder, contact, calendar instances etc), single value extended properties (not multi-value), and the property value must be a non-null string.

.PARAMETER MailboxExtendedProperty
    One of more mailbox extended properties to search for in the mailbox, returned by Get-MailboxExtendedProperty.

.EXAMPLE
    $mailboxExtendedProperty = Get-MailboxExtendedProperty -Identity fred@contoso.com | Where-Object { $_.PropertyName -like '*Some Pattern*' }
    $messagesWithExtendedProperty = .\Search-MailboxExtendedProperty.ps1 -MailboxExtendedProperty $mailboxExtendedProperty
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({
            if ($_.GetType().FullName -eq 'System.Management.Automation.PSObject' -or $_.GetType().FullName -eq 'System.Object[]') {
                $true
            } else {
                throw "The parameter MailboxExtendedProperty doesn't appear to be the result from running 'Get-MailboxExtendedProperty'."
            }
        })]
    $MailboxExtendedProperty
)

process {
    function Get-FolderPath {
        param (
            [string]$userId,
            [string]$folderId
        )

        $folderPath = @()
        $currentFolderId = $folderId

        # Get the folder path from the target folder to the root
        do {
            $folder = Get-MgUserMailFolder -UserId $userId -MailFolderId $currentFolderId -Select 'DisplayName, ParentFolderId'
            if ($null -eq $folder) {
                break
            } else {
                $folderPath += $folder.DisplayName
                $currentFolderId = $folder.ParentFolderId
            }
        }
        while ($folder.DisplayName -ne "")

        # Reverse the array to get the path from root to the target folder
        $fullPath = ($folderPath | Sort-Object -Descending) -join "\"

        # Ensure the path starts with a backslash and does not end with one
        return "\" + $fullPath.TrimEnd("\")
    }

    # Folder paths already looked up
    $mailboxFolderPath = @{}

    # Messages found with the extended property
    $message = @()

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

    Write-Host "Searching for mailbox items with the specified $($MailboxExtendedProperty.Count) extended properties in the mailbox of $($user.UserPrincipalName)."

    # For each of the specified mailbox extended properties
    foreach ($property in $MailboxExtendedProperty) {
        # Get the mailbox extended property identity again to check if it still exists and parse the identity
        $parsedProperty = Get-MailboxExtendedProperty -Identity $property.Identity

        if ($null -eq $parsedProperty) {
            Write-Host -ForegroundColor Yellow "Mailbox extended property no longer present in mailbox $($property.Identity)."
            continue
        } else {
            if ($parsedProperty.PropertyType -eq "StringProperty") {
                $property = "String {$($parsedProperty.PropertyNamespace.Guid)} Name $($parsedProperty.PropertyName)"
            } elseif ($parsedProperty.PropertyType -eq "IdProperty") {
                $property = "String {$($parsedProperty.PropertyNamespace.Guid)} Id 0x$($parsedProperty.PropertyId.ToString('X'))"
            } else {
                Write-Host -ForegroundColor Red "Mailbox extended property type $($parsedProperty.PropertyType) not supported."
                continue
            }

            Write-Host "Searching for mailbox items with the extended property $property."

            # Url encode the extended property
            $urlEncodedProperty = [System.Uri]::UnescapeDataString($property)
            # Filter for messages with the extended property set
            $filter = "singleValueExtendedProperties/Any(ep: ep/id eq '$urlEncodedProperty' and ep/value ne null)"
            # Expand the extended property to get the value
            $expandProperty = "singleValueExtendedProperties(`$filter=id eq '$property')"

            # Search for mailbox items with the extended property
            $mailboxItem = Get-MgUserMessage -UserId $user.UserPrincipalName -Filter $filter -Property "Subject,ParentFolderId,SingleValueExtendedProperties,InternetMessageId" -ExpandProperty $expandProperty
            foreach ($item in $mailboxItem) {

                # Get the folder path for the item (it doesn't exist as a property)
                if ($mailboxFolderPath.ContainsKey($item.ParentFolderId)) {
                    $folderPath = $mailboxFolderPath[$item.ParentFolderId]
                } else {
                    $folderPath = Get-FolderPath -userId $user.UserPrincipalName -folderId $item.ParentFolderId
                    $mailboxFolderPath[$item.ParentFolderId] = $folderPath
                }

                # Add the item to the list of messages
                $message += New-Object PSObject -Property @{
                    Id                            = $item.Id
                    SingleValueExtendedProperties = $item.SingleValueExtendedProperties
                    Subject                       = $item.Subject
                    InternetMessageId             = $item.InternetMessageId
                    ParentFolderId                = $item.ParentFolderId
                    FolderPath                    = $folderPath
                }
            }

            Write-Host "Found $($mailboxItem.Count) mailbox items with the extended property $property."
        }
    }

    Write-Host "Found a total of $($message.Count) mailbox items with the specified $($MailboxExtendedProperty.Count) extended properties in the mailbox of $($user.UserPrincipalName)."

    return $message
}
