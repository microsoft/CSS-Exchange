---
title: Clear-MailboxPermission.ps1
parent: Admin
---

# Clear-MailboxPermission

Download the latest release: [Clear-MailboxPermission.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Clear-MailboxPermission.ps1)

Attempting to Add-MailboxPermission or Remove-MailboxPermission sometimes fails with the following message:

`The ACL for object is not in canonical order (Deny/Allow/Inherited) and will be ignored.`

This indicates that the ACEs that make up the ACL do not follow canonical ordering, which generally means
denies before allows, and explicit before inherited. When the mailbox security descriptor is in this state,
the cmdlets can no longer modify it.

This script can be used to return it to a working state. The script does this by clearing all permissions
and resetting it to the default permissions that a brand new mailbox would have.

## Common Usage

The easiest way to use the script is to pipe the affected mailboxes to it:

`Get-Mailbox joe@contoso.com | .\Clear-MailboxPermission.ps1`

Note the script also supports -WhatIf and -Confirm. It will prompt for confirmation by default.
