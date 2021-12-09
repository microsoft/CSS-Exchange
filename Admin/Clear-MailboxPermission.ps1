# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Clears the permissions from a mailbox, resetting it to the
    default permissions that exist when a mailbox is first created.
.DESCRIPTION
    When the permissions on an Exchange mailbox are not ordered
    correct, the mailbox security is considered non-canonical. In this
    case, modifying the mailbox permissions fails with a message like:

    The ACL for object is not in canonical order (Deny/Allow/Inherited) and will be ignored.

    This script overwrites the mailbox permissions with the defaults,
    effectively clearing all other permissions. This fixes the non-canonical
    order and makes it possible to modify the permissions once again.
.EXAMPLE
   Get-Mailbox joe@contoso.com | .\Clear-MailboxPermission.ps1

    Clears the mailbox permissions from a single mailbox. Any number of
    mailboxes can be piped to the script.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]
    $DistinguishedName
)

begin {
    $defaultSecurityDescriptor = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:PSG:PSD:(A;CI;CCRC;;;PS)"
}

process {
    $user = [ADSI]("LDAP://" + $DistinguishedName)
    $displayName = $user.Properties["displayName"][0].ToString()
    if ($PSCmdlet.ShouldProcess($displayName, 'Clear mailbox permissions')) {
        $user.Properties["msExchMailboxSecurityDescriptor"].Clear()
        [byte[]]$mbxSdBytes = [System.Array]::CreateInstance([System.Byte], $defaultSecurityDescriptor.BinaryLength)
        $defaultSecurityDescriptor.GetBinaryForm($mbxSdBytes, 0)
        [void]$user.Properties["msExchMailboxSecurityDescriptor"].Add($mbxSdBytes)
        $user.CommitChanges()
    }
}
