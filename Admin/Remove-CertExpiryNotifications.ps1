# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Removes certificate expiry notification emails.
.DESCRIPTION
    Removes certificate expiry notification emails from the arbitration mailbox in an Exchange organization.
    The user must have access to the SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9} arbitration mailbox
    in order to run this script. See the docs for more information.

    Common errors are also described in the docs. Please see the docs for more information.
.EXAMPLE
    PS C:\> .\Remove-CertExpiryNotifications.ps1 -Server exch1.contoso.com -WhatIf

    For more examples, please see the docs.
.PARAMETER Server
    The Exchange server to connect to. Note this must be the name in the certificate,
    or a TLS failure will occur.
.PARAMETER Credential
    The credentials to use to connect to the Exchange server. If not provided, the
    current logged in user will be used.
.LINK
    https://aka.ms/RemoveCertExpiryNotifications
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $Server,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $Credential
)

$invokeParameters = @{}
if ($null -ne $Credential) {
    $invokeParameters.Credential = $Credential
} else {
    $invokeParameters.UseDefaultCredentials = $true
}

$mailbox = (Get-Mailbox -Arbitration | Where-Object { $_.Name -eq "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}" }).UserPrincipalName
if ($null -eq $mailbox) {
    Write-Host "Arbitration mailbox not found."
    return
}

try {
    $mailFolders = Invoke-RestMethod -Uri "https://$Server/api/v2.0/Users('$mailbox')/mailfolders" @invokeParameters
} catch {
    Write-Host "Error connecting to Exchange. Please check the docs for common errors: https://aka.ms/RemoveCertExpiryNotifications"
    throw
}

if ($null -eq $mailFolders -or $mailFolders.value.Count -eq 0) {
    Write-Host "Could not get inbox child folders or there were no folders found."
    return
}

$asyncOperationNotificationFolder = $mailFolders.value | Where-Object { $_.DisplayName -eq "AsyncOperationNotification" }
if ($null -eq $asyncOperationNotificationFolder) {
    Write-Host "AsyncOperationNotification folder not found."
    return
}

$messages = Invoke-RestMethod -Uri "https://$Server/api/v2.0/Users('$mailbox')/mailfolders/$($asyncOperationNotificationFolder.Id)/messages" @invokeParameters
if ($null -eq $messages -or $messages.value.Count -eq 0) {
    Write-Host "No messages were found in the AsyncOperationNotification folder."
    return
}

if ($messages.value.Count -gt 0) {
    Write-Host "Found $($messages.value.Count) messages in AsyncOperationNotification folder."
}

foreach ($message in $messages.value) {
    $subject = "<Empty Subject>"
    if (-not [string]::IsNullOrEmpty($message.Subject)) {
        Write-Host "Unexpected subject value: $($message.Subject)"
    } else {
        $messageDescription = "Message received $($message.ReceivedDateTime) with Subject: $subject"

        if ($PSCmdlet.ShouldProcess($messageDescription, "Delete message")) {
            Write-Host "Deleting: $messageDescription"
            Invoke-RestMethod -Method DELETE -Uri "https://$Server/api/v2.0/Users('$mailbox')/mailfolders/$($asyncOperationNotificationFolder.Id)/messages/$($message.Id)" @invokeParameters
        }
    }
}
