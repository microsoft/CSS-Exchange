# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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

$mailFolders = Invoke-RestMethod -Uri "https://$Server/api/v2.0/Users('$mailbox')/mailfolders" @invokeParameters
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
