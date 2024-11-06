# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Get-MgContext
#Requires -Modules Microsoft.Graph.Authentication
# Get-MgUserMessage
#Requires -Modules Microsoft.Graph.Mail
# Get-EXOMailbox Get-ConnectionInformation Get-MessageTrace
#Requires -Modules ExchangeOnlineManagement -Version 3.0.0

# How to connect:
# $ClientSecretCredential = Get-Credential -Credential "[YOUR APP ID HERE]"
# Connect-MgGraph -TenantId ""[YOUR TENANT ID HERE]"" -ClientSecretCredential $ClientSecretCredential -NoWelcome

<#
.SYNOPSIS
Re-sends email in Failed state from Exchange Online to the originally intended recipients with parameters to target the emails to resend.

.DESCRIPTION
This script re-sends all Failed email from the past day, by default, or allows you to use the following parameters to target which emails to resend.

.PARAMETER SenderAddress
    Filter emails based on the sender's address.
.PARAMETER RecipientAddress
    Filter emails based on the recipient's address.
.PARAMETER Subject
    Filter emails based on the email Subject.
.PARAMETER MessageID
    Filter emails based on the MessageId address. You must put the MessageId in double quotes.
.PARAMETER Days
    Resend emails that failed within the past X number of days. Default is 1 day.
.PARAMETER Force
    Sends emails without confirmation prompt.
.PARAMETER IncludeDuplicates
    Will resend all emails with the same Message Id.
.PARAMETER SkipConnectionCheck
    Skips connection check for Graph and Exchange Online.
.PARAMETER SkipVersionCheck
    Skips the version check of the script.
.PARAMETER ScriptUpdateOnly
    Just updates script version to latest one.

.EXAMPLE
	.\ResendFailedMail.ps1
	To resend all Failed email from the past day.

.EXAMPLE
	.\ResendFailedMail.ps1 -SenderAddress gary@contoso.com -RecipientAddress  ahmad@fabrikam.com -Days 7
	To resend Failed email from specific sender, recipient, and specified number of days.

.EXAMPLE
	.\ResendFailedMail.ps1 -Force -SenderAddress gary@contsoso.com -Days 5
	To resend Failed email from a specific sender for the past 5 days without a confirmation prompt.
#>

[CmdletBinding(DefaultParameterSetName = 'ResendCopyFailed', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [string[]]$SenderAddress,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [string[]]$Subject,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [string[]]$RecipientAddress ,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [string[]]$MessageId,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [switch]$IncludeDuplicates,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [switch]$Force,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [DateTime]$StartDate,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [DateTime]$EndDate,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [ValidateRange(1, 10)]
    [Int16]$Days,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [switch]$SkipConnectionCheck,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailedDays")]
    [switch]$SkipVersionCheck,
    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

$Script:DualLoggingEnabled = $true
. $PSScriptRoot\..\..\Shared\GenericScriptStartLogging.ps1

$versionsUrl = "https://aka.ms/ResendFailedMail-VersionsURL"
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1

$recipientCache = @{}

Write-Verbose "Url to check for new versions of the script is: $versionsUrl"

function Test-GraphContext {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes,
        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedScopes
    )

    $validScope = $true
    foreach ($expectedScope in $ExpectedScopes) {
        if ($Scopes -contains $expectedScope) {
            Write-Verbose "Scopes $expectedScope is present."
        } else {
            Write-Host "The following scope is missing: $expectedScope" -ForegroundColor Red
            $validScope = $false
        }
    }
    return $validScope
}

if (-not $SkipConnectionCheck) {
    #Validate EXO PS Connection
    $exoConnection = $null
    try {
        $exoConnection = Get-ConnectionInformation -ErrorAction Stop
    } catch {
        Write-Host "Error checking EXO connection:`n$_" -ForegroundColor Red
        Write-Host "Verify that you have ExchangeOnlineManagement module installed." -ForegroundColor Yellow
        Write-Host "You need a connection to Exchange Online; you can use:" -ForegroundColor Yellow
        Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
        Write-Host "Exchange Online Powershell Module is required." -ForegroundColor Red
        Write-Verbose "$_"
        exit
    }
    if ($null -eq $exoConnection) {
        Write-Host "Not connected to EXO" -ForegroundColor Red
        Write-Host "You need a connection to Exchange Online; you can use:" -ForegroundColor Yellow
        Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
        Write-Host "Exchange Online Powershell Module is required." -ForegroundColor Red
        exit
    } elseif ($exoConnection.count -eq 1) {
        Write-Host " "
        Write-Host "Connected to EXO"
        Write-Host "Session details"
        Write-Host "Tenant Id: $($exoConnection.TenantId)"
        Write-Host "User: $($exoConnection.UserPrincipalName)"
    } else {
        Write-Host "You have more than one EXO session. Please use just one session." -ForegroundColor Red
        exit
    }

    #Validate Graph is connected
    $graphConnection = $null
    Write-Host " "
    try {
        $graphConnection = Get-MgContext -ErrorAction Stop
    } catch {
        Write-Host "Error checking Graph connection:`n$_" -ForegroundColor Red
        Write-Host "Verify that you have Microsoft.Graph.Mail and Microsoft.Graph.Users.Actions modules installed and loaded." -ForegroundColor Yellow
        Write-Host "You could use:" -ForegroundColor Yellow
        Write-Host "`t`$ClientSecretCredential = Get-Credential -Credential ""[YOUR APP ID HERE]""" -ForegroundColor Yellow
        Write-Host "`t# Enter client_secret in the password prompt." -ForegroundColor Yellow
        Write-Host "`tConnect-MgGraph -TenantId ""[YOUR TENANT ID HERE]"" -ClientSecretCredential `$ClientSecretCredential -NoWelcome" -ForegroundColor Yellow
        Write-Verbose "$_"
        exit
    }
    if ($null -eq $graphConnection) {
        Write-Host "Not connected to Graph" -ForegroundColor Red
        Write-Host "Verify that you have Microsoft.Graph.Mail and Microsoft.Graph.Users.Actions modules installed and loaded." -ForegroundColor Yellow
        Write-Host "You could use:" -ForegroundColor Yellow
        Write-Host "`t`$ClientSecretCredential = Get-Credential -Credential ""[YOUR APP ID HERE]""" -ForegroundColor Yellow
        Write-Host "`t# Enter client_secret in the password prompt." -ForegroundColor Yellow
        Write-Host "`tConnect-MgGraph -TenantId ""[YOUR TENANT ID HERE]"" -ClientSecretCredential `$ClientSecretCredential -NoWelcome" -ForegroundColor Yellow
        exit
    } elseif ($graphConnection.count -eq 1) {
        $expectedScopes = 'Mail.Read', 'Mail.Send'
        if (Test-GraphContext -Scopes $graphConnection.Scopes -ExpectedScopes $expectedScopes) {
            Write-Host "Connected to Graph"
            Write-Host "Session details"
            Write-Host "TenantID: $(($graphConnection).TenantId)"
            Write-Host "AuthType: $(($graphConnection).AuthType)"
        } else {
            Write-Host "We cannot continue without Graph Powershell session without Expected Scopes." -ForegroundColor Red
            Write-Host "Verify that you have Microsoft.Graph.Mail and Microsoft.Graph.Users.Actions modules installed and loaded." -ForegroundColor Yellow
            Write-Host "You could use:" -ForegroundColor Yellow
            Write-Host "`t`$ClientSecretCredential = Get-Credential -Credential ""[YOUR APP ID HERE]""" -ForegroundColor Yellow
            Write-Host "`t# Enter client_secret in the password prompt." -ForegroundColor Yellow
            Write-Host "`tConnect-MgGraph -TenantId ""[YOUR TENANT ID HERE]"" -ClientSecretCredential `$ClientSecretCredential -NoWelcome" -ForegroundColor Yellow
            exit
        }
    } else {
        Write-Host "You have more than one Graph sessions. Please use just one session." -ForegroundColor Red
        exit
    }
    if (($graphConnection.TenantId) -ne ($exoConnection.TenantId) ) {
        Write-Host "`nThe Tenant Id from Graph and EXO are different. Please use the same tenant." -ForegroundColor Red
        exit
    }
}

if ($PsCmdlet.ParameterSetName -eq 'ResendCopyFailedDays') {
    $StartDate = (Get-Date).AddDays(-$Days)
    Write-Verbose "StartDate: $StartDate"
    $EndDate = Get-Date
    Write-Verbose "EndDate: $EndDate"
}

$traceParams = @{
    Status = "Failed"
}

if ($StartDate) { $traceParams["StartDate"] = $StartDate }
if ($EndDate) { $traceParams["EndDate"] = $EndDate }
if ($RecipientAddress ) { $traceParams["RecipientAddress"] = $RecipientAddress }
if ($SenderAddress) { $traceParams["SenderAddress"] = $SenderAddress }
if ($MessageId) { $traceParams["MessageId"] = $MessageId }

try {
    [array]$failedMessages = Get-MessageTrace @traceParams -ErrorAction Stop
} catch {
    Write-Host "Error: $_.Exception.Message" -ForegroundColor Red
    exit
}

if ($failedMessages.count -ge 1000) {
    Write-Host "We get more than 1000 messages, please limit your search." -ForegroundColor Red
    exit
}

if (-not $IncludeDuplicates) {
    [array]$failedMessages = $failedMessages | Group-Object -Property MessageId | ForEach-Object { $_.Group | Sort-Object -Property Received | Select-Object -First 1 }
}

$verifiedAcceptedSenderMessages = New-Object System.Collections.Generic.List[object]
$count = 0
$totalMessages = $failedMessages.Count
foreach ($failedMessage in $failedMessages) {
    $count++
    Write-Progress -Activity "Checking Progress" -Status "$count of $totalMessages" -PercentComplete ($count / $totalMessages * 100) -CurrentOperation "Checking message $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)"
    Write-Verbose "Checking $($failedMessage.SenderAddress)"
    $tempAddress = $null
    if ($recipientCache.ContainsKey($failedMessage.SenderAddress)) {
        Write-Verbose "RecipientAddress  $($failedMessage.SenderAddress) found in cache"
        if ($recipientCache[$failedMessage.SenderAddress]) {
            $verifiedAcceptedSenderMessages.Add($failedMessage)
        } else {
            Write-Verbose "Sender $($failedMessage.SenderAddress) is not a recipient in this tenant."
            Write-Verbose "Discarded $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)"
        }
    } else {
        try {
            $tempAddress = Get-EXOMailbox $failedMessage.SenderAddress -ErrorAction Stop
            if ($null -eq $tempAddress) {
                Write-Verbose "Sender $($failedMessage.SenderAddress) is not a recipient in this tenant."
                Write-Verbose "Discarded $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)"
                $recipientCache[$failedMessage.SenderAddress] = $false
            } else {
                Write-Verbose "Added to cache Recipient $($failedMessage.SenderAddress) with Id $($failedMessage.SenderAddress)"
                $recipientCache[$failedMessage.SenderAddress] = $true
                Write-Verbose "Verified $($failedMessage.SenderAddress)"
                $verifiedAcceptedSenderMessages.Add($failedMessage)
            }
        } catch {
            Write-Verbose "Error getting Sender Address $($failedMessage.SenderAddress)"
            Write-Verbose "Discarded $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)"
            $recipientCache[$failedMessage.SenderAddress] = $false
            Write-Verbose "$_"
        }
    }
}

$totalMessages = $verifiedAcceptedSenderMessages.Count
if ($totalMessages -gt 0) {
    if (-not $Force) {
        Write-Host "`nWe are going to resend the following messages:"
        Write-Host ($verifiedAcceptedSenderMessages | Format-Table -AutoSize Received, MessageId, SenderAddress, RecipientAddress, Subject | Out-String)
        Write-Host "Total number of messages: $totalMessages`n"
    }

    if ($Force -or $PSCmdlet.ShouldContinue("Are you sure you want to do it?", "Resend messages")) {
        $count = 0
        $resendCount = 0
        foreach ( $failedMessage in $verifiedAcceptedSenderMessages ) {
            $count++
            Write-Progress -Activity "Resending Progress" -Status "$count of $totalMessages" -PercentComplete ($count / $totalMessages * 100) -CurrentOperation "Resending message $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)"
            try {
                $fullMessage = $null
                $fullMessage = Get-MgUserMessage -UserId $failedMessage.SenderAddress -Filter "InternetMessageId eq '$($failedMessage.MessageId)'" -ExpandProperty Attachments -ErrorAction Stop | Sort-Object ReceivedDateTime | Select-Object -First 1
            } catch {
                Write-Host "Error getting message $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)" -ForegroundColor Red
                Write-Verbose "$_"
                continue
            }
            if ($fullMessage.Count -eq 0) {
                Write-Host "Message not found for $($failedMessage.MessageId)" -ForegroundColor Yellow
            } else {
                Write-Verbose "Resending message $($failedMessage.MessageId) - Subject: $($fullMessage.Subject)"
                try {
                    Send-MgUserMessage -UserId $failedMessage.SenderAddress -MessageId $fullMessage.Id
                    Write-Host "Resent Message: $($failedMessage.MessageId) - Subject: $($fullMessage.Subject)"
                    $resendCount++
                } catch {
                    Write-Host "Error resending message $($failedMessage.MessageId) - Subject: $($fullMessage.Subject)" -ForegroundColor Red
                    Write-Verbose "$_"
                }
            }
        }
        Write-Host "Summary"
        Write-Host "Total Successful Resent: $resendCount"
        if ($totalMessages - $resendCount -gt 0) {
            Write-Host "Total Unsuccessful Resent: $($totalMessages-$resendCount)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "No messages found" -ForegroundColor Yellow
}
