# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Get-MgContext
#Requires -Modules Microsoft.Graph.Authentication
# Get-MgUserMessage
#Requires -Modules Microsoft.Graph.Mail
# Send-MgUserMail Send-MgUserMessage
#Requires -Modules Microsoft.Graph.Users.Actions
#Requires -Modules ExchangeOnlineManagement -Version 3.0.0

# How to connect:
# Connect-MgGraph -TenantId "[YOUR TENANT ID HERE]" -ClientSecretCredential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "[YOUR APP ID HERE]", (ConvertTo-SecureString -String "[VALUE FIELD OF YOUR SECRET HERE]" -AsPlainText -Force)) -NoWelcome
# Connect-ExchangeOnline -ShowBanner:$false

<#
.SYNOPSIS
Resends email in Failed state from Exchange Online to the originally intended recipients with parameters to target the emails to resend.

.DESCRIPTION
This script resends all Failed email from the past day, by default, or allows you to use the following parameters to target which emails to resend.

.PARAMETER Sender
    Filter emails based on the sender's address.
.PARAMETER Recipient
    Filter emails based on the recipient's address.
.PARAMETER Subject
    Filter emails based on the email Subject.
.PARAMETER MessageID
    Filter emails based on the MessageId address. You must put the MessageId in double quotes.
.PARAMETER Days
    Resend emails that failed within the past X number of days. Default is 1 day.
.PARAMETER Force
    Sends emails without confirmation prompt.
.PARAMETER IncludeDuplicate
    Will resend all emails with the same Message Id.
.PARAMETER ShowDetailedPolicies
    In addition to the policy applied, show any policy details that are set to True, On, or not blank.
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
	.\ResendFailedMail.ps1 -Sender gary@contoso.com -Recipient ahmad@fabrikam.com -Days 7
	To resend Failed email from specific sender, recipient, and specified number of days.

.EXAMPLE
	.\ResendFailedMail.ps1 -Force -Sender gary@contsoso.com -Days 5
	To resend Failed email from a specific sender for the past 5 days without a confirmation prompt.
#>

[CmdletBinding(DefaultParameterSetName = 'ResendCopyFailed', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [string[]]$Sender,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [string[]]$Subject,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [string[]]$Recipient,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [string[]]$MessageId,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [switch]$IncludeDuplicates,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [switch]$Force,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [int]$Days = 1,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [switch]$SkipConnectionCheck,
    [Parameter(Mandatory = $false, ParameterSetName = "ResendCopyFailed")]
    [switch]$SkipVersionCheck,
    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Progress.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Warning.ps1

$recipientCache = @{}

function Write-DebugLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
    }
}

function Write-HostLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
    }
    # all write-host should be logged in the debug log as well.
    Write-DebugLog $message
}

$LogFileName = "ResendFailedMail"
$StartDate = Get-Date
$StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
$Script:DebugLogger = Get-NewLoggerInstance -LogName "$LogFileName-Debug-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
$Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
SetWriteHostAction ${Function:Write-HostLog}
SetWriteProgressAction ${Function:Write-DebugLog}
SetWriteVerboseAction ${Function:Write-DebugLog}
SetWriteWarningAction ${Function:Write-HostLog}

$BuildVersion = ""

Write-Host ("ResendFailedMail.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/ResendFailedMail-VersionsURL" -Confirm:$false) {
        ($true) { Write-Host ("Script was successfully updated.") -ForegroundColor Green }
        ($false) { Write-Host ("No update of the script performed.") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation.") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/ResendFailedMail-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command.") -ForegroundColor Yellow
    return
}

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
        Write-Host "`tConnect-MgGraph -TenantId ""[YOUR TENANT ID HERE]"" -ClientSecretCredential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ""[YOUR APP ID HERE]"", (ConvertTo-SecureString -String ""[VALUE FIELD OF YOUR SECRET HERE]"" -AsPlainText -Force)) -NoWelcome" -ForegroundColor Yellow
        Write-Verbose "$_"
        exit
    }
    if ($null -eq $graphConnection) {
        Write-Host "Not connected to Graph" -ForegroundColor Red
        Write-Host "Verify that you have Microsoft.Graph.Mail and Microsoft.Graph.Users.Actions modules installed and loaded." -ForegroundColor Yellow
        Write-Host "You could use:" -ForegroundColor Yellow
        Write-Host "`tConnect-MgGraph -TenantId ""[YOUR TENANT ID HERE]"" -ClientSecretCredential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ""[YOUR APP ID HERE]"", (ConvertTo-SecureString -String ""[VALUE FIELD OF YOUR SECRET HERE]"" -AsPlainText -Force)) -NoWelcome" -ForegroundColor Yellow
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
            Write-Host "`tConnect-MgGraph -TenantId ""[YOUR TENANT ID HERE]"" -ClientSecretCredential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ""[YOUR APP ID HERE]"", (ConvertTo-SecureString -String ""[VALUE FIELD OF YOUR SECRET HERE]"" -AsPlainText -Force)) -NoWelcome" -ForegroundColor Yellow
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

$acceptedDomains = $null
try {
    $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
} catch {
    Write-Host "Error getting Accepted Domains:`n$_" -ForegroundColor Red
    exit
}

if ($null -eq $acceptedDomains) {
    Write-Host "We do not get accepted domains." -ForegroundColor Red
    exit
}

if ($acceptedDomains.count -eq 0) {
    Write-Host "No accepted domains found." -ForegroundColor Red
    exit
} else {
    $acceptedDomainList = New-Object System.Collections.Generic.List[string]
    $acceptedDomains | ForEach-Object { $acceptedDomainList.Add($_.DomainName.ToString()) }
}

$failedMessages = $null
$failedMessages = Get-MessageTrace -StartDate (Get-Date).AddDays(-$Days) -EndDate (Get-Date) | Where-Object { $_.Status -eq "Failed" }

if ($Sender) { $failedMessages = $failedMessages | Where-Object { $Sender -contains $_.SenderAddress } }
if ($Subject) { $failedMessages = $failedMessages | Where-Object { $Subject -contains $_.Subject } }
if ($Recipient) { $failedMessages = $failedMessages | Where-Object { $Recipient -contains $_.RecipientAddress } }
if ($MessageId) { $failedMessages = $failedMessages | Where-Object { $MessageId -contains $_.MessageId } }
if (-not $IncludeDuplicates) { $failedMessages = $failedMessages | Sort-Object MessageId -Unique }

$failedMessages = $failedMessages | Where-Object { $acceptedDomainList -contains $_.SenderAddress.Split("@")[1] }

$verifiedAcceptedSenderMessages = @()
foreach ($failedMessage in $failedMessages) {
    Write-Verbose "Checking $($failedMessage.SenderAddress)"
    $tempAddress = $null
    if ($recipientCache.ContainsKey($failedMessage.SenderAddress)) {
        Write-Verbose "Recipient $($failedMessage.SenderAddress) found in cache"
        $verifiedAcceptedSenderMessages += $failedMessage
    } else {
        try {
            $tempAddress = Get-EXORecipient $failedMessage.SenderAddress -ErrorAction Stop
            if ($null -eq $tempAddress) {
                Write-Host "Sender $($failedMessage.RecipientAddress) is not a recipient in this tenant." -ForegroundColor Yellow
                Write-Host "Discarded $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)" -ForegroundColor Yellow
            } else {
                Write-Verbose "Added to cache Recipient $($failedMessage.SenderAddress) with Id $($failedMessage.SenderAddress)"
                $recipientCache[$failedMessage.SenderAddress] = $failedMessage.SenderAddress
                Write-Verbose "Verified $($failedMessage.SenderAddress)"
                $verifiedAcceptedSenderMessages += $failedMessage
            }
        } catch {
            Write-Host "Error getting Sender $($failedMessage.SenderAddress)" -ForegroundColor Yellow
            Write-Host "Discarded $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)" -ForegroundColor Yellow
            Write-Verbose "$_"
        }
    }
}

if ( $verifiedAcceptedSenderMessages ) {
    if ($verifiedAcceptedSenderMessages.Count) {
        $totalMessages = $verifiedAcceptedSenderMessages.Count
    } else {
        $totalMessages = 1
    }

    if (-not $Force) {
        Write-Host "`nWe are going to resend the following messages:"
        Write-Host ($verifiedAcceptedSenderMessages | Format-Table -AutoSize Received, MessageId, SenderAddress, RecipientAddress, Subject | Out-String)
        Write-Host "Total number of messages: $totalMessages`n"
    }

    if ($Force -or $PSCmdlet.ShouldContinue("Are you sure you want to do it?", "Resend messages")) {
        $count = 0
        foreach ( $failedMessage in $verifiedAcceptedSenderMessages ) {
            $count++
            Write-Progress -Activity "Resending Progress" -Status "$count of $totalMessages" -PercentComplete ($count / $totalMessages * 100) -CurrentOperation "Resending message $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)"
            try {
                $fullMessage = $null
                $fullMessage = Get-MgUserMessage -UserId $failedMessage.SenderAddress -Filter "InternetMessageId eq '$($failedMessage.MessageId)'" -ExpandProperty Attachments -ErrorAction Stop | Sort-Object ReceivedDateTime | Select-Object -First 1
            } catch {
                Write-Host "Error getting message $($failedMessage.MessageId) - Subject: $($failedMessage.Subject)" -ForegroundColor Red
                Write-Verbose "$_"
            }
            if ($fullMessage.Count -eq 0) {
                Write-Host "Message not found for $($failedMessage.MessageId)" -ForegroundColor Yellow
            } else {
                Write-Verbose "Resending message $($failedMessage.MessageId) - Subject: $($fullMessage.Subject)"
                try {
                    #Send-MgUserMail -UserId $failedMessage.SenderAddress -Message $fullMessage -ErrorAction Stop
                    Send-MgUserMessage -UserId $failedMessage.SenderAddress -MessageId $fullMessage.Id -ErrorAction Stop
                    Write-Host "Resent Message: $($failedMessage.MessageId) - Subject: $($fullMessage.Subject)"
                } catch {
                    Write-Host "Error resending message $($failedMessage.MessageId) - Subject: $($fullMessage.Subject)" -ForegroundColor Red
                    Write-Verbose "$_"
                }
            }
        }
    }
} else {
    Write-Host "No messages found" -ForegroundColor Yellow
}
