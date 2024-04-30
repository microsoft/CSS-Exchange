# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
 Checks which MDO/EOP threat policies cover a particular user.

.Description
 Which policy applies to USER?
	a. Checks only for enabled policies and accounts for inclusions/exclusions within enabled policies.
	b. Input can be an individual's email address or a CSV file.
	c. Prints rule priority and policy/rule that applies. If none, prints Default policy. Priority property 0 is highest.
    d. Option to print to screen or to an output file.
	e. Checks any existing groups in AAD to get members.
	f. This script is backed by documentation about script priorities and behavior at the time of writing.
	g. CONSIDERATIONS: Preset rules have no configurable or visible properties. Their set values documented here:
       https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#policy-settings-in-preset-security-policies

.NOTES
The script checks for connection to AzureAD and Exchange Online, and, if not connected, connects you before running this script.
Only read-only permissions are needed as the script only reads from policies.
#>

param(
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedCsv')]
    [string]$CsvFilePath,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedEmail')]
    [string[]]$EmailAddresses,

    [Parameter(ParameterSetName = 'AppliedCsv')]
    [Parameter(ParameterSetName = 'AppliedEmail')]
    [Parameter(ParameterSetName = 'Applied')]
    [switch]$SkipConnectionCheck,

    [Parameter(ParameterSetName = 'AppliedCsv')]
    [Parameter(ParameterSetName = 'AppliedEmail')]
    [Parameter(ParameterSetName = 'Applied')]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1

function Write-HostLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
    }
}

SetWriteHostAction ${Function:Write-HostLog}

$LogFileName = "AllEOP-AppliedTo-User-Options"
$StartDate = Get-Date
$StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
$Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

$BuildVersion = ""

Write-Host ("AllEOP-AppliedTo-User-Options.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/AllEOP-AppliedTo-User-Options-VersionsURL" -Confirm:$false) {
    ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
    ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/AllEOP-AppliedTo-User-Options-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

[MailAddress[]]$ValidEmailAddresses = $null

if ($CsvFilePath ) {
    $EmailAddresses = Import-Csv -Path $CsvFilePath | Select-Object -ExpandProperty Email
}

$foundError = $false
foreach ($EmailAddress in $EmailAddresses) {
    try {
        $tempAddress = $null
        $tempAddress = [MailAddress]$EmailAddress
        $recipient = $null
        $recipient = Get-Recipient $tempAddress.ToString() -ErrorAction SilentlyContinue
        if ($null -eq $recipient) {
            Write-Host "$EmailAddress is not a mailbox in this tenant" -ForegroundColor Red
        } else {
            $ValidEmailAddresses += $tempAddress
        }
    } catch {
        Write-Host "The EmailAddress $EmailAddress cannot be validated. Please provide a valid email address." -ForegroundColor Red
        $foundError = $true
    }
}
if ($foundError) {
    exit
}

. $PSScriptRoot\..\Shared\Connect-M365.ps1

Write-Output "`n"
Write-Host "Disclaimer:

The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever
(including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.`n" -ForegroundColor Yellow

if (-not $SkipConnectionCheck) {
    #Connect to AzureAD PS
    Connect2AzureAD

    #Connect to EXO PS
    Connect2EXO
}

$AcceptedDomains = Get-AcceptedDomain

if ($AcceptedDomains.count -gt 0) {
    $foundError = $false
    foreach ( $EmailAddress in $ValidEmailAddresses ) {
        $Domain = $EmailAddress.Host
        if ($AcceptedDomains.DomainName -notcontains $Domain) {
            Write-Host "The domain $Domain is not an accepted domain in your organization. Please provide a valid email address." -ForegroundColor Red
            $foundError = $true
        }
    }
    if ($foundError) {
        exit
    }
}

$malwareFilterRules = Get-MalwareFilterRule | Where-Object { $_.State -ne 'Disabled' }
$antiPhishRules = Get-AntiPhishRule | Where-Object { $_.State -ne 'Disabled' }
$hostedContentFilterRules = Get-HostedContentFilterRule | Where-Object { $_.State -ne 'Disabled' }
$hostedOutboundSpamFilterRules = Get-HostedOutboundSpamFilterRule | Where-Object { $_.State -ne 'Disabled' }
$eopProtectionPolicyRules = Get-EOPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }
function CheckRules($rules, $email, $domain) {
    foreach ($rule in $rules) {
        $isInGroup = $false
        if ($rule.SentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.SentToMemberOf
            $isInGroup = IsInGroup $email $groupObjectId
        }

        $isInExceptGroup = $false
        if ($rule.ExceptIfSentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.ExceptIfSentToMemberOf
            $isInExceptGroup = IsInGroup $email $groupObjectId
        }

        if (($email -in $rule.SentTo -or !$rule.SentTo) -and
            ($domain -in $rule.RecipientDomainIs -or !$rule.RecipientDomainIs) -and
            ($isInGroup -or !$rule.SentToMemberOf)) {
            if (($email -notin $rule.ExceptIfSentTo -or !$rule.ExceptIfSentTo) -and
                ($domain -notin $rule.ExceptIfRecipientDomainIs -or !$rule.ExceptIfRecipientDomainIs) -and
                (!$isInExceptGroup -or !$rule.ExceptIfSentToMemberOf)) {
                return $rule
            }
        }
    }
    return $null
}

function CheckRulesAlternative($rules, $email, $domain) {
    foreach ($rule in $rules) {
        $isInGroup = $false
        if ($rule.FromMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.FromMemberOf
            $isInGroup = IsInGroup $email $groupObjectId
        }

        $isInExceptGroup = $false
        if ($rule.ExceptIfFrom) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.ExceptIfFrom
            $isInExceptGroup = IsInGroup $email $groupObjectId
        }

        if (($email -in $rule.From -or !$rule.From) -and
            ($domain -in $rule.SenderDomainIs -or !$rule.SenderDomainIs) -and
            ($isInGroup -or !$rule.FromMemberOf)) {
            if (($email -notin $rule.ExceptIfFrom -or !$rule.ExceptIfFrom) -and
                ($domain -notin $rule.ExceptIfSenderDomainIs -or !$rule.ExceptIfSenderDomainIs) -and
                (!$isInExceptGroup -or !$rule.ExceptIfFromMemberOf)) {
                return $rule
            }
        }
    }
    return $null
}

function Get-Policy($rule, $policyType) {
    if ($null -eq $rule) {
        $policyDetails = "`nThe $policyType policy: `n   The Default policy."
    } else {
        $policyDetails = "`nThe $policyType policy: `n   Name: {0}`n   Priority: {1}" -f $rule.Name, $rule.Priority
    }
    return $policyDetails
}

function Get-UserDetails($emailAddress) {
    $userDetails = "`nPolicies applied to $emailAddress : "
    return $userDetails
}

foreach ($email in $ValidEmailAddresses) {
    $emailAddress = $email.ToString()
    $domain = $emailAddress.Host
    $isInGroup = $false
    $isInExceptGroup = $false
    # Initialize a variable to capture all policy details
    $allPolicyDetails = ""
    $userDetails = Get-UserDetails -emailAddress $emailAddress

    # Check the EOPProtectionPolicyRules first as they have higher precedence
    $matchedRule = CheckRules -rules $eopProtectionPolicyRules -email $emailAddress -domain $domain

    if ($null -ne $matchedRule -and $eopProtectionPolicyRules -contains $matchedRule) {
        $allPolicyDetails += "`nThe policy that covers the user for malware, spam, and phishing: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority

        #    write-output ("`nThe policy that covers the user for malware, spam, and phishing: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority)
        $outboundSpamMatchedRule = CheckRulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress -domain $domain
        $allPolicyDetails += Get-Policy $outboundSpamMatchedRule "Outbound Spam"
        $allPolicyDetails = $userDetails + "`n" + $allPolicyDetails
        Write-Host $allPolicyDetails -ForegroundColor Green
        Write-Output "`n"
        continue
    }

    if ($null -eq $matchedRule) {
        # If no match in EOPProtectionPolicyRules, check MalwareFilterRules, AntiPhishRules, outboundSpam, and HostedContentFilterRules
        $malwareMatchedRule = CheckRules -rules $malwareFilterRules -email $emailAddress -domain $domain
        $antiPhishMatchedRule = CheckRules -rules $antiPhishRules -email $emailAddress -domain $domain
        $spamMatchedRule = CheckRules -rules $hostedContentFilterRules -email $emailAddress -domain $domain
        $outboundSpamMatchedRule = CheckRulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress -domain $domain
    }

    # Capture the output of each Get-Policy call
    $allPolicyDetails += Get-Policy $malwareMatchedRule "Malware"
    $allPolicyDetails += Get-Policy $antiPhishMatchedRule "Anti-phish"
    $allPolicyDetails += Get-Policy $spamMatchedRule "Anti-spam"
    $allPolicyDetails += Get-Policy $outboundSpamMatchedRule "Outbound Spam"

    $allPolicyDetails = $userDetails + "`n" + $allPolicyDetails

    Write-Host $allPolicyDetails -ForegroundColor Yellow
}

Write-Output "`n"
