# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
 Checks which MDO/EOP threat policies cover a particular user.

.Description
 Which policy applies to USER?
	a. Checks only for enabled policies and accounts for inclusions/exclusions within enabled policies.
	b. Input is individual's email address.
	c. Prints rule priority and policy/rule that applies. If none, prints Default policy. Print if excluded by group, domain, or individually. Rules have the Priority property. 0 is highest.
	d. Checks any existing groups in AAD to get members.
	e. This script is backed by documentation about script priorities and behavior at the time of writing.
	f. CONSIDERATIONS: Preset rules have no configurable or visible properties. Their set values documented here:
       https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#policy-settings-in-preset-security-policies

.NOTES
The script checks for connection to AzureAD and Exchange Online, and, if not connected, connects you before running this script.
Only read-only permissions are needed as the script only reads from policies.
#>

param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Applied')]
    [string]$emailAddress,

    [Parameter(ParameterSetName = 'Applied')]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

try {
    $null = [MailAddress]$EmailAddress
} catch {
    Write-Error "Invalid email address"
    exit
}

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

Write-Host ("AllEOP-AppliedTo-User.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/AllEOP-AppliedTo-User-VersionsURL" -Confirm:$false) {
    ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
    ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/AllEOP-AppliedTo-User-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Host "[ERROR]: Please run as Administrator" -ForegroundColor Red
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
arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages." -ForegroundColor DarkBlue

#Connect to AzureAD PS
$SessionCheck = Get-PSSession | Where-Object { $_.Name -like "*AzureAD*" -and $_.State -match "opened" }
if ($null -eq $SessionCheck) {
    Connect2AzureAD
}

#Connect to EXO PS
$SessionCheck = Get-PSSession | Where-Object { $_.Name -like "*ExchangeOnline*" -and $_.State -match "opened" }
if ($null -eq $SessionCheck) {
    Connect2EXO
}

# Get the email address from the user
Write-Output "`n"
Write-Host "This script checks to see which threat policies apply to a user. Only one policy applies for each type. It takes into account policy priorities and exclusions but doesn't check user or tenant overrides." -ForegroundColor Blue
Write-Host "Make sure you connect to Exchange Online and Azure AD before running it.`n" -ForegroundColor Blue

# Extract the domain from the email address
$domain = $emailAddress.Split("@")[1]

# Get the rules from Get-MalwareFilterRule, Get-AntiPhishRule, Get-HostedContentFilterRule, Get-HostedOutboundSpamFilterRule, and Get-EOPProtectionPolicyRule
$malwareFilterRules = Get-MalwareFilterRule | Where-Object { $_.State -ne 'Disabled' }
$antiPhishRules = Get-AntiPhishRule | Where-Object { $_.State -ne 'Disabled' }
$hostedContentFilterRules = Get-HostedContentFilterRule | Where-Object { $_.State -ne 'Disabled' }
$hostedOutboundSpamFilterRules = Get-HostedOutboundSpamFilterRule | Where-Object { $_.State -ne 'Disabled' }
$eopProtectionPolicyRules = Get-EOPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }

function Get-GroupObjectId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$groupEmail
    )

    # Get the group
    $group = Get-AzureADGroup -SearchString $groupEmail

    # Return the Object ID of the group
    return $group.ObjectId
}

# Function to check if an email is in a group
function IsInGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$email,

        [Parameter(Mandatory = $true)]
        [string]$groupObjectId
    )

    # Get the group members
    $groupMembers = Get-AzureADGroupMember -ObjectId $groupObjectId

    # Check if the email address is in the group
    foreach ($member in $groupMembers) {
        if ($member.Mail -eq $email)
        { return $true }
    }
    return $false
}

# Function to check rules
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

# Function to check Outbound spam rules that have alternative properties
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

# Function to get the policy
function Get-Policy($rule, $policyType) {
    if ($null -eq $rule) {
        Write-Host "`nThe $policyType policy that applies to User: `n   The Default policy." -ForegroundColor DarkYellow
    } else {
        Write-Host ("`nThe $policyType policy that applies to User: `n   Name: {0}`n   Priority: {1}" -f $rule.Name, $rule.Priority) -ForegroundColor DarkGreen
    }
}

# Check the EOPProtectionPolicyRules first as they have higher precedence
$matchedRule = CheckRules -rules $eopProtectionPolicyRules -email $emailAddress -domain $domain

if ($null -ne $matchedRule -and $eopProtectionPolicyRules -contains $matchedRule) {
    Write-Host ("`nThe policy that covers the user for malware, spam, and phishing: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor DarkMagenta
    $outboundSpamMatchedRule = CheckRulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress -domain $domain
    Get-Policy $outboundSpamMatchedRule "Outbound Spam"
    Write-Host "`n"
    return
}

if ($null -eq $matchedRule) {
    # If no match in EOPProtectionPolicyRules, check the MalwareFilterRules, AntiPhishRules, and HostedContentFilterRules
    $malwareMatchedRule = CheckRules -rules $malwareFilterRules -email $emailAddress -domain $domain
    $antiPhishMatchedRule = CheckRules -rules $antiPhishRules -email $emailAddress -domain $domain
    $spamMatchedRule = CheckRules -rules $hostedContentFilterRules -email $emailAddress -domain $domain
    $outboundSpamMatchedRule = CheckRulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress -domain $domain
}
Get-Policy $malwareMatchedRule "Malware"
Get-Policy $antiPhishMatchedRule "Anti-phish"
Get-Policy $spamMatchedRule "Anti-spam"
Get-Policy $outboundSpamMatchedRule "Outbound Spam"

Write-Output "`n"
