# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
 Checks which Safe Attachment and Safe Links policies cover a particular user.

.Description
 Which Safe Attachment policy applies to USER? This info is included in the RULES of SafeAttachmentRule and ATPProtectionPolicyRule
		a. Checks only for enabled policies; accounts for exclusions of enabled policies too.
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
    [string]$EmailAddress,

    [Parameter(ParameterSetName = 'Applied')]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

Write-Host ("SA-SL-Policies-AppliedTo-User.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/SA-SL-Policies-AppliedTo-User-VersionsURL" -Confirm:$false) {
    ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
    ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/SA-SL-Policies-AppliedTo-User-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

if ($EmailAddress) {
    try {
        $null = [MailAddress]$EmailAddress
    } catch {
        Write-Host "The EmailAddress $EmailAddress cannot be validated. Please provide a valid email address." -ForegroundColor Red
        exit
    }
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
arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages." -ForegroundColor Yellow

Write-Output "`n"
Write-Host "This script checks to see which Safe Attachments policy applies to a user. Only one policy applies. It takes into account policy priorities and exclusions but doesn't check user or tenant overrides." -ForegroundColor Yellow

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

# Extract the domain from the email address
$domain = $emailAddress.Split("@")[1]

# Get the rules from Get-SafeAttachmentRule and Get-ATPProtectionPolicyRule
$SafeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
$SafeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
$ATPProtectionPolicyRules = Get-ATPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }

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
            if (![string]::IsNullOrEmpty($groupObjectId)) {
                $isInGroup = IsInGroup $email $groupObjectId
            }
        }

        $isInExceptGroup = $false
        if ($rule.ExceptIfSentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.ExceptIfSentToMemberOf
            if (![string]::IsNullOrEmpty($groupObjectId)) {
                $isInExceptGroup = IsInGroup $email $groupObjectId
            }
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

Write-Output "`n"

# Check the ATPProtectionPolicyRules first as they have higher precedence
$matchedRule = CheckRules -rules $ATPProtectionPolicyRules -email $emailAddress -domain $domain

if ($null -ne $matchedRule -and $ATPProtectionPolicyRules -contains $matchedRule) {
    Write-Host ("The preset security policy applies to the user for both Safe Attachments and Safe Links: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Magenta
    return
}

# ALL THE SAME FOR SA + SL TO HERE...

if ($null -eq $matchedRule) {
    # No match in preset ATPProtectionPolicyRules, check custom SafeAttachmentRules
    $SAmatchedRule = CheckRules -rules $SafeAttachmentRules -email $emailAddress -domain $domain
}

if ($null -eq $matchedRule) {
    # No match in preset ATPProtectionPolicyRules, check custom SafeLinksRules
    $SLmatchedRule = CheckRules -rules $SafeLinksRules -email $emailAddress -domain $domain
}

if ($null -eq $SAmatchedRule) {
    # Get the Built-in Protection Rule
    $builtInProtectionRule = Get-ATPBuiltInProtectionRule

    # Initialize a variable to track if the user is a member of any excluded group
    $isInExcludedGroup = $false

    # Check if the user is a member of any group in ExceptIfSentToMemberOf
    foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
        $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
        if (![string]::IsNullOrEmpty($groupObjectId) -and (IsInGroup $emailAddress $groupObjectId)) {
            $isInExcludedGroup = $true
            break
        }
    }

    # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
    if ($emailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
        $isInExcludedGroup -or
        $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
        Write-Host "The user is excluded from all Safe Attachment protection because they are excluded from Built-in Protection and they are not explicitly included in any other policy." -ForegroundColor Red
    } else {
        Write-Host "If your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy for Safe Attachments. This policy is not configurable." -ForegroundColor Yellow
    }
    $policy = $null
} else {
    $policy = Get-SafeAttachmentPolicy -Identity $SAmatchedRule.Name
    Write-Host ("The Safe Attachments policy that applies to the user: `n   Name: {0}`n   Priority: {1}`n   Policy: {2}" -f $SAmatchedRule.Name, $SAmatchedRule.Priority, $policy) -ForegroundColor Green
}

if ($null -eq $SLmatchedRule) {
    # Get the Built-in Protection Rule
    $builtInProtectionRule = Get-ATPBuiltInProtectionRule

    # Initialize a variable to track if the user is a member of any excluded group
    $isInExcludedGroup = $false

    # Check if the user is a member of any group in ExceptIfSentToMemberOf
    foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
        $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
        if (![string]::IsNullOrEmpty($groupObjectId) -and (IsInGroup $emailAddress $groupObjectId)) {
            $isInExcludedGroup = $true
            break
        }
    }

    # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
    if ($emailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
        $isInExcludedGroup -or
        $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
        Write-Host "The user is excluded from all Safe Links protection because they are excluded from Built-in Protection and they are not explicitly included in any other policy." -ForegroundColor Red
    } else {
        Write-Host "If your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy for Safe Links. This policy is not configurable." -ForegroundColor Yellow
    }
    $policy = $null
} else {
    $policy = Get-SafeLinksPolicy -Identity $SLmatchedRule.Name
    Write-Host ("`nThe Safe Links policy that applies to the user: `n   Name: {0}`n   Priority: {1}`n   Policy: {2}" -f $SLmatchedRule.Name, $SLmatchedRule.Priority, $policy) -ForegroundColor Green
}

Write-Host "`n"
