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

$LogFileName = "SA-SL-Policies-AppliedTo-User"
$StartDate = Get-Date
$StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
$Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

$BuildVersion = ""

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
. $PSScriptRoot\Shared\MDO-Functions.ps1

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

if (-not $SkipConnectionCheck) {
    #Connect to AzureAD PS
    Connect-AAD

    #Connect to EXO PS
    Connect-EXO
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

# Get the rules from Get-SafeAttachmentRule and Get-ATPProtectionPolicyRule
$SafeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
$SafeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
$ATPProtectionPolicyRules = Get-ATPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }

Write-Output "`n"

foreach ($email in $ValidEmailAddresses) {
    $emailAddress = $email.ToString()
    $domain = $email.Host

    Write-Host "`nChecking user $emailAddress..."

    # Check the ATPProtectionPolicyRules first as they have higher precedence
    $matchedRule = Test-Rules -rules $ATPProtectionPolicyRules -email $emailAddress -domain $domain

    if ($null -ne $matchedRule -and $ATPProtectionPolicyRules -contains $matchedRule) {
        Write-Host ("The preset security policy applies to the user for both Safe Attachments and Safe Links: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Magenta
        return
    }

    # ALL THE SAME FOR SA + SL TO HERE...

    if ($null -eq $matchedRule) {
        # No match in preset ATPProtectionPolicyRules, check custom SafeAttachmentRules
        $SAmatchedRule = Test-Rules -rules $SafeAttachmentRules -email $emailAddress -domain $domain
    }

    if ($null -eq $matchedRule) {
        # No match in preset ATPProtectionPolicyRules, check custom SafeLinksRules
        $SLmatchedRule = Test-Rules -rules $SafeLinksRules -email $emailAddress -domain $domain
    }

    if ($null -eq $SAmatchedRule) {
        # Get the Built-in Protection Rule
        $builtInProtectionRule = Get-ATPBuiltInProtectionRule

        # Initialize a variable to track if the user is a member of any excluded group
        $isInExcludedGroup = $false

        # Check if the user is a member of any group in ExceptIfSentToMemberOf
        foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
            if (![string]::IsNullOrEmpty($groupObjectId) -and (Test-IsInGroup $emailAddress $groupObjectId)) {
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
            if (![string]::IsNullOrEmpty($groupObjectId) -and (Test-IsInGroup $emailAddress $groupObjectId)) {
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
}

Write-Host "`n"
