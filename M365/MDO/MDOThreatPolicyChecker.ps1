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

[CmdletBinding(DefaultParameterSetName = 'AppliedTenant')]
param(
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [string]$CsvFilePath,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedEmail')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
    [string[]]$EmailAddresses,

    [Parameter(ParameterSetName = 'AppliedCsv')]
    [Parameter(ParameterSetName = 'AppliedEmail')]
    [switch]$IncludeMDOPolicies,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$OnlyMDOPolicies,

    [Parameter(ParameterSetName = 'AppliedCsv')]
    [Parameter(ParameterSetName = 'AppliedEmail')]
    [Parameter(ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(ParameterSetName = 'AppliedMDOEmail')]
    [Parameter(ParameterSetName = 'AppliedTenant')]
    [switch]$SkipConnectionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\Connect-M365.ps1
. $PSScriptRoot\Shared\MDO-Functions.ps1

function Write-HostLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
    }
}

SetWriteHostAction ${Function:Write-HostLog}

$LogFileName = "MDOThreatPolicyChecker"
$StartDate = Get-Date
$StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
$Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

$BuildVersion = ""

Write-Host ("MDOThreatPolicyChecker.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false) {
    ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
    ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

Write-Host "`n"
Write-Host "Disclaimer:

The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever
(including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.`n" -ForegroundColor Yellow

if (-not $SkipConnectionCheck) {
    if ($PSCmdlet.ParameterSetName -ne "AppliedTenant") {
        #Connect to AzureAD PS
        try {
            $connection = $null
            $connection = Get-AzureADTenantDetail -ErrorAction SilentlyContinue
            if ($connection.count -eq 1) {
                Write-Host "Connected to AzureAD"
                Write-Host "Session details"
                Write-Host "Tenant: $($connection.DisplayName)"
            } else {
                Write-Host "You have more than one AzureAD sessions please use just one session" -ForegroundColor Red
                break
            }
        } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
            Write-Host "Not connected to AzureAD" -ForegroundColor Red
            Write-Host "You need a connection to AzureAD, you can use:" -ForegroundColor Yellow
            Write-Host "Connect-AzureAD " -ForegroundColor Yellow
            break
        }
    }

    #Connect to EXO PS
    $connection = $null
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($null -eq $connection) {
        Write-Host "Not connected to EXO V2" -ForegroundColor Red
        Write-Host "You need a connection To Exchange Online, you can use:" -ForegroundColor Yellow
        Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
        Write-Host "Please use Global administrator credentials when prompted!" -ForegroundColor Yellow
        Write-Host "Exchange Online Powershell Module is required" -ForegroundColor Red
        break
    } elseif ($connection.count -eq 1) {
        Write-Host "Connected to EXO V2"
        Write-Host "Session details"
        Write-Host "Tenant Id: $($connection.TenantId)"
        Write-Host "User: $($connection.UserPrincipalName)"
    } else {
        Write-Host "You have more than one EXO sessions please use just one session" -ForegroundColor Red
        break
    }
}

if ($PSCmdlet.ParameterSetName -eq "AppliedTenant") {
    # Define the cmdlets to retrieve policies from and their corresponding policy types
    $Cmdlets = @{
        "Get-HostedContentFilterRule"  = "Anti-spam Policy"
        "Get-EOPProtectionPolicyRule"  = "Preset security policies Policy"
        "Get-MalwareFilterRule"        = "Malware Policy"
        "Get-ATPProtectionPolicyRule"  = "MDO (SafeLinks/SafeAttachments) Policy in preset security policies"
        "Get-AntiPhishRule"            = "Anti-phishing Policy"
        "Get-SafeLinksRule"            = "Safe Links Policy"
        "Get-SafeAttachmentRule"       = "Safe Attachment Policy"
        "Get-ATPBuiltInProtectionRule" = "Built-in protection preset security Policy"
    }
    $IssueCounter = 0

    # Loop through each cmdlet
    foreach ($Cmdlet in $Cmdlets.Keys) {
        # Retrieve the policies
        $Policies = & $Cmdlet

        # Loop through each policy
        foreach ($Policy in $Policies) {
            # Initialize an empty list to store issues
            $Issues = @()

            # Check the logic of the policy and add issues to the list
            if ($Policy.SentTo -and $Policy.ExceptIfSentTo) {
                $Issues += "User inclusions and exclusions. Excluding and including Users individually is redundant and confusing as only the included Users could possibly be included.`nSuggestion: excluding individual Users should be used to exclude from group or domain inclusions, if needed."
            }
            if ($Policy.RecipientDomainIs -and $Policy.ExceptIfRecipientDomainIs) {
                $Issues += "Domain inclusions and exclusions. Excluding and including Domains is redundant and confusing as only the included Domains could possibly be included."
            }
            if ($Policy.SentTo -and $Policy.SentToMemberOf) {
                $Issues += "Illogical inclusions of Users and Groups. The policy will only apply to Users who are also members of any Groups you have specified. This makes the Group inclusion redundant and confusing.`nSuggestion: use one or the other type of inclusion."
            }
            if ($Policy.SentTo -and $Policy.RecipientDomainIs) {
                $Issues += "Illogical inclusions of Users and Domains. The policy will only apply to Users whose email domains also match any Domains you have specified. This makes the Domain inclusion redundant and confusing.`nSuggestion: use one or the other type of inclusion."
            }

            # If there are any issues, print the policy details once and then list all the issues
            if ($Issues.Count -gt 0) {
                Write-Host ("`nPolicy '" + $Policy.Name + "':") -ForegroundColor Yellow
                Write-Host ("   - Type: '" + $Cmdlets[$Cmdlet] + "'.") -ForegroundColor DarkCyan
                Write-Host ("   - State: " + $Policy.State + ".") -ForegroundColor DarkCyan
                Write-Host ("   - Issues: ") -ForegroundColor Red
                foreach ($Issue in $Issues) {
                    Write-Host ("      -> " + $Issue) -ForegroundColor DarkCyan
                    $IssueCounter += 1
                }
            }
        }
    }
    if ($IssueCounter -eq 0) {
        Write-Host ("`nNo logical inconsistencies found!") -ForegroundColor DarkGreen
    }
} else {

    if ($CsvFilePath) {
        $EmailAddresses = Import-Csv -Path $CsvFilePath | Select-Object -ExpandProperty Email
    }

    $foundError = $false
    [MailAddress[]]$ValidEmailAddresses = $null
    foreach ($EmailAddress in $EmailAddresses) {
        $tempAddress = $null
        $tempAddress = Test-EmailAddress -EmailAddress $EmailAddress
        if ($null -eq $tempAddress) {
            $foundError = $true
        } else {
            $ValidEmailAddresses += $tempAddress
        }
    }
    if ($foundError) {
        exit
    }

    if ( -not $OnlyMDOPolicies) {
        $malwareFilterRules = Get-MalwareFilterRule | Where-Object { $_.State -ne 'Disabled' }
        $antiPhishRules = Get-AntiPhishRule | Where-Object { $_.State -ne 'Disabled' }
        $hostedContentFilterRules = Get-HostedContentFilterRule | Where-Object { $_.State -ne 'Disabled' }
        $hostedOutboundSpamFilterRules = Get-HostedOutboundSpamFilterRule | Where-Object { $_.State -ne 'Disabled' }
        $eopProtectionPolicyRules = Get-EOPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }

        foreach ($email in $ValidEmailAddresses) {
            $emailAddress = $email.ToString()
            # Initialize a variable to capture all policy details
            $allPolicyDetails = ""
            $userDetails = Get-UserDetails -emailAddress $emailAddress

            # Check the EOPProtectionPolicyRules first as they have higher precedence
            $matchedRule = $null
            $matchedRule = Test-Rules -rules $eopProtectionPolicyRules -email $emailAddress

            if ($null -ne $matchedRule -and $eopProtectionPolicyRules -contains $matchedRule) {
                $allPolicyDetails += "`nThe policy that covers the user for malware, spam, and phishing: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority

                #    write-output ("`nThe policy that covers the user for malware, spam, and phishing: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority)
                $outboundSpamMatchedRule = Test-RulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress
                $allPolicyDetails += Get-Policy $outboundSpamMatchedRule "Outbound Spam"
                $allPolicyDetails = $userDetails + "`n" + $allPolicyDetails
                Write-Host $allPolicyDetails -ForegroundColor Green
                Write-Output "`n"
                continue
            }

            if ($null -eq $matchedRule) {
                # If no match in EOPProtectionPolicyRules, check MalwareFilterRules, AntiPhishRules, outboundSpam, and HostedContentFilterRules
                $malwareMatchedRule = Test-Rules -rules $malwareFilterRules -email $emailAddress
                $antiPhishMatchedRule = Test-Rules -rules $antiPhishRules -email $emailAddress
                $spamMatchedRule = Test-Rules -rules $hostedContentFilterRules -email $emailAddress
                $outboundSpamMatchedRule = Test-RulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress
            }

            # Capture the output of each Get-Policy call
            $allPolicyDetails += Get-Policy $malwareMatchedRule "Malware"
            $allPolicyDetails += Get-Policy $antiPhishMatchedRule "Anti-phish"
            $allPolicyDetails += Get-Policy $spamMatchedRule "Anti-spam"
            $allPolicyDetails += Get-Policy $outboundSpamMatchedRule "Outbound Spam"

            $allPolicyDetails = $userDetails + "`n" + $allPolicyDetails

            Write-Host $allPolicyDetails -ForegroundColor Yellow
        }
    }

    if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
        Write-Output "`n"
        Write-Host "This script checks to see which Safe Attachments and Safe Links policies apply to a user." -ForegroundColor Yellow
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
            } else {

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
        }
    }
}

Write-Host "`n"
