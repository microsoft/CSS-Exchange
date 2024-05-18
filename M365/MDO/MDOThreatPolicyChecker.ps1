# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
 This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant. In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant or confusing and lead to missed coverage of users or coverage by an unexpected threat policy.

.DESCRIPTION
 This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant. In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant or confusing and lead to missed coverage of users or coverage by an unexpected threat policy.

.PARAMETER CsvFilePath
  Allows you to specify a CSV file with a list of email addresses to check.
.PARAMETER EmailAddresses
  Allows you to specify email address or multiple addresses separated by commas.
.PARAMETER IncludeMDOPolicies
  Checks both EOP and MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddresses parameter.
.PARAMETER OnlyMDOPolicies
  Checks only MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddresses parameter.
.PARAMETER SkipConnectionCheck
  Skips connection check for Graph and Exchange Online.
.PARAMETER ScriptUpdateOnly
  Just updates script version to latest one.


.EXAMPLE
	.\MDOThreatPolicyChecker.ps1
	To check all threat policies for potentially confusing user inclusion and/or exclusion conditions and print them out for review.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv]
	To provide a CSV input file with email addresses and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@domainX.com,user2@domainY.com
	To provide multiple email addresses by command line and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies
	To provide a CSV input file with email addresses and see both EOP and MDO policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@domainX.com -OnlyMDOPolicies
	To provide an email address and see only MDO (Safe Attachment and Safe Links) policies.
#>

[CmdletBinding(DefaultParameterSetName = 'AppliedTenant')]
param(
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [string]$CsvFilePath,

    [Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'AppliedEmail')]
    [Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
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

begin {

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
}

process {
    if (-not $SkipConnectionCheck) {
        if ($PSCmdlet.ParameterSetName -ne "AppliedTenant") {
            #Validate Graph is connected
            $connection = $null
            $connection = Get-MgContext -ErrorAction SilentlyContinue
            if ($null -eq $connection) {
                Write-Host "Not connected to Graph" -ForegroundColor Red
                Write-Host "Please use Global administrator credentials" -ForegroundColor Yellow
                Write-Host "Connect-MgGraph -Scopes 'Group.Read.All','User.Read.All'" -ForegroundColor Yellow
                break
            } elseif ($connection.count -eq 1) {
                $ExpectedScopes = "GroupMember.Read.All", 'User.Read.All'
                if (Test-GraphContext -Scopes $connection.Scopes -ExpectedScopes $ExpectedScopes) {
                    Write-Host "Connected to Graph"
                    Write-Host "Session details"
                    Write-Host "Tenant: $((Get-MgOrganization).DisplayName)"
                } else {
                    Write-Host "We cannot continue without Graph Powershell session non Expected Scopes found" -ForegroundColor Red
                    break
                }
            } else {
                Write-Host "You have more than one Graph sessions please use just one session" -ForegroundColor Red
                break
            }
        }

        #Validate EXO PS Connection
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
                    $Issues += "User inclusions and exclusions. Excluding and including Users individually is redundant and confusing as only the included Users could possibly be included."
                }
                if ($Policy.RecipientDomainIs -and $Policy.ExceptIfRecipientDomainIs) {
                    $Issues += "Domain inclusions and exclusions. Excluding and including Domains is redundant and confusing as only the included Domains could possibly be included."
                }
                if ($Policy.SentTo -and $Policy.SentToMemberOf) {
                    $Issues += "Illogical inclusions of Users and Groups. The policy will only apply to Users who are also members of any Groups you have specified. This makes the Group inclusion redundant and confusing.`n    Suggestion: use one or the other type of inclusion."
                }
                if ($Policy.SentTo -and $Policy.RecipientDomainIs) {
                    $Issues += "Illogical inclusions of Users and Domains. The policy will only apply to Users whose email domains also match any Domains you have specified. This makes the Domain inclusion redundant and confusing.`n    Suggestion: use one or the other type of inclusion."
                }

                # If there are any issues, print the policy details once and then list all the issues
                if ($Issues.Count -gt 0) {
                    Write-Host ("`nPolicy '" + $Policy.Name + "':") -ForegroundColor Yellow
                    Write-Host ("   - Type: '" + $Cmdlets[$Cmdlet] + "'.") -ForegroundColor Yellow
                    Write-Host ("   - State: " + $Policy.State + ".") -ForegroundColor Yellow
                    Write-Host ("   - Issues: ") -ForegroundColor Red
                    foreach ($Issue in $Issues) {
                        Write-Host ("      -> " + $Issue)
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

        $AcceptedDomains = $null
        $AcceptedDomains = Get-AcceptedDomain

        if ($null -eq $AcceptedDomains) {
            Write-Host "We do not get accepted domains." -ForegroundColor Red
            exit
        }

        if ($AcceptedDomains.count -eq 0) {
            Write-Host "No accepted domains found." -ForegroundColor Red
            exit
        }

        $foundError = $false
        [MailAddress[]]$ValidEmailAddresses = $null
        foreach ($EmailAddress in $EmailAddresses) {
            $tempAddress = $null
            $tempAddress = Test-EmailAddress -EmailAddress $EmailAddress -AcceptedDomains $AcceptedDomains
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
        }

        if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
            #Write-Output "`n"
            #Write-Host "This script checks to see which Safe Attachments and Safe Links policies apply to a user." -ForegroundColor Yellow
            # Get the rules from Get-SafeAttachmentRule and Get-ATPProtectionPolicyRule
            $SafeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
            $SafeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
            $ATPProtectionPolicyRules = Get-ATPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }
            #Write-Output "`n"
        }

        foreach ($email in $ValidEmailAddresses) {
            $emailAddress = $email.ToString()
            # Initialize a variable to capture all policy details
            $allPolicyDetails = ""
            Write-Host "`nPolicies applied to $emailAddress..."

            if ( -not $OnlyMDOPolicies) {
                # Check the EOPProtectionPolicyRules first as they have higher precedence
                $matchedRule = $null
                $matchedRule = Test-Rules -rules $eopProtectionPolicyRules -email $emailAddress

                if ($null -ne $matchedRule -and $eopProtectionPolicyRules -contains $matchedRule) {
                    $allPolicyDetails += "`nFor malware, spam, and phishing: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority

                    #    write-output ("`nFor malware, spam, and phishing: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority)
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

            if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
                $domain = $email.Host

                # Check the ATPProtectionPolicyRules first as they have higher precedence
                $matchedRule = Test-Rules -rules $ATPProtectionPolicyRules -email $emailAddress -domain $domain

                if ($null -ne $matchedRule -and $ATPProtectionPolicyRules -contains $matchedRule) {
                    Write-Host ("For both Safe Attachments and Safe Links: `n   Name: {0}`n   Priority: {1}`n   The policy actions are not configurable.`n" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Magenta
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
                            if (![string]::IsNullOrEmpty($groupObjectId) -and (Test-IsInGroup -email $emailAddress -groupObjectId $groupObjectId)) {
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
                            Write-Host "`nSafe Attachments: `n  If your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy. This policy is not configurable." -ForegroundColor Yellow
                        }
                        $policy = $null
                    } else {
                        $policy = Get-SafeAttachmentPolicy -Identity $SAmatchedRule.Name
                        Write-Host ("`nSafe Attachments: `n   Name: {0}`n   Priority: {1}" -f $SAmatchedRule.Name, $SAmatchedRule.Priority) -ForegroundColor Green
                    }

                    if ($null -eq $SLmatchedRule) {
                        # Get the Built-in Protection Rule
                        $builtInProtectionRule = Get-ATPBuiltInProtectionRule

                        # Initialize a variable to track if the user is a member of any excluded group
                        $isInExcludedGroup = $false

                        # Check if the user is a member of any group in ExceptIfSentToMemberOf
                        foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
                            $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
                            if (![string]::IsNullOrEmpty($groupObjectId) -and (Test-IsInGroup -email $emailAddress -groupObjectId $groupObjectId)) {
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
                            Write-Host "`nSafe Links: `n  If your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy. This policy is not configurable." -ForegroundColor Yellow
                        }
                        $policy = $null
                    } else {
                        $policy = Get-SafeLinksPolicy -Identity $SLmatchedRule.Name
                        Write-Host ("Safe Links: `n  Name: {0}`n   Priority: {1}" -f $SLmatchedRule.Name, $SLmatchedRule.Priority) -ForegroundColor Green
                    }
                }
            }
        }
    }

    Write-Host "`n"
}