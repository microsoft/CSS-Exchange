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

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [switch]$IncludeMDOPolicies,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$OnlyMDOPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$ShowDetailedPolicies,

    [Parameter(ParameterSetName = 'AppliedCsv', Mandatory = $false)]
    [Parameter(ParameterSetName = 'AppliedEmail', Mandatory = $false)]
    [Parameter(ParameterSetName = 'AppliedMDOCsv', Mandatory = $false)]
    [Parameter(ParameterSetName = 'AppliedMDOEmail', Mandatory = $false)]
    [Parameter(ParameterSetName = 'AppliedTenant', Mandatory = $false)]
    [switch]$SkipConnectionCheck,

    [Parameter(ParameterSetName = 'AppliedCsv')]
    [Parameter(ParameterSetName = 'AppliedEmail')]
    [Parameter(ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(ParameterSetName = 'AppliedMDOEmail')]
    [Parameter(ParameterSetName = 'AppliedTenant')]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

begin {

    . $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
    . $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1

    function Get-GroupObjectId {
        [OutputType([string])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [MailAddress]$groupEmail
        )

        # Get the group
        $group = $null
        $group = Get-MgGroup -Filter "mail eq '$($groupEmail)'" -ErrorAction SilentlyContinue

        if ($group) {
            # Return the Object ID of the group
            return $group.Id
        } else {
            Write-Host "The EmailAddress of group $groupEmail was not found" -ForegroundColor Red
            return $null
        }
    }

    function Test-EmailAddress {
        [OutputType([MailAddress])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$EmailAddress,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            $AcceptedDomains
        )

        try {
            $tempAddress = $null
            $tempAddress = [MailAddress]$EmailAddress
        } catch {
            Write-Host "The EmailAddress $EmailAddress cannot be validated. Please provide a valid email address." -ForegroundColor Red
            return $null
        }
        $recipient = $null
        $recipient = Get-Recipient $EmailAddress -ErrorAction SilentlyContinue
        if ($null -eq $recipient) {
            Write-Host "$EmailAddress is not a recipient in this tenant" -ForegroundColor Red
            return $null
        } else {
            $Domain = $tempAddress.Host
            if ($AcceptedDomains.DomainName -contains $Domain) {
                return $tempAddress
            } else {
                Write-Host "The domain $Domain is not an accepted domain in your organization. Please provide a valid email address." -ForegroundColor Red
                return $null
            }
        }
    }

    # Function to check if an email is in a group
    function Test-IsInGroup {
        [OutputType([bool])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [MailAddress]$email,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$groupObjectId
        )

        # Get the group members
        $groupMembers = $null
        $groupMembers = Get-MgGroupMember -GroupId $groupObjectId

        # Check if the email address is in the group
        if ($null -ne $groupMembers) {
            foreach ($member in $groupMembers) {
                # Get the user object by Id
                $user = Get-MgUser -UserId $member.Id
                # Compare the user's email address with the $email parameter
                if ($user.Mail -eq $email.ToString()) {
                    return $true
                }
            }
        } else {
            Write-Host "The group with Object ID $groupObjectId does not have any members." -ForegroundColor Red
        }
        return $false
    }

    # Function to check rules
    function Test-Rules {
        param(
            [Parameter(Mandatory = $true)]
            $rules,
            [Parameter(Mandatory = $true)]
            [MailAddress]$email
        )
        foreach ($rule in $rules) {
            $isInGroup = $false
            if ($rule.SentToMemberOf) {
                foreach ($groupEmail in $rule.SentToMemberOf) {
                    $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $isInGroup = Test-IsInGroup -email $email -groupObjectId $groupObjectId
                        if ($isInGroup) {
                            break
                        }
                    }
                }
            }

            $isInExceptGroup = $false
            if ($rule.ExceptIfSentToMemberOf) {
                foreach ($groupEmail in $rule.ExceptIfSentToMemberOf) {
                    $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $isInExceptGroup = Test-IsInGroup -email $email -groupObjectId $groupObjectId
                        if ($isInExceptGroup) {
                            break
                        }
                    }
                }
            }

            $temp = $email.Host
            $DomainIncluded = $false
            $DomainExcluded = $false
            while ($temp.IndexOf(".") -gt 0) {
                if ($temp -in $rule.RecipientDomainIs) {
                    $DomainIncluded = $true
                }
                if ($temp -in $rule.ExceptIfRecipientDomainIs) {
                    $DomainExcluded = $true
                }
                $temp = $temp.Substring($temp.IndexOf(".") + 1)
            }

            # Check for explicit inclusion in any user, group, or domain that are not empty, and account for 3 empty inclusions
            # Also check for any exclusions as user, group, or domain. Nulls don't need to be accounted for and this is an OR condition for exclusions
            if ((($email -in $rule.SentTo -or !$rule.SentTo) -and
                ($DomainIncluded -or !$rule.RecipientDomainIs) -and
                ($isInGroup -or !$rule.SentToMemberOf)) -and
                ($DomainIncluded -or $isInGroup -or $email -in $rule.SentTo)) {
                if (($email -notin $rule.ExceptIfSentTo) -and
                    (!$isInExceptGroup) -and
                    (!$DomainExcluded)) {
                    return $rule
                }
            }
            # Check for implicit inclusion (no mailboxes included at all), which is possible for Presets and SA/SL. They are included if not explicitly excluded.
            if (!$rule.SentTo -and !$rule.RecipientDomainIs -and !$rule.SentToMemberOf) {
                if (($email -notin $rule.ExceptIfSentTo) -and
                    (!$isInExceptGroup) -and
                    (!$DomainExcluded)) {
                    return $rule
                }
            }
        }
        return $null
    }

    function Test-RulesAlternative {
        param(
            [Parameter(Mandatory = $true)]
            $rules,
            [Parameter(Mandatory = $true)]
            [MailAddress]$email
        )
        foreach ($rule in $rules) {
            $isInGroup = $false
            if ($rule.FromMemberOf) {
                foreach ($groupEmail in $rule.FromMemberOf) {
                    $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $isInGroup = Test-IsInGroup -email $email.Address -groupObjectId $groupObjectId
                        if ($isInGroup) {
                            break
                        }
                    }
                }
            }

            $isInExceptGroup = $false
            if ($rule.ExceptIfFromMemberOf) {
                foreach ($groupEmail in $rule.ExceptIfFromMemberOf) {
                    $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $isInExceptGroup = Test-IsInGroup -email $email.Address -groupObjectId $groupObjectId
                        if ($isInExceptGroup) {
                            break
                        }
                    }
                }
            }

            $temp = $email.Host
            $DomainIncluded = $false
            $DomainExcluded = $false
            while ($temp.IndexOf(".") -gt 0) {
                if ($temp -in $rule.SenderDomainIs) {
                    $DomainIncluded = $true
                }
                if ($temp -in $rule.ExceptIfRecipientDomainIs) {
                    $DomainExcluded = $true
                }
                $temp = $temp.Substring($temp.IndexOf(".") + 1)
            }

            # Check for explicit inclusion in any user, group, or domain that are not empty, and they need to be included in at least 1 inclusion condition
            # Then check for any exclusions as user, group, or domain. Nulls don't need to be accounted for in the exclusions
            if ((($email -in $rule.From -or !$rule.From) -and
            ($DomainIncluded -or !$rule.SenderDomainIs) -and
            ($isInGroup -or !$rule.FromMemberOf)) -and
            ($isInGroup -or $DomainIncluded -or $email -in $rule.From)) {
                if (($email -notin $rule.ExceptIfFrom) -and
                (!$DomainExcluded) -and
                (!$isInExceptGroup)) {
                    return $rule
                }
            }
        }
        return $null
    }

    function Show-DetailedPolicy {
        param (
            [Parameter(Mandatory = $true)]
            $policy
        )
        <<<<<<< HEAD
        Write-Host "`tProperties of the policy that are True, On, or not blank:" -ForegroundColor Yellow
        =======
        Write-Host "`n`tProperties of the policy that are True, On, or not blank:"
        >>>>>>> 2f66cc78cfb5f40b6f4a0dedf3e2951397c548ba
        $excludedProperties = 'Identity', 'Id', 'Name', 'ExchangeVersion', 'DistinguishedName', 'ObjectCategory', 'ObjectClass', 'WhenChanged', 'WhenCreated', 'WhenChangedUTC', 'WhenCreatedUTC', 'ExchangeObjectId', 'OrganizationalUnitRoot', 'OrganizationId', 'OriginatingServer', 'ObjectState'

        $policy.PSObject.Properties | ForEach-Object {
            if ($null -ne $_.Value -and $_.Value -ne '{}' -and $_.Value -ne 'Off' -and $_.Value -ne 'False' -and $_.Value -ne '' -and $excludedProperties -notcontains $_.Name) {
                Write-Host "`t`t$($_.Name): $($_.Value)"
            }
        }
        Write-Host " "
    }

    function Get-Policy {
        param(
            $rule = $null,
            $policyType = $null
        )

        if ($null -eq $rule) {
            if ($policyType -eq "Anti-phish") {
                $policyDetails = "`n$policyType (Impersonation, Mailbox/Spoof Intelligence, Honor DMARC):`n`tThe Default policy."
            } elseif ($policyType -eq "Anti-spam") {
                $policyDetails = "`n$policyType (includes phish & bulk actions):`n`tThe Default policy."
            } else {
                $policyDetails = "`n${policyType}:`n`tThe Default policy."
            }
        } else {
            if ($policyType -eq "Anti-phish") {
                $policyDetails = "`n$policyType (Impersonation, Mailbox/Spoof Intelligence, Honor DMARC):`n`tName: {0}`n`tPriority: {1}" -f $rule.Name, $rule.Priority
            } elseif ($policyType -eq "Anti-spam") {
                $policyDetails = "`n$policyType (includes phish & bulk actions):`n`tName: {0}`n`tPriority: {1}" -f $rule.Name, $rule.Priority
            } else {
                $policyDetails = "`n${policyType}:`n`tName: {0}`n`tPriority: {1}" -f $rule.Name, $rule.Priority
            }
        }
        return $policyDetails
    }

    function Test-GraphContext {
        [OutputType([bool])]
        param (
            [Parameter(Mandatory = $true)]
            [string[]]$Scopes,
            [Parameter(Mandatory = $true)]
            [string[]]$ExpectedScopes
        )

        $ValidScope = $true
        foreach ($ExpectedScope in $ExpectedScopes) {
            if ($Scopes -contains $ExpectedScope) {
                Write-Verbose "Scopes $ExpectedScope is present."
            } else {
                Write-Host "The following scope is missing: $ExpectedScope" -ForegroundColor Red
                $ValidScope = $false
            }
        }
        return $ValidScope
    }

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

    Write-Host " "
    Write-Host "Disclaimer:

The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever
(including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages." -ForegroundColor Yellow
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
                    Write-Host "We cannot continue without Graph Powershell session without Expected Scopes" -ForegroundColor Red
                    break
                }
            } else {
                Write-Host "You have more than one Graph sessions. Please use just one session" -ForegroundColor Red
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
            Write-Host "You have more than one EXO sessions. Please use just one session" -ForegroundColor Red
            break
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "AppliedTenant") {
        # Define the cmdlets to retrieve policies from and their corresponding policy types
        $Cmdlets = @{
            "Get-HostedContentFilterRule"                                               = "Anti-spam Policy"
            "Get-HostedOutboundSpamFilterRule"                                          = "Outbound Spam Policy"
            "Get-MalwareFilterRule"                                                     = "Malware Policy"

            "Get-AntiPhishRule"                                                         = "Anti-phishing Policy"
            "Get-SafeLinksRule"                                                         = "Safe Links Policy"
            "Get-SafeAttachmentRule"                                                    = "Safe Attachment Policy"
            "Get-ATPBuiltInProtectionRule"                                              = "Built-in protection preset security Policy"
            # "Get-EOPProtectionPolicyRule"      = "Preset security policies Policy"
            # "Get-ATPProtectionPolicyRule"      = "MDO (SafeLinks/SafeAttachments) Policy in preset security policies"
            { Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' }   = "EOP"
            { Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' } = "EOP"
            { Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' }   = "MDO (Safe Links / Safe Attachments)"
            { Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' } = "MDO (Safe Links / Safe Attachments)"
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
                    Write-Host ("`t- Type: '" + $Cmdlets[$Cmdlet] + "'.") -ForegroundColor Yellow
                    Write-Host ("`t- State: " + $Policy.State + ".") -ForegroundColor Yellow
                    Write-Host ("`t- Issues: ") -ForegroundColor Red
                    foreach ($Issue in $Issues) {
                        Write-Host ("`t`t-> " + $Issue)
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
            #Handle csv control to expected content
            $EmailAddresses = Import-Csv -Path $CsvFilePath | Select-Object -ExpandProperty Email
        }

        $AcceptedDomains = $null
        $AcceptedDomains = Get-AcceptedDomain -ErrorAction SilentlyContinue

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

        $malwareFilterRules = $null
        $antiPhishRules = $null
        $hostedContentFilterRules = $null
        $hostedOutboundSpamFilterRules = $null
        $EopStrictPresetRules = $null
        $EopStandardPresetRules = $null

        if ( -not $OnlyMDOPolicies) {
            $malwareFilterRules = Get-MalwareFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $antiPhishRules = Get-AntiPhishRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedContentFilterRules = Get-HostedContentFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedOutboundSpamFilterRules = Get-HostedOutboundSpamFilterRule | Where-Object { $_.State -ne 'Disabled' }
            # $eopProtectionPolicyRules = Get-EOPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }
            $EopStrictPresetRules = Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
            $EopStandardPresetRules = Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
        }

        $SafeAttachmentRules = $null
        $SafeLinksRules = $null
        $MdoStrictPresetRules = $null
        $MdoStandardPresetRules = $null

        if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
            # Get the custom and preset rules for Safe Attachments/Links
            $SafeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
            $SafeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
            # $ATPProtectionPolicyRules = Get-ATPProtectionPolicyRule | Where-Object { $_.State -ne 'Disabled' }
            $MdoStrictPresetRules = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
            $MdoStandardPresetRules = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
        }

        foreach ($email in $ValidEmailAddresses) {
            $emailAddress = $email.ToString()
            # Initialize a variable to capture all policy details
            $allPolicyDetails = ""
            Write-Host "`n`nPolicies applied to $emailAddress..."

            if ( -not $OnlyMDOPolicies) {
                # Check the Strict EOP rules first as they have higher precedence
                $matchedRule = $null
                # $matchedRule = Test-Rules -rules $eopProtectionPolicyRules -email $emailAddress
                $matchedRule = Test-Rules -rules $EopStrictPresetRules -email $emailAddress
                if ($EopStrictPresetRules -contains $matchedRule) {
                    $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}`n`tThe policy actions are not configurable." -f $matchedRule.Name, $matchedRule.Priority
                    Write-Host $allPolicyDetails -ForegroundColor Green
                    $outboundSpamMatchedRule = $null
                    $outboundSpamMatchedRule = Test-RulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress
                    $allPolicyDetails = Get-Policy $outboundSpamMatchedRule "Outbound Spam"
                    Write-Host $allPolicyDetails -ForegroundColor Yellow
                } else {
                    # Check the Standard EOP rules secondly
                    $matchedRule = $null
                    $matchedRule = Test-Rules -rules $EopStandardPresetRules -email $emailAddress

                    if ($EopStandardPresetRules -contains $matchedRule) {
                        $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}`n`tThe policy actions are not configurable." -f $matchedRule.Name, $matchedRule.Priority
                        Write-Host $allPolicyDetails -ForegroundColor Green

                        $outboundSpamMatchedRule = $null
                        $outboundSpamMatchedRule = Test-RulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress
                        $allPolicyDetails = Get-Policy $outboundSpamMatchedRule "Outbound Spam"
                        Write-Host $allPolicyDetails -ForegroundColor Yellow
                    } else {
                        # If no match in EOPProtectionPolicyRules, check MalwareFilterRules, AntiPhishRules, outboundSpam, and HostedContentFilterRules
                        $malwareMatchedRule = $null
                        $malwareMatchedRule = Test-Rules -rules $malwareFilterRules -email $emailAddress
                        $allPolicyDetails = " "
                        Write-Host (Get-Policy $malwareMatchedRule "Malware") -ForegroundColor Yellow
                        if ($malwareMatchedRule -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy (Get-MalwareFilterPolicy $malwareMatchedRule.Identity)
                        }
                        $antiPhishMatchedRule = $null
                        $antiPhishMatchedRule = Test-Rules -rules $antiPhishRules -email $emailAddress
                        Write-Host (Get-Policy $antiPhishMatchedRule "Anti-phish") -ForegroundColor Yellow
                        if ($antiPhishMatchedRule -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy (Get-AntiPhishPolicy $antiPhishMatchedRule.Identity)
                        }
                        $spamMatchedRule = $null
                        $spamMatchedRule = Test-Rules -rules $hostedContentFilterRules -email $emailAddress
                        Write-Host (Get-Policy $spamMatchedRule "Anti-spam") -ForegroundColor Yellow
                        if ($spamMatchedRule -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy (Get-HostedContentFilterPolicy $spamMatchedRule.Identity)
                        }
                        $outboundSpamMatchedRule = $null
                        $outboundSpamMatchedRule = Test-RulesAlternative -rules $hostedOutboundSpamFilterRules -email $emailAddress
                        Write-Host (Get-Policy $outboundSpamMatchedRule "Outbound Spam") -ForegroundColor Yellow
                        if ($outboundSpamMatchedRule -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy (Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.Identity)
                        }
                        $allPolicyDetails = $userDetails + "`n" + $allPolicyDetails
                        Write-Host $allPolicyDetails -ForegroundColor Yellow
                    }
                }
            }

            if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
                $domain = $email.Host
                $matchedRule = $null

                # Check the MDO Strict Preset rules first as they have higher precedence
                $matchedRule = Test-Rules -rules $MdoStrictPresetRules -email $emailAddress

                if ($MdoStrictPresetRules -contains $matchedRule) {
                    Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                } else {
                    # Check the Standard MDO rules secondly
                    $matchedRule = $null
                    $matchedRule = Test-Rules -rules $MdoStandardPresetRules -email $emailAddress

                    if ($MdoStandardPresetRules -contains $matchedRule) {
                        Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                    } else {
                        # No match in preset ATPProtectionPolicyRules, check custom SA/SL rules
                        $SAmatchedRule = $null
                        $SAmatchedRule = Test-Rules -rules $SafeAttachmentRules -email $emailAddress

                        $SLmatchedRule = $null
                        $SLmatchedRule = Test-Rules -rules $SafeLinksRules -email $emailAddress

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
                                Write-Host "`nSafe Attachments:`n`tThe user is excluded from all Safe Attachment protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Attachments:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $policy = Get-SafeAttachmentPolicy -Identity $SAmatchedRule.Name
                            Write-Host ("`nSafe Attachments:`n`tName: {0}`n`tPriority: {1}" -f $SAmatchedRule.Name, $SAmatchedRule.Priority) -ForegroundColor Yellow
                            if ($SAmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy (Get-SafeAttachmentPolicy $SAmatchedRule.Identity)
                            }
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
                                Write-Host "`nSafe Links:`n`tThe user is excluded from all Safe Links protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Links:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $policy = Get-SafeLinksPolicy -Identity $SLmatchedRule.Name
                            Write-Host ("`nSafe Links:`n`tName: {0}`n`tPriority: {1}" -f $SLmatchedRule.Name, $SLmatchedRule.Priority) -ForegroundColor Yellow
                            if ($SLmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy (Get-SafeLinksPolicy $SLmatchedRule.Identity)
                            }
                        }
                    }
                }
            }
        }
    }
    Write-Host " "
}
