# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Evaluates user coverage and potential redundancies in Microsoft Defender for Office 365 and Exchange Online Protection threat policies, including anti-malware, anti-phishing, and anti-spam policies, as well as Safe Attachments and Safe Links policies if licensed.

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
	.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@contoso.com,user2@fabrikam.com
	To provide multiple email addresses by command line and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies
	To provide a CSV input file with email addresses and see both EOP and MDO policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@contoso.com -OnlyMDOPolicies
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

    # Cache to reduce calls to Get-MgGroup
    $groupCache = @{}
    # Cache of members to reduce number of calls to Get-MgGroupMember
    $memberCache = @{}

    function Get-GroupObjectId {
        [OutputType([string])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [MailAddress]$GroupEmail
        )

        # Check the cache first
        if ($groupCache.ContainsKey($GroupEmail)) {
            return $groupCache[$GroupEmail]
        }

        # Get the group
        $group = $null
        $group = Get-MgGroup -Filter "mail eq '$($GroupEmail)'" -ErrorAction SilentlyContinue

        if ($group) {
            # Cache the result
            $groupCache[$GroupEmail] = $group.Id

            # Return the Object ID of the group
            return $group.Id
        } else {
            Write-Host "The EmailAddress of group $GroupEmail was not found" -ForegroundColor Red
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
            $domain = $tempAddress.Host
            if ($AcceptedDomains.DomainName -contains $domain) {
                return $tempAddress
            } else {
                Write-Host "The domain $domain is not an accepted domain in your organization. Please provide a valid email address." -ForegroundColor Red
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
            [MailAddress]$Email,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$GroupObjectId
        )

        # Check the cache first
        $cacheKey = "$Email|$GroupObjectId"
        if ($memberCache.ContainsKey($cacheKey)) {
            return $memberCache[$cacheKey]
        }

        # Get the group members
        $groupMembers = $null
        $groupMembers = Get-MgGroupMember -GroupId $GroupObjectId

        # Check if the email address is in the group
        if ($null -ne $groupMembers) {
            foreach ($member in $groupMembers) {
                # Get the user object by Id
                $user = Get-MgUser -UserId $member.Id
                # Compare the user's email address with the $email parameter
                if ($user.Mail -eq $Email.ToString()) {
                    # Cache the result
                    $memberCache[$cacheKey] = $true
                    return $true
                }
            }
        } else {
            Write-Host "The group with Object ID $GroupObjectId does not have any members." -ForegroundColor Red
        }

        # Cache the result
        $memberCache[$cacheKey] = $false
        return $false
    }

    # Function to check rules
    function Test-Rules {
        param(
            [Parameter(Mandatory = $true)]
            $Rules,
            [Parameter(Mandatory = $true)]
            [MailAddress]$Email
        )
        foreach ($rule in $Rules) {
            $isInGroup = $false
            if ($rule.SentToMemberOf) {
                foreach ($groupEmail in $rule.SentToMemberOf) {
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $isInGroup = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($isInGroup) {
                            break
                        }
                    }
                }
            }

            $isInExceptGroup = $false
            if ($rule.ExceptIfSentToMemberOf) {
                foreach ($groupEmail in $rule.ExceptIfSentToMemberOf) {
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $isInExceptGroup = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($isInExceptGroup) {
                            break
                        }
                    }
                }
            }

            $temp = $Email.Host
            $domainIncluded = $false
            $domainExcluded = $false
            while ($temp.IndexOf(".") -gt 0) {
                if ($temp -in $rule.RecipientDomainIs) {
                    $domainIncluded = $true
                }
                if ($temp -in $rule.ExceptIfRecipientDomainIs) {
                    $domainExcluded = $true
                }
                $temp = $temp.Substring($temp.IndexOf(".") + 1)
            }

            # Check for explicit inclusion in any user, group, or domain that are not empty, and account for 3 empty inclusions
            # Also check for any exclusions as user, group, or domain. Nulls don't need to be accounted for and this is an OR condition for exclusions
            if ((($Email -in $rule.SentTo -or (-not $rule.SentTo)) -and
                ($domainIncluded -or (-not $rule.RecipientDomainIs)) -and
                ($isInGroup -or (-not $rule.SentToMemberOf))) -and
                ($DomainIncluded -or $isInGroup -or $Email -in $rule.SentTo)) {
                if (($Email -notin $rule.ExceptIfSentTo) -and
                    (-not $isInExceptGroup) -and
                    (-not $domainExcluded)) {
                    return $rule
                }
            }
            # Check for implicit inclusion (no mailboxes included at all), which is possible for Presets and SA/SL. They are included if not explicitly excluded.
            if ((-not $rule.SentTo) -and (-not $rule.RecipientDomainIs) -and (-not $rule.SentToMemberOf)) {
                if (($Email -notin $rule.ExceptIfSentTo) -and
                    (-not $isInExceptGroup) -and
                    (-not $domainExcluded)) {
                    return $rule
                }
            }
        }
        return $null
    }

    function Test-RulesAlternative {
        param(
            [Parameter(Mandatory = $true)]
            $Rules,
            [Parameter(Mandatory = $true)]
            [MailAddress]$Email
        )
        foreach ($rule in $Rules) {
            $isInGroup = $false
            if ($rule.FromMemberOf) {
                foreach ($groupEmail in $rule.FromMemberOf) {
                    $groupObjectId = Get-GroupObjectId -groupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $isInGroup = Test-IsInGroup -Email $Email.Address -GroupObjectId $groupObjectId
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
                        $isInExceptGroup = Test-IsInGroup -Email $Email.Address -GroupObjectId $groupObjectId
                        if ($isInExceptGroup) {
                            break
                        }
                    }
                }
            }

            $temp = $Email.Host
            $domainIncluded = $false
            $domainExcluded = $false
            while ($temp.IndexOf(".") -gt 0) {
                if ($temp -in $rule.SenderDomainIs) {
                    $domainIncluded = $true
                }
                if ($temp -in $rule.ExceptIfRecipientDomainIs) {
                    $domainExcluded = $true
                }
                $temp = $temp.Substring($temp.IndexOf(".") + 1)
            }

            # Check for explicit inclusion in any user, group, or domain that are not empty, and they need to be included in at least 1 inclusion condition
            # Then check for any exclusions as user, group, or domain. Nulls don't need to be accounted for in the exclusions
            if ((($Email -in $rule.From -or (-not $rule.From)) -and
            ($domainIncluded -or (-not $rule.SenderDomainIs)) -and
            ($isInGroup -or (-not $rule.FromMemberOf))) -and
            ($isInGroup -or $domainIncluded -or $Email -in $rule.From)) {
                if (($Email -notin $rule.ExceptIfFrom) -and
                    (-not $domainExcluded) -and
                    (-not $isInExceptGroup)) {
                    return $rule
                }
            }
        }
        return $null
    }

    function Show-DetailedPolicy {
        param (
            [Parameter(Mandatory = $true)]
            $Policy
        )
        Write-Host "`n`tProperties of the policy that are True, On, or not blank:"
        $excludedProperties = 'Identity', 'Id', 'Name', 'ExchangeVersion', 'DistinguishedName', 'ObjectCategory', 'ObjectClass', 'WhenChanged', 'WhenCreated', 'WhenChangedUTC', 'WhenCreatedUTC', 'ExchangeObjectId', 'OrganizationalUnitRoot', 'OrganizationId', 'OriginatingServer', 'ObjectState'

        $Policy.PSObject.Properties | ForEach-Object {
            if ($null -ne $_.Value -and $_.Value -ne '{}' -and $_.Value -ne 'Off' -and $_.Value -ne 'False' -and $_.Value -ne '' -and $excludedProperties -notcontains $_.Name) {
                Write-Host "`t`t$($_.Name): $($_.Value)"
            }
        }
        Write-Host " "
    }

    function Get-Policy {
        param(
            $Rule = $null,
            $PolicyType = $null
        )

        if ($null -eq $Rule) {
            if ($PolicyType -eq "Anti-phish") {
                $policyDetails = "`n$PolicyType (Impersonation, Mailbox/Spoof Intelligence, Honor DMARC):`n`tThe Default policy."
            } elseif ($PolicyType -eq "Anti-spam") {
                $policyDetails = "`n$PolicyType (includes phish & bulk actions):`n`tThe Default policy."
            } else {
                $policyDetails = "`n${PolicyType}:`n`tThe Default policy."
            }
        } else {
            if ($PolicyType -eq "Anti-phish") {
                $policyDetails = "`n$PolicyType (Impersonation, Mailbox/Spoof Intelligence, Honor DMARC):`n`tName: {0}`n`tPriority: {1}" -f $Rule.Name, $Rule.Priority
            } elseif ($PolicyType -eq "Anti-spam") {
                $policyDetails = "`n$PolicyType (includes phish & bulk actions):`n`tName: {0}`n`tPriority: {1}" -f $Rule.Name, $Rule.Priority
            } else {
                $policyDetails = "`n${PolicyType}:`n`tName: {0}`n`tPriority: {1}" -f $Rule.Name, $Rule.Priority
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

    function Write-HostLog ($Message) {
        if (-not [string]::IsNullOrEmpty($Message)) {
            $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $Message
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

    if ((-not($SkipVersionCheck)) -and (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false)) {
        Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
        return
    }
}

process {
    if (-not $SkipConnectionCheck) {
        #Validate EXO PS Connection
        $exoConnection = $null
        try {
            $exoConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Error checking EXO connection" -ForegroundColor Red
            Write-Host "Verify that you have ExchangeOnlineManagement module installed" -ForegroundColor Yellow
            Write-Host "You need a connection To Exchange Online, you can use:" -ForegroundColor Yellow
            Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
            Write-Host "Exchange Online Powershell Module is required" -ForegroundColor Red
            exit
        }
        if ($null -eq $exoConnection) {
            Write-Host "Not connected to EXO" -ForegroundColor Red
            Write-Host "You need a connection To Exchange Online, you can use:" -ForegroundColor Yellow
            Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
            Write-Host "Exchange Online Powershell Module is required" -ForegroundColor Red
            exit
        } elseif ($exoConnection.count -eq 1) {
            Write-Host " "
            Write-Host "Connected to EXO"
            Write-Host "Session details"
            Write-Host "Tenant Id: $($exoConnection.TenantId)"
            Write-Host "User: $($exoConnection.UserPrincipalName)"
        } else {
            Write-Host "You have more than one EXO sessions. Please use just one session" -ForegroundColor Red
            exit
        }

        if ($PSCmdlet.ParameterSetName -ne "AppliedTenant") {
            #Validate Graph is connected
            $graphConnection = $null
            Write-Host " "
            try {
                $graphConnection = Get-MgContext -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Error checking Graph connection" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded" -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "Connect-MgGraph -Scopes 'Group.Read.All','User.Read.All'" -ForegroundColor Yellow
                exit
            }
            if ($null -eq $graphConnection) {
                Write-Host "Not connected to Graph" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded" -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "Connect-MgGraph -Scopes 'Group.Read.All','User.Read.All'" -ForegroundColor Yellow
                exit
            } elseif ($graphConnection.count -eq 1) {
                $expectedScopes = "GroupMember.Read.All", 'User.Read.All'
                if (Test-GraphContext -Scopes $graphConnection.Scopes -ExpectedScopes $expectedScopes) {
                    Write-Host "Connected to Graph"
                    Write-Host "Session details"
                    Write-Host "TenantID: $(($graphConnection).TenantId)"
                    Write-Host "Account: $(($graphConnection).Account)"
                } else {
                    Write-Host "We cannot continue without Graph Powershell session without Expected Scopes" -ForegroundColor Red
                    Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded" -ForegroundColor Yellow
                    Write-Host "You could use:" -ForegroundColor Yellow
                    Write-Host "Connect-MgGraph -Scopes 'Group.Read.All','User.Read.All'" -ForegroundColor Yellow
                    exit
                }
            } else {
                Write-Host "You have more than one Graph sessions. Please use just one session" -ForegroundColor Red
                exit
            }
            if (($graphConnection.TenantId) -ne ($exoConnection.TenantId) ) {
                Write-Host "`nThe Tenant Id from Graph and EXO are different. Please use the same tenant" -ForegroundColor Red
                exit
            }
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "AppliedTenant") {
        # Define the cmdlets to retrieve policies from and their corresponding policy types
        $cmdlets = @{
            "Get-HostedContentFilterRule"                                               = "Anti-spam Policy"
            "Get-HostedOutboundSpamFilterRule"                                          = "Outbound Spam Policy"
            "Get-MalwareFilterRule"                                                     = "Malware Policy"
            "Get-AntiPhishRule"                                                         = "Anti-phishing Policy"
            "Get-SafeLinksRule"                                                         = "Safe Links Policy"
            "Get-SafeAttachmentRule"                                                    = "Safe Attachment Policy"
            "Get-ATPBuiltInProtectionRule"                                              = "Built-in protection preset security Policy"
            { Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' }   = "EOP"
            { Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' } = "EOP"
            { Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' }   = "MDO (Safe Links / Safe Attachments)"
            { Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' } = "MDO (Safe Links / Safe Attachments)"
        }

        $foundIssues = $false

        Write-Host " "
        # Loop through each cmdlet
        foreach ($cmdlet in $cmdlets.Keys) {
            # Retrieve the policies
            $policies = & $cmdlet

            # Loop through each policy
            foreach ($policy in $policies) {
                # Initialize an empty list to store issues
                $issues = New-Object System.Collections.Generic.List[string]

                # Check the logic of the policy and add issues to the list
                if ($policy.SentTo -and $policy.ExceptIfSentTo) {
                    $issues.Add("`t`t-> User inclusions and exclusions. `n`t`t`tExcluding and including Users individually is redundant and confusing as only the included Users could possibly be included.`n")
                }
                if ($policy.RecipientDomainIs -and $policy.ExceptIfRecipientDomainIs) {
                    $issues.Add("`t`t-> Domain inclusions and exclusions. `n`t`t`tExcluding and including Domains is redundant and confusing as only the included Domains could possibly be included.`n")
                }
                if ($policy.SentTo -and $policy.SentToMemberOf) {
                    $issues.Add("`t`t-> Illogical inclusions of Users and Groups. `n`t`t`tThe policy will only apply to Users who are also members of any Groups you have specified. `n`t`t`tThis makes the Group inclusion redundant and confusing.`n`t`t`tSuggestion: use one or the other type of inclusion.`n")
                }
                if ($policy.SentTo -and $policy.RecipientDomainIs) {
                    $issues.Add("`t`t-> Illogical inclusions of Users and Domains. `n`t`t`tThe policy will only apply to Users whose email domains also match any Domains you have specified. `n`t`t`tThis makes the Domain inclusion redundant and confusing.`n`t`t`tSuggestion: use one or the other type of inclusion.`n")
                }

                # If there are any issues, print the policy details once and then list all the issues
                if ($issues.Count -gt 0) {
                    if ($policy.State -eq "Enabled") {
                        $color = $null
                    } else {
                        $color = "Yellow"
                    }
                    Write-Host ("Policy $($policy.Name):")
                    Write-Host ("`tType: $($cmdlets[$cmdlet]).")
                    Write-Host ("`tState: $($policy.State).") -ForegroundColor $color
                    Write-Host ("`tIssues: ") -ForegroundColor Red
                    foreach ($issue in $issues) {
                        Write-Host $issue
                    }
                    $foundIssues = $true
                }
            }
        }
        if (-not $foundIssues) {
            Write-Host ("No logical inconsistencies found!") -ForegroundColor DarkGreen
        }
    } else {
        if ($CsvFilePath) {
            try {
                # Import CSV file
                $csvFile = Import-Csv -Path $CsvFilePath
                # checking 'email' header
                if ($csvFile[0].PSObject.Properties.Name -contains 'Email') {
                    $EmailAddresses = $csvFile | Select-Object -ExpandProperty Email
                } else {
                    Write-Host "CSV does not contain 'Email' header." -ForegroundColor Red
                    exit
                }
            } catch {
                Write-Host "Error importing CSV file: $_" -ForegroundColor Red
                exit
            }
        }

        $acceptedDomains = $null
        $acceptedDomains = Get-AcceptedDomain -ErrorAction SilentlyContinue

        if ($null -eq $acceptedDomains) {
            Write-Host "We do not get accepted domains." -ForegroundColor Red
            exit
        }

        if ($acceptedDomains.count -eq 0) {
            Write-Host "No accepted domains found." -ForegroundColor Red
            exit
        }

        $foundError = $false
        [MailAddress[]]$validEmailAddresses = $null
        foreach ($emailAddress in $EmailAddresses) {
            $tempAddress = $null
            $tempAddress = Test-EmailAddress -EmailAddress $emailAddress -AcceptedDomains $acceptedDomains
            if ($null -eq $tempAddress) {
                $foundError = $true
            } else {
                $validEmailAddresses += $tempAddress
            }
        }
        if ($foundError) {
            exit
        }

        $malwareFilterRules = $null
        $antiPhishRules = $null
        $hostedContentFilterRules = $null
        $hostedOutboundSpamFilterRules = $null
        $eopStrictPresetRules = $null
        $eopStandardPresetRules = $null

        if ( -not $OnlyMDOPolicies) {
            $malwareFilterRules = Get-MalwareFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $antiPhishRules = Get-AntiPhishRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedContentFilterRules = Get-HostedContentFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedOutboundSpamFilterRules = Get-HostedOutboundSpamFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $eopStrictPresetRules = Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
            $eopStandardPresetRules = Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
        }

        $safeAttachmentRules = $null
        $safeLinksRules = $null
        $mdoStrictPresetRules = $null
        $mdoStandardPresetRules = $null

        if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
            # Get the custom and preset rules for Safe Attachments/Links
            $safeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
            $safeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
            $mdoStrictPresetRules = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
            $mdoStandardPresetRules = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Where-Object { $_.State -ne 'Disabled' }
        }

        foreach ($email in $validEmailAddresses) {
            $emailAddress = $email.ToString()
            # Initialize a variable to capture all policy details
            $allPolicyDetails = ""
            Write-Host "`n`nPolicies applied to $emailAddress..."

            if ( -not $OnlyMDOPolicies) {
                # Check the Strict EOP rules first as they have higher precedence
                $matchedRule = $null
                if ($eopStrictPresetRules) {
                    $matchedRule = Test-Rules -Rules $eopStrictPresetRules -email $emailAddress
                }
                if ($eopStrictPresetRules -contains $matchedRule) {
                    $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}`n`tThe policy actions are not configurable." -f $matchedRule.Name, $matchedRule.Priority
                    Write-Host $allPolicyDetails -ForegroundColor Green
                    $outboundSpamMatchedRule = $null
                    if ($hostedOutboundSpamFilterRules) {
                        $outboundSpamMatchedRule = Test-RulesAlternative -Rules $hostedOutboundSpamFilterRules -email $emailAddress
                        $allPolicyDetails = Get-Policy $outboundSpamMatchedRule "Outbound Spam"
                        Write-Host $allPolicyDetails -ForegroundColor Yellow
                    }
                } else {
                    # Check the Standard EOP rules secondly
                    $matchedRule = $null
                    if ($eopStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $eopStandardPresetRules -email $emailAddress
                    }
                    if ($eopStandardPresetRules -contains $matchedRule) {
                        $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}`n`tThe policy actions are not configurable." -f $matchedRule.Name, $matchedRule.Priority
                        Write-Host $allPolicyDetails -ForegroundColor Green
                        $outboundSpamMatchedRule = $null
                        if ($hostedOutboundSpamFilterRules) {
                            $outboundSpamMatchedRule = Test-RulesAlternative -Rules $hostedOutboundSpamFilterRules -Email $emailAddress
                            $allPolicyDetails = Get-Policy $outboundSpamMatchedRule "Outbound Spam"
                            Write-Host $allPolicyDetails -ForegroundColor Yellow
                        }
                    } else {
                        # If no match in EOPProtectionPolicyRules, check MalwareFilterRules, AntiPhishRules, outboundSpam, and HostedContentFilterRules
                        $allPolicyDetails = " "
                        $malwareMatchedRule = $null
                        if ($malwareFilterRules) {
                            $malwareMatchedRule = Test-Rules -Rules $malwareFilterRules -Email $emailAddress
                            Write-Host (Get-Policy $malwareMatchedRule "Malware") -ForegroundColor Yellow
                            if ($malwareMatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy (Get-MalwareFilterPolicy $malwareMatchedRule.Identity)
                            }
                        }
                        $antiPhishMatchedRule = $null
                        if ($antiPhishRules) {
                            $antiPhishMatchedRule = Test-Rules -Rules $antiPhishRules -Email $emailAddress
                            Write-Host (Get-Policy $antiPhishMatchedRule "Anti-phish") -ForegroundColor Yellow
                            if ($antiPhishMatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy (Get-AntiPhishPolicy $antiPhishMatchedRule.Identity)
                            }
                        }
                        $spamMatchedRule = $null
                        if ($hostedContentFilterRules) {
                            $spamMatchedRule = Test-Rules -Rules $hostedContentFilterRules -Email $emailAddress
                            Write-Host (Get-Policy $spamMatchedRule "Anti-spam") -ForegroundColor Yellow
                            if ($spamMatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy (Get-HostedContentFilterPolicy $spamMatchedRule.Identity)
                            }
                        }
                        $outboundSpamMatchedRule = $null
                        if ($hostedOutboundSpamFilterRules) {
                            $outboundSpamMatchedRule = Test-RulesAlternative -Rules $hostedOutboundSpamFilterRules -Email $emailAddress
                            Write-Host (Get-Policy $outboundSpamMatchedRule "Outbound Spam") -ForegroundColor Yellow
                            if ($outboundSpamMatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy (Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.Identity)
                            }
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
                if ($mdoStrictPresetRules) {
                    $matchedRule = Test-Rules -Rules $mdoStrictPresetRules -Email $emailAddress
                }
                if ($mdoStrictPresetRules -contains $matchedRule) {
                    Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                } else {
                    # Check the Standard MDO rules secondly
                    $matchedRule = $null
                    if ($mdoStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $mdoStandardPresetRules -Email $emailAddress
                    }
                    if ($mdoStandardPresetRules -contains $matchedRule) {
                        Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                    } else {
                        # No match in preset ATPProtectionPolicyRules, check custom SA/SL rules
                        $SAmatchedRule = $null
                        if ($safeAttachmentRules) {
                            $SAmatchedRule = Test-Rules -Rules $safeAttachmentRules -Email $emailAddress
                        }
                        $SLmatchedRule = $null
                        if ($safeLinksRules) {
                            $SLmatchedRule = Test-Rules -Rules $safeLinksRules -Email $emailAddress
                        }
                        if ($null -eq $SAmatchedRule) {
                            # Get the Built-in Protection Rule
                            $builtInProtectionRule = Get-ATPBuiltInProtectionRule
                            # Initialize a variable to track if the user is a member of any excluded group
                            $isInExcludedGroup = $false
                            # Check if the user is a member of any group in ExceptIfSentToMemberOf
                            foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
                                $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $emailAddress -GroupObjectId $groupObjectId)) {
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
                            Write-Host "`nSafe Attachments:`n`tName: $($SAmatchedRule.Name)`n`tPriority: $($SAmatchedRule.Priority)"  -ForegroundColor Yellow
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
                                $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $emailAddress -GroupObjectId $groupObjectId)) {
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
                            Write-Host "`nSafe Links:`n`tName: $($SLmatchedRule.Name)`n`tPriority: $($SLmatchedRule.Priority)" -ForegroundColor Yellow
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
