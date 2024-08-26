# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Users
#Requires -Modules Microsoft.Graph.Groups
#Requires -Modules ExchangeOnlineManagement -Version 3.0.0

<#
.SYNOPSIS
Evaluates user coverage and potential redundancies in Microsoft Defender for Office 365 and Exchange Online Protection threat policies, including anti-malware, anti-phishing, and anti-spam policies, as well as Safe Attachments and Safe Links policies if licensed.

.DESCRIPTION
This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant. In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant or confusing and lead to missed coverage of users or coverage by an unexpected threat policy. It also includes an option to show all the actions and settings of the policies that apply to a user.

.PARAMETER CsvFilePath
    Allows you to specify a CSV file with a list of email addresses to check.
.PARAMETER EmailAddress
    Allows you to specify email address or multiple addresses separated by commas.
.PARAMETER IncludeMDOPolicies
    Checks both EOP and MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddress parameter.
.PARAMETER OnlyMDOPolicies
    Checks only MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddress parameter.
.PARAMETER ShowDetailedPolicies
    In addition to the policy applied, show any policy details that are set to True, On, or not blank.
.PARAMETER SkipConnectionCheck
    Skips connection check for Graph and Exchange Online.
.PARAMETER SkipVersionCheck
    Skips the version check of the script.
.PARAMETER ScriptUpdateOnly
    Just updates script version to latest one.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1
	To check all threat policies for potentially confusing user inclusion and/or exclusion conditions and print them out for review.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv]
	To provide a CSV input file with email addresses and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddress user1@contoso.com,user2@fabrikam.com
	To provide multiple email addresses by command line and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies
	To provide a CSV input file with email addresses and see both EOP and MDO policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddress user1@contoso.com -OnlyMDOPolicies
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
    [string[]]$EmailAddress,

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

    [Parameter(Mandatory = $false)]
    [switch]$SkipConnectionCheck,

    [Parameter(Mandatory = $false)]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

begin {

    . $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
    . $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Warning.ps1
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

        $stGroupEmail = $GroupEmail.ToString()
        # Check the cache first
        Write-Verbose "Looking Group $stGroupEmail in cache"
        if ($groupCache.ContainsKey($stGroupEmail)) {
            Write-Verbose "Group $stGroupEmail found in cache"
            return $groupCache[$stGroupEmail]
        }

        # Get the group
        $group = $null
        Write-Verbose "Getting $stGroupEmail"
        try {
            $group = Get-MgGroup -Filter "mail eq '$stGroupEmail'" -ErrorAction Stop
        } catch {
            Write-Host "Error getting group $stGroupEmail`:`n$_" -ForegroundColor Red
            return $null
        }

        if ($group -and $group.id) {
            if ($group.Id.GetType() -eq [string]) {
                # Cache the result
                Write-Verbose "Added to cache Group $stGroupEmail with Id $($group.Id)"
                $groupCache[$stGroupEmail] = $group.Id

                # Return the Object ID of the group
                return $group.Id
            } else {
                Write-Host "Wrong type for $($group.ToString()): $($group.Id.GetType().Name)" -ForegroundColor Red
                return $null
            }
        } else {
            Write-Host "The EmailAddress of group $stGroupEmail was not found." -ForegroundColor Red
            return $null
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
        $stEmail = $Email.ToString()
        $cacheKey = "$stEmail|$GroupObjectId"
        Write-Verbose "Looking for $stEmail|$GroupObjectId in cache"
        if ($memberCache.ContainsKey($cacheKey)) {
            Write-Verbose "Found $stEmail|$GroupObjectId in cache"
            return $memberCache[$cacheKey]
        }

        # Get the group members
        $groupMembers = $null
        Write-Verbose "Getting $GroupObjectId"
        try {
            $groupMembers = Get-MgGroupMember -GroupId $GroupObjectId -ErrorAction Stop
        } catch {
            Write-Host "Error getting group members for $GroupObjectId`:`n$_" -ForegroundColor Red
            return $null
        }

        # Check if the email address is in the group
        if ($null -ne $groupMembers) {
            foreach ($member in $groupMembers) {
                # Check if the member is a user
                if ($member['@odata.type'] -eq '#microsoft.graph.user') {
                    if ($member.Id) {
                        # Get the user object by Id
                        Write-Verbose "Getting user with Id $($member.Id)"
                        try {
                            $user = Get-MgUser -UserId $member.Id -ErrorAction Stop
                        } catch {
                            Write-Host "Error getting user with Id $($member.Id):`n$_" -ForegroundColor Red
                            return $null
                        }
                        # Compare the user's email address with the $email parameter
                        if ($user.Mail -eq $Email.ToString()) {
                            # Cache the result
                            $memberCache[$cacheKey] = $true
                            return $true
                        }
                    } else {
                        Write-Host "The user with Id $($member.Id) does not have an email address." -ForegroundColor Red
                    }
                }
                # Check if the member is a group
                elseif ($member['@odata.type'] -eq '#microsoft.graph.group') {
                    Write-Verbose "Nested group $($member.Id)"
                    # Recursive call to check nested groups
                    $isInNestedGroup = Test-IsInGroup -Email $Email -GroupObjectId $member.Id
                    if ($isInNestedGroup) {
                        # Cache the result
                        Write-Verbose "Cache group $cacheKey"
                        $memberCache[$cacheKey] = $true
                        return $true
                    }
                }
            }
        } else {
            Write-Verbose "The group with Object ID $GroupObjectId does not have any members."
        }

        # Cache the result
        $memberCache[$cacheKey] = $false
        return $false
    }

    function Test-EmailAddress {
        [OutputType([MailAddress])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$EmailAddress,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$AcceptedDomains
        )

        try {
            $tempAddress = $null
            Write-Verbose "Casting $EmailAddress"
            $tempAddress = [MailAddress]$EmailAddress
        } catch {
            Write-Host "The EmailAddress $EmailAddress cannot be validated. Please provide a valid email address." -ForegroundColor Red
            Write-Host "Error details:`n$_" -ForegroundColor Red
            return $null
        }

        $domain = $tempAddress.Host
        Write-Verbose "Checking domain $domain"
        if ($AcceptedDomains -contains $domain) {
            Write-Verbose "Verified domain $domain for $tempAddress"
            $recipient = $null
            Write-Verbose "Getting $EmailAddress"
            try {
                $recipient = Get-EXORecipient $EmailAddress -ErrorAction Stop
                if ($null -eq $recipient) {
                    Write-Host "$EmailAddress is not a recipient in this tenant." -ForegroundColor Red
                } else {
                    return $tempAddress
                }
            } catch {
                Write-Host "Error getting recipient $EmailAddress`:`n$_" -ForegroundColor Red
            }
        } else {
            Write-Host "The domain $domain is not an accepted domain in your organization. Please provide a valid email address: $tempAddress " -ForegroundColor Red
        }
        return $null
    }

    # Function to check rules
    function Test-Rules {
        param(
            [Parameter(Mandatory = $true)]
            $Rules,
            [Parameter(Mandatory = $true)]
            [MailAddress]$Email,
            [Parameter(Mandatory = $false)]
            [switch]$Outbound
        )

        foreach ($rule in $Rules) {
            $senderOrReceiver = $exceptSenderOrReceiver = $memberOf = $exceptMemberOf = $domainsIs = $exceptIfDomainsIs = $null
            $emailInRule = $emailExceptionInRule = $groupInRule = $groupExceptionInRule = $domainInRule = $domainExceptionInRule = $false

            if ($Outbound) {
                Write-Verbose "Checking outbound rule $($rule.Name)"
                $requestedProperties = 'From', 'ExceptIfFrom', 'FromMemberOf', 'ExceptIfFromMemberOf', 'SenderDomainIs', 'ExceptIfSenderDomainIs'
                $senderOrReceiver = $rule.From
                $exceptSenderOrReceiver = $rule.ExceptIfFrom
                $memberOf = $rule.FromMemberOf
                $exceptMemberOf = $rule.ExceptIfFromMemberOf
                $domainsIs = $rule.SenderDomainIs
                $exceptIfDomainsIs = $rule.ExceptIfSenderDomainIs
            } else {
                Write-Verbose "Checking inbound rule $($rule.Name)"
                $requestedProperties = 'SentTo', 'ExceptIfSentTo', 'SentToMemberOf', 'ExceptIfSentToMemberOf', 'RecipientDomainIs', 'ExceptIfRecipientDomainIs'
                $senderOrReceiver = $rule.SentTo
                $exceptSenderOrReceiver = $rule.ExceptIfSentTo
                $memberOf = $rule.SentToMemberOf
                $exceptMemberOf = $rule.ExceptIfSentToMemberOf
                $domainsIs = $rule.RecipientDomainIs
                $exceptIfDomainsIs = $rule.ExceptIfRecipientDomainIs
            }

            $Policy.PSObject.Properties | ForEach-Object {
                if ($requestedProperties -contains $_.Name) {
                    Write-Host "`t`t$($_.Name): $($_.Value)"
                }
            }
            Write-Verbose " "

            if ($senderOrReceiver -and $Email -in $senderOrReceiver) {
                Write-Verbose "emailInRule"
                $emailInRule = $true
            }
            if ($exceptSenderOrReceiver -and $Email -in $exceptSenderOrReceiver) {
                Write-Verbose "emailExceptionInRule"
                $emailExceptionInRule = $true
            }

            if ($memberOf) {
                foreach ($groupEmail in $memberOf) {
                    Write-Verbose "Checking member in $groupEmail"
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $groupInRule = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($groupInRule) {
                            Write-Verbose "groupInRule $($Email.ToString()) - $($groupObjectId)"
                            break
                        }
                    }
                }
            }

            if ($exceptMemberOf) {
                foreach ($groupEmail in $exceptMemberOf) {
                    Write-Verbose "Checking member in exception $groupEmail"
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $groupExceptionInRule = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($groupExceptionInRule) {
                            Write-Verbose "groupExceptionInRule $($Email.ToString()) - $($groupObjectId)"
                            break
                        }
                    }
                }
            }

            $temp = $Email.Host
            while ($temp.IndexOf(".") -gt 0) {
                if ($temp -in $domainsIs) {
                    Write-Verbose "domainInRule: $temp"
                    $domainInRule = $true
                }
                if ($temp -in $exceptIfDomainsIs) {
                    Write-Verbose "domainExceptionInRule: $temp"
                    $domainExceptionInRule = $true
                }
                $temp = $temp.Substring($temp.IndexOf(".") + 1)
            }

            # Check for explicit inclusion in any user, group, or domain that are not empty, and account for 3 empty inclusions
            # Also check for any exclusions as user, group, or domain. Nulls don't need to be accounted for and this is an OR condition for exclusions
            if (((($emailInRule -or (-not $senderOrReceiver)) -and ($domainInRule -or (-not $domainsIs)) -and ($groupInRule -or (-not $memberOf))) -and
                 ($emailInRule -or $domainInRule -or $groupInRule)) -and
                ((-not $emailExceptionInRule) -and (-not $groupExceptionInRule) -and (-not $domainExceptionInRule))) {
                Write-Verbose "Return Rule $($rule.Name)"
                Write-Verbose "emailInRule: $emailInRule domainInRule: $domainInRule groupInRule: $groupInRule  "
                Write-Verbose "emailExceptionInRule: $emailExceptionInRule groupExceptionInRule: $groupExceptionInRule domainExceptionInRule: $domainExceptionInRule  "
                return $rule
            }

            # Check for implicit inclusion (no mailboxes included at all), which is possible for Presets and SA/SL. They are included if not explicitly excluded. Only inbound
            if ((-not $Outbound) -and
                (((-not $senderOrReceiver) -and (-not $domainsIs) -and (-not $memberOf)) -and
                 ((-not $emailExceptionInRule) -and (-not $groupExceptionInRule) -and (-not $domainExceptionInRule)))) {
                Write-Verbose "Return Rule $($rule.Name)"
                Write-Verbose "senderOrReceiver: $senderOrReceiver domainsIs: $domainsIs memberOf: $memberOf  "
                Write-Verbose "emailExceptionInRule: $emailExceptionInRule groupExceptionInRule: $groupExceptionInRule domainExceptionInRule: $domainExceptionInRule  "
                return $rule
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
        $excludedProperties = 'Identity', 'Id', 'Name', 'ExchangeVersion', 'DistinguishedName', 'ObjectCategory', 'ObjectClass', 'WhenChanged', 'WhenCreated',
        'WhenChangedUTC', 'WhenCreatedUTC', 'ExchangeObjectId', 'OrganizationalUnitRoot', 'OrganizationId', 'OriginatingServer', 'ObjectState', 'Priority', 'ImmutableId',
        'Description', 'HostedContentFilterPolicy', 'AntiPhishPolicy', 'MalwareFilterPolicy', 'SafeAttachmentPolicy', 'SafeLinksPolicy', 'HostedOutboundSpamFilterPolicy'

        $Policy.PSObject.Properties | ForEach-Object {
            if ($null -ne $_.Value -and
                (($_.Value.GetType() -eq [Boolean] -and $_.Value -eq $true) -or
                    ($_.Value -ne '{}' -and $_.Value -ne 'Off' -and $_.Value -ne $true -and $_.Value -ne '' -and $excludedProperties -notcontains $_.Name))) {
                Write-Host "`t`t$($_.Name): $($_.Value)"
            } else {
                Write-Verbose "`t`tExcluded property:$($_.Name): $($_.Value)"
            }
        }
        Write-Host " "
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

    $LogFileName = "MDOThreatPolicyChecker"
    $StartDate = Get-Date
    $StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
    $Script:DebugLogger = Get-NewLoggerInstance -LogName "$LogFileName-Debug-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
    $Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteWarningAction ${Function:Write-HostLog}

    $BuildVersion = ""

    Write-Host ("MDOThreatPolicyChecker.ps1 script version $($BuildVersion)") -ForegroundColor Green

    if ($ScriptUpdateOnly) {
        switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false) {
            ($true) { Write-Host ("Script was successfully updated.") -ForegroundColor Green }
            ($false) { Write-Host ("No update of the script performed.") -ForegroundColor Yellow }
            default { Write-Host ("Unable to perform ScriptUpdateOnly operation.") -ForegroundColor Red }
        }
        return
    }

    if ((-not($SkipVersionCheck)) -and (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false)) {
        Write-Host ("Script was updated. Please re-run the command.") -ForegroundColor Yellow
        return
    }
}

process {
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

        if ($PSCmdlet.ParameterSetName -ne "AppliedTenant") {
            #Validate Graph is connected
            $graphConnection = $null
            Write-Host " "
            try {
                $graphConnection = Get-MgContext -ErrorAction Stop
            } catch {
                Write-Host "Error checking Graph connection:`n$_" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                exit
            }
            if ($null -eq $graphConnection) {
                Write-Host "Not connected to Graph" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                exit
            } elseif ($graphConnection.count -eq 1) {
                $expectedScopes = "Group.Read.All", 'User.Read.All'
                if (Test-GraphContext -Scopes $graphConnection.Scopes -ExpectedScopes $expectedScopes) {
                    Write-Host "Connected to Graph"
                    Write-Host "Session details"
                    Write-Host "TenantID: $(($graphConnection).TenantId)"
                    Write-Host "Account: $(($graphConnection).Account)"
                } else {
                    Write-Host "We cannot continue without Graph Powershell session without Expected Scopes." -ForegroundColor Red
                    Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                    Write-Host "You could use:" -ForegroundColor Yellow
                    Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
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
    }

    if ($PSCmdlet.ParameterSetName -eq "AppliedTenant") {
        # Define the cmdlets to retrieve policies from and their corresponding policy types
        $cmdlets = @{
            "Get-HostedContentFilterRule"                                                                        = "Anti-spam Policy"
            "Get-HostedOutboundSpamFilterRule"                                                                   = "Outbound Spam Policy"
            "Get-MalwareFilterRule"                                                                              = "Malware Policy"
            "Get-AntiPhishRule"                                                                                  = "Anti-phishing Policy"
            "Get-SafeLinksRule"                                                                                  = "Safe Links Policy"
            "Get-SafeAttachmentRule"                                                                             = "Safe Attachment Policy"
            "Get-ATPBuiltInProtectionRule"                                                                       = "Built-in protection preset security Policy"
            { Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } }   = "EOP"
            { Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } } = "EOP"
            { Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } }   = "MDO (Safe Links / Safe Attachments)"
            { Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } } = "MDO (Safe Links / Safe Attachments)"
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
                        $color = [console]::ForegroundColor
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
                    $EmailAddress = $csvFile | Select-Object -ExpandProperty Email
                } else {
                    Write-Host "CSV does not contain 'Email' header." -ForegroundColor Red
                    exit
                }
            } catch {
                Write-Host "Error importing CSV file:`n$_" -ForegroundColor Red
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

        $foundError = $false
        $validEmailAddress = New-Object System.Collections.Generic.List[MailAddress]
        foreach ($email in $EmailAddress) {
            $tempAddress = $null
            $tempAddress = Test-EmailAddress -EmailAddress $email -AcceptedDomains $acceptedDomainList
            if ($null -eq $tempAddress) {
                $foundError = $true
            } else {
                $validEmailAddress.Add($tempAddress)
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
            $eopStrictPresetRules = Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
            $eopStandardPresetRules = Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
        }

        $safeAttachmentRules = $null
        $safeLinksRules = $null
        $mdoStrictPresetRules = $null
        $mdoStandardPresetRules = $null

        if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
            # Get the custom and preset rules for Safe Attachments/Links
            $safeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
            $safeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
            $mdoStrictPresetRules = Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
            $mdoStandardPresetRules = Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
        }

        foreach ($email in $validEmailAddress) {
            $stEmailAddress = $email.ToString()
            # Initialize a variable to capture all policy details
            $allPolicyDetails = ""
            Write-Host "`n`nPolicies applied to $stEmailAddress..."

            if ( -not $OnlyMDOPolicies) {
                # Check the Strict EOP rules first as they have higher precedence
                $matchedRule = $null
                if ($eopStrictPresetRules) {
                    $matchedRule = Test-Rules -Rules $eopStrictPresetRules -email $stEmailAddress
                }
                if ($eopStrictPresetRules -contains $matchedRule) {
                    $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority
                    if ($ShowDetailedPolicies) {
                        $allPolicyDetails += "`n`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
                    }
                    Write-Host $allPolicyDetails -ForegroundColor Green
                    $outboundSpamMatchedRule = $null
                    if ($hostedOutboundSpamFilterRules) {
                        $outboundSpamMatchedRule = Test-Rules -Rules $hostedOutboundSpamFilterRules -email $stEmailAddress -Outbound
                        if ($null -eq $outboundSpamMatchedRule) {
                            Write-Host "`nOutbound Spam:`n`tDefault policy"  -ForegroundColor Yellow
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy "Default"
                        } else {
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.Name
                            Write-Host "`nOutbound Spam:`n`tName: $($outboundSpamMatchedRule.Name)`n`tPriority: $($outboundSpamMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($hostedOutboundSpamFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $hostedOutboundSpamFilterPolicy
                        }
                    }
                } else {
                    # Check the Standard EOP rules secondly
                    $matchedRule = $null
                    if ($eopStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $eopStandardPresetRules -email $stEmailAddress
                    }
                    if ($eopStandardPresetRules -contains $matchedRule) {
                        $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority
                        if ($ShowDetailedPolicies) {
                            $allPolicyDetails += "`n`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
                        }
                        Write-Host $allPolicyDetails -ForegroundColor Green
                        $outboundSpamMatchedRule = $allPolicyDetails = $null
                        if ($hostedOutboundSpamFilterRules) {
                            $outboundSpamMatchedRule = Test-Rules -Rules $hostedOutboundSpamFilterRules -Email $stEmailAddress -Outbound
                            if ($null -eq $outboundSpamMatchedRule) {
                                Write-Host "`nOutbound Spam:`n`tDefault policy"  -ForegroundColor Yellow
                                $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy "Default"
                            } else {
                                $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.Name
                                Write-Host "`nOutbound Spam:`n`tName: $($outboundSpamMatchedRule.Name)`n`tPriority: $($outboundSpamMatchedRule.Priority)"  -ForegroundColor Yellow
                            }
                            if ($hostedOutboundSpamFilterPolicy -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $hostedOutboundSpamFilterPolicy
                            }
                        }
                    } else {
                        # If no match in EOPProtectionPolicyRules, check MalwareFilterRules, AntiPhishRules, outboundSpam, and HostedContentFilterRules
                        $allPolicyDetails = " "
                        $malwareMatchedRule = $malwareFilterPolicy = $null
                        if ($malwareFilterRules) {
                            $malwareMatchedRule = Test-Rules -Rules $malwareFilterRules -Email $stEmailAddress
                        }
                        if ($null -eq $malwareMatchedRule) {
                            Write-Host "`nMalware:`n`tDefault policy"  -ForegroundColor Yellow
                            $malwareFilterPolicy = Get-MalwareFilterPolicy "Default"
                        } else {
                            $malwareFilterPolicy = Get-MalwareFilterPolicy $malwareMatchedRule.Name
                            Write-Host "`nMalware:`n`tName: $($malwareMatchedRule.Name)`n`tPriority: $($malwareMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($malwareFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $malwareFilterPolicy
                        }

                        $antiPhishMatchedRule = $antiPhishPolicy = $null
                        if ($antiPhishRules) {
                            $antiPhishMatchedRule = Test-Rules -Rules $antiPhishRules -Email $stEmailAddress
                        }
                        if ($null -eq $antiPhishMatchedRule) {
                            Write-Host "`nAnti-phish:`n`tDefault policy"  -ForegroundColor Yellow
                            $antiPhishPolicy = Get-AntiPhishPolicy "Office365 AntiPhish Default"
                        } else {
                            $antiPhishPolicy = Get-AntiPhishPolicy $antiPhishMatchedRule.Name
                            Write-Host "`nAnti-phish:`n`tName: $($antiPhishMatchedRule.Name)`n`tPriority: $($antiPhishMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($antiPhishPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $antiPhishPolicy
                        }

                        $spamMatchedRule = $hostedContentFilterPolicy = $null
                        if ($hostedContentFilterRules) {
                            $spamMatchedRule = Test-Rules -Rules $hostedContentFilterRules -Email $stEmailAddress
                        }
                        if ($null -eq $spamMatchedRule) {
                            Write-Host "`nAnti-spam:`n`tDefault policy"  -ForegroundColor Yellow
                            $hostedContentFilterPolicy = Get-HostedContentFilterPolicy "Default"
                        } else {
                            $hostedContentFilterPolicy = Get-HostedContentFilterPolicy $spamMatchedRule.Name
                            Write-Host "`nAnti-spam:`n`tName: $($spamMatchedRule.Name)`n`tPriority: $($spamMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($hostedContentFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $hostedContentFilterPolicy
                        }

                        $outboundSpamMatchedRule = $hostedOutboundSpamFilterPolicy = $null
                        if ($hostedOutboundSpamFilterRules) {
                            $outboundSpamMatchedRule = Test-Rules -Rules $hostedOutboundSpamFilterRules -email $stEmailAddress -Outbound
                        }
                        if ($null -eq $outboundSpamMatchedRule) {
                            Write-Host "`nOutbound Spam:`n`tDefault policy"  -ForegroundColor Yellow
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy "Default"
                        } else {
                            $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.Name
                            Write-Host "`nOutbound Spam:`n`tName: $($outboundSpamMatchedRule.Name)`n`tPriority: $($outboundSpamMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($hostedOutboundSpamFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $hostedOutboundSpamFilterPolicy
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
                    $matchedRule = Test-Rules -Rules $mdoStrictPresetRules -Email $stEmailAddress
                }
                if ($mdoStrictPresetRules -contains $matchedRule) {
                    Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                    if ($ShowDetailedPolicies) {
                        Write-Host ("`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#microsoft-defender-for-office-365-security") -ForegroundColor Green
                    }
                } else {
                    # Check the Standard MDO rules secondly
                    $matchedRule = $null
                    if ($mdoStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $mdoStandardPresetRules -Email $stEmailAddress
                    }
                    if ($mdoStandardPresetRules -contains $matchedRule) {
                        Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                        if ($ShowDetailedPolicies) {
                            Write-Host ("`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#microsoft-defender-for-office-365-security") -ForegroundColor Green
                        }
                    } else {
                        # No match in preset ATPProtectionPolicyRules, check custom SA/SL rules
                        $SAmatchedRule = $null
                        if ($safeAttachmentRules) {
                            $SAmatchedRule = Test-Rules -Rules $safeAttachmentRules -Email $stEmailAddress
                        }
                        $SLmatchedRule = $null
                        if ($safeLinksRules) {
                            $SLmatchedRule = Test-Rules -Rules $safeLinksRules -Email $stEmailAddress
                        }
                        if ($null -eq $SAmatchedRule) {
                            # Get the Built-in Protection Rule
                            $builtInProtectionRule = Get-ATPBuiltInProtectionRule
                            # Initialize a variable to track if the user is a member of any excluded group
                            $isInExcludedGroup = $false
                            # Check if the user is a member of any group in ExceptIfSentToMemberOf
                            foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
                                $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $stEmailAddress -GroupObjectId $groupObjectId)) {
                                    $isInExcludedGroup = $true
                                    break
                                }
                            }
                            # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
                            if ($stEmailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
                                $isInExcludedGroup -or
                                $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
                                Write-Host "`nSafe Attachments:`n`tThe user is excluded from all Safe Attachment protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Attachments:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $safeAttachmentPolicy = Get-SafeAttachmentPolicy -Identity $SAmatchedRule.Name
                            Write-Host "`nSafe Attachments:`n`tName: $($SAmatchedRule.Name)`n`tPriority: $($SAmatchedRule.Priority)"  -ForegroundColor Yellow
                            if ($SAmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $safeAttachmentPolicy
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
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $stEmailAddress -GroupObjectId $groupObjectId)) {
                                    $isInExcludedGroup = $true
                                    break
                                }
                            }

                            # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
                            if ($stEmailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
                                $isInExcludedGroup -or
                                $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
                                Write-Host "`nSafe Links:`n`tThe user is excluded from all Safe Links protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Links:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $safeLinkPolicy = Get-SafeLinksPolicy -Identity $SLmatchedRule.Name
                            Write-Host "`nSafe Links:`n`tName: $($SLmatchedRule.Name)`n`tPriority: $($SLmatchedRule.Priority)" -ForegroundColor Yellow
                            if ($SLmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $safeLinkPolicy
                            }
                        }
                    }
                }
            }
        }
    }
    Write-Host " "
}
