# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-GroupObjectId {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$groupEmail
    )

    try {
        $tempAddress = $null
        $tempAddress = [MailAddress]$groupEmail
        # Get the group
        $group = Get-AzureADGroup -SearchString $tempAddress.User

        # Return the Object ID of the group
        return $group.ObjectId
    } catch {
        Write-Host "The EmailAddress of group $groupEmail cannot be validated. Please provide a valid email address." -ForegroundColor Red
        return $null
    }
}

function Test-EmailAddress {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EmailAddress
    )

    try {
        $tempAddress = $null
        $tempAddress = [MailAddress]$EmailAddress
        $recipient = $null
        $recipient = Get-Recipient $tempAddress.ToString() -ErrorAction SilentlyContinue
        if ($null -eq $recipient) {
            Write-Host "$EmailAddress is not a recipient in this tenant" -ForegroundColor Red
            return $null
        } else {
            $AcceptedDomains = $null
            $AcceptedDomains = Get-AcceptedDomain
            if ($AcceptedDomains.count -gt 0) {
                $Domain = $tempAddress.Host
                if ($AcceptedDomains.DomainName -contains $Domain) {
                    return $tempAddress
                } else {
                    Write-Host "The domain $Domain is not an accepted domain in your organization. Please provide a valid email address." -ForegroundColor Red
                    return $null
                }
            } else {
                Write-Host "The accepted domains is empty" -ForegroundColor Red
                return $null
            }
        }
    } catch {
        Write-Host "The EmailAddress $EmailAddress cannot be validated. Please provide a valid email address." -ForegroundColor Red
        return $null
    }
}

# Function to check if an email is in a group
function Test-IsInGroup {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$email,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$groupObjectId
    )

    # Get the group members
    $groupMembers = $null
    $groupMembers = Get-AzureADGroupMember -ObjectId $groupObjectId

    # Check if the email address is in the group
    if ($null -ne $groupMembers) {
        foreach ($member in $groupMembers) {
            if ($member.Mail -eq $email)
            { return $true }
        }
    } else {
        Write-Host "The group with Object ID $groupObjectId does not have any members." -ForegroundColor Red
    }
    return $false
}

# Function to check rules
function Test-Rules {
    param(
        #[Parameter(Mandatory = $true)]
        #[ValidateNotNullOrEmpty()]
        [string]$rules,

        #[Parameter(Mandatory = $true)]
        #[ValidateNotNullOrEmpty()]
        [MailAddress]$email
    )
    foreach ($rule in $rules) {
        $isInGroup = $false
        if ($rule.SentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.SentToMemberOf
            if ([string]::IsNullOrEmpty($groupObjectId)) {
                Write-Host "The group in $($rule.Name) with email address $($rule.SentToMemberOf) does not exist." -ForegroundColor Yellow
            } else {
                $isInGroup = Test-IsInGroup $email $groupObjectId
            }
        }

        $isInExceptGroup = $false
        if ($rule.ExceptIfSentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.ExceptIfSentToMemberOf
            if ([string]::IsNullOrEmpty($groupObjectId)) {
                Write-Host "The group in $($rule.Name) with email address $($rule.ExceptIfSentToMemberOf) does not exist." -ForegroundColor Yellow
            } else {
                $isInExceptGroup = Test-IsInGroup $email $groupObjectId
            }
        }

        if (($email -in $rule.SentTo -or !$rule.SentTo) -and
            ($email.Host -in $rule.RecipientDomainIs -or !$rule.RecipientDomainIs) -and
            ($isInGroup -or !$rule.SentToMemberOf)) {
            if (($email -notin $rule.ExceptIfSentTo -or !$rule.ExceptIfSentTo) -and
                ($email.Host -notin $rule.ExceptIfRecipientDomainIs -or !$rule.ExceptIfRecipientDomainIs) -and
                (!$isInExceptGroup -or !$rule.ExceptIfSentToMemberOf)) {
                return $rule
            }
        }
    }
    return $null
}

function Test-RulesAlternative {
    param(
        #[Parameter(Mandatory = $true)]
        #[ValidateNotNullOrEmpty()]
        [string]$rules,

        #[Parameter(Mandatory = $true)]
        #[ValidateNotNullOrEmpty()]
        [string]$email
    )
    foreach ($rule in $rules) {
        $isInGroup = $false
        if ($rule.FromMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.FromMemberOf
            if ([string]::IsNullOrEmpty($groupObjectId)) {
                Write-Host "The group in $($rule.Name)  with email $($rule.FromMemberOf) does not exist." -ForegroundColor Yellow
            } else {
                $isInGroup = Test-IsInGroup -email $email -groupObjectId $groupObjectId
            }
        }

        $isInExceptGroup = $false
        if ($rule.ExceptIfFrom) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.ExceptIfFrom
            if ([string]::IsNullOrEmpty($groupObjectId)) {
                Write-Host "The group in $($rule.Name) with email $($rule.ExceptIfFrom) does not exist." -ForegroundColor Yellow
            } else {
                $isInExceptGroup = Test-IsInGroup -email $email -groupObjectId $groupObjectId
            }
        }

        if (($email -in $rule.From -or !$rule.From) -and
        ($email.Host -in $rule.SenderDomainIs -or !$rule.SenderDomainIs) -and
        ($isInGroup -or !$rule.FromMemberOf)) {
            if (($email -notin $rule.ExceptIfFrom -or !$rule.ExceptIfFrom) -and
            ($email.Host -notin $rule.ExceptIfSenderDomainIs -or !$rule.ExceptIfSenderDomainIs) -and
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
