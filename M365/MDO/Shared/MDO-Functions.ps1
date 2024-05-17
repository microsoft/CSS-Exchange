# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        Write-Host "The EmailAddress of group $groupEmail vas not found" -ForegroundColor Red
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
        $rules,
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

        if (($email -in $rule.SentTo -or !$rule.SentTo) -and
            ($DomainIncluded -or !$rule.RecipientDomainIs) -and
            ($isInGroup -or !$rule.SentToMemberOf)) {
            if (($email -notin $rule.ExceptIfSentTo -or !$rule.ExceptIfSentTo) -and
                (!$DomainExcluded -or !$rule.ExceptIfRecipientDomainIs) -and
                (!$isInExceptGroup -or !$rule.ExceptIfSentToMemberOf)) {
                return $rule
            }
        }
    }
    return $null
}

function Test-RulesAlternative {
    param(
        $rules,
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

        if (($email -in $rule.From -or !$rule.From) -and
        ($DomainIncluded -or !$rule.SenderDomainIs) -and
        ($isInGroup -or !$rule.FromMemberOf)) {
            if (($email -notin $rule.ExceptIfFrom -or !$rule.ExceptIfFrom) -and
            (!$DomainExcluded -or !$rule.ExceptIfSenderDomainIs) -and
            (!$isInExceptGroup -or !$rule.ExceptIfFromMemberOf)) {
                return $rule
            }
        }
    }
    return $null
}

function Get-Policy {
    param(
        $rule = $null,
        $policyType = $null
    )

    if ($null -eq $rule) {
        if ($policyType -eq "Anti-phish") {
            $policyDetails = "`n$policyType - User/Domain Impersonation, Mailbox/Spoof Intelligence, and Honor DMARC: `n  The Default policy."
        } elseif ($policyType -eq "Anti-spam") {
            $policyDetails = "`n$policyType - plus phish detection actions: `n  The Default policy."
        } else {
            $policyDetails = "`n$policyType : `n  The Default policy."
        }
    } else {
        if ($policyType -eq "Anti-phish") {
            $policyDetails = "`n$policyType - User/Domain Impersonation, Mailbox/Spoof Intelligence, and Honor DMARC: `n  Name: {0}  `n  Priority: {1}" -f $rule.Name, $rule.Priority
        } elseif ($policyType -eq "Anti-spam") {
            $policyDetails = "`n$policyType - plus phish detection actions: `n  Name: {0}`n  Priority: {1}" -f $rule.Name, $rule.Priority
        } else {
            $policyDetails = "`n$policyType : `n  Name: {0}`n  Priority: {1}" -f $rule.Name, $rule.Priority
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
