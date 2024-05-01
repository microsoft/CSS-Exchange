# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
function Test-IsInGroup {
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
function Test-Rules($rules, $email, $domain) {
    foreach ($rule in $rules) {
        $isInGroup = $false
        if ($rule.SentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.SentToMemberOf
            if (![string]::IsNullOrEmpty($groupObjectId)) {
                $isInGroup = Test-IsInGroup $email $groupObjectId
            }
        }

        $isInExceptGroup = $false
        if ($rule.ExceptIfSentToMemberOf) {
            $groupObjectId = Get-GroupObjectId -groupEmail $rule.ExceptIfSentToMemberOf
            if (![string]::IsNullOrEmpty($groupObjectId)) {
                $isInExceptGroup = Test-IsInGroup $email $groupObjectId
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
