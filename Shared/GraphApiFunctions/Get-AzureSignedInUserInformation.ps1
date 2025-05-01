# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Queries the properties and relationship of the signed-in user
    https://learn.microsoft.com/graph/api/user-get
#>
function Get-AzureSignedInUserInformation {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Getting information for the signed-in user via Graph Api: $GraphApiUrl"

    # Groups with permission to grant admin consent
    # Build-in roles: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
    # Admin consent overview: https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview
    $groupsEligibleToGrantAdminConsent = @(
        "62e90394-69f5-4237-9190-012177145e10",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    )

    $memberOfListObject = New-Object System.Collections.Generic.List[object]

    $getAzureSignedInUserBasicParams = @{
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    # Gets the properties and relationship of the signed-in user
    $getAzureSignedInUserResponse = Invoke-GraphApiRequest @getAzureSignedInUserBasicParams -Query "me"

    if ($getAzureSignedInUserResponse.Successful -eq $false) {
        Write-Verbose "Unable to query signed-in user information - please try again"
        return
    }

    # Gets the group membership of the signed-in user
    $getAzureSignedInUserMemberOfResponse = Invoke-GraphApiRequest @getAzureSignedInUserBasicParams -Query "me/memberOf"

    if ($getAzureSignedInUserMemberOfResponse.Successful -eq $false) {
        Write-Verbose "Unable to query signed-in user memberOf information - please try again"
        return
    }

    foreach ($group in $getAzureSignedInUserMemberOfResponse.Content.value) {
        Write-Verbose "Adding group: '$($group.displayName)' to list"
        $memberOfListObject.Add($group)
    }

    return [PSCustomObject]@{
        UserInformation             = $getAzureSignedInUserResponse.Content
        MemberOfInformation         = $memberOfListObject
        EligibleToGrantAdminConsent = ($groupsEligibleToGrantAdminConsent | Where-Object { $_ -in $memberOfListObject.roleTemplateId }).Count -ge 1
    }
}
