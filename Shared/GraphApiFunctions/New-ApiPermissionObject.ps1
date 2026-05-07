# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Creates an API permission object for Azure application validation.

.DESCRIPTION
    Factory function that generates a standardized API permission object structure
    used for validating Azure application permissions. The object contains the API type
    (Graph or EWS), the well-known first-party application ID for that API, and a
    hashtable of permissions with their types.

    Supports two input syntaxes:
    - Simple: An array of permission names with a single permission type (when all permissions share the same type)
    - Hashtable: A hashtable for mixed permission types

    The function automatically maps the ApiType to the correct Microsoft first-party AppId:
    - Graph: 00000003-0000-0000-c000-000000000000 (Microsoft Graph)
    - EWS: 00000002-0000-0ff1-ce00-000000000000 (Office 365 Exchange Online)

.PARAMETER ApiType
    The type of API for the permissions. Valid values are "Graph" or "EWS".

.PARAMETER Permissions
    An array of permission names. Use with -PermissionType when all permissions share the same type.

.PARAMETER PermissionType
    The type for all permissions specified in -Permissions. Valid values are "Application" or "Delegated".

.PARAMETER PermissionsHashtable
    A hashtable containing permission names as keys and permission types (or arrays of types) as values.
    Use this when permissions have different types or when a permission needs both Application and Delegated.

.EXAMPLE
    $graphPermissions = New-ApiPermissionObject -ApiType "Graph" -Permissions "ProfilePhoto.Read.All", "Calendars.ReadBasic.All", "Mail.Read" -PermissionType "Application"

    Creates a Graph API permission object with three Application permissions using the simple syntax.

.EXAMPLE
    $ewsPermissions = New-ApiPermissionObject -ApiType "EWS" -Permissions "full_access_as_app" -PermissionType "Application"

    Creates an EWS API permission object with a single Application permission.

.EXAMPLE
    $mixedPermissions = New-ApiPermissionObject -ApiType "Graph" -PermissionsHashtable @{
        "Mail.Read"  = @("Application", "Delegated")
        "User.Read"  = "Delegated"
    }

    Creates a Graph API permission object with mixed permission types using the hashtable syntax.
    Mail.Read is requested as both Application and Delegated, while User.Read is Delegated only.

.OUTPUTS
    PSCustomObject with the following properties:
    - ApiType: The API type (Graph or EWS)
    - FirstPartyAppId: The well-known AppId of the Microsoft first-party application for this API
    - Permissions: Hashtable of permission names (keys) and arrays of permission types (values)
#>
function New-ApiPermissionObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Factory function that only creates and returns an object without modifying system state')]
    [CmdletBinding(DefaultParameterSetName = "SimplePermissions")]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Graph", "EWS")]
        [string]$ApiType,

        [Parameter(Mandatory = $true, ParameterSetName = "SimplePermissions")]
        [ValidateNotNullOrEmpty()]
        [string[]]$Permissions,

        [Parameter(Mandatory = $true, ParameterSetName = "SimplePermissions")]
        [ValidateSet("Application", "Delegated")]
        [string]$PermissionType,

        [Parameter(Mandatory = $true, ParameterSetName = "HashtablePermissions")]
        [ValidateNotNullOrEmpty()]
        [hashtable]$PermissionsHashtable
    )

    $validPermissionTypes = @("Application", "Delegated")
    $outputPermissions = @{}

    # Map ApiType to the well-known Microsoft first-party application IDs
    $firstPartyAppIdMap = @{
        "Graph" = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
        "EWS"   = "00000002-0000-0ff1-ce00-000000000000"  # Office 365 Exchange Online
    }

    $firstPartyAppId = $firstPartyAppIdMap[$ApiType]

    if ($PSCmdlet.ParameterSetName -eq "SimplePermissions") {
        foreach ($permission in $Permissions) {
            $outputPermissions[$permission] = @($PermissionType)
        }
    } else {
        foreach ($permissionName in $PermissionsHashtable.Keys) {
            $permTypes = @($PermissionsHashtable[$permissionName])

            foreach ($permType in $permTypes) {
                if ($permType -notin $validPermissionTypes) {
                    throw "Invalid permission type '$permType' for permission '$permissionName'. Valid values are: $($validPermissionTypes -join ', ')"
                }
            }

            $outputPermissions[$permissionName] = $permTypes
        }
    }

    return [PSCustomObject]@{
        ApiType         = $ApiType
        FirstPartyAppId = $firstPartyAppId
        Permissions     = $outputPermissions
    }
}
