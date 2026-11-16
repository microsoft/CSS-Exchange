# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1

# Collects the AD permissions of the provided Receive Connectors.
# A failure on one connector is logged and doesn't stop the collection of the others.
function Get-ReceiveConnectorPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $false)]
        [object[]]$ReceiveConnector
    )

    Write-Verbose "Function Enter: $($MyInvocation.MyCommand)"
    $connectorCount = 0
    $failedCount = 0

    foreach ($connector in $ReceiveConnector) {

        if ($null -eq $connector) {
            continue
        }

        $connectorCount++

        # Get-ADPermission returns the permissions of all objects when Identity is null or empty.
        if ([string]::IsNullOrEmpty($connector.DistinguishedName)) {
            Write-Verbose "Receive Connector '$($connector.Identity)' doesn't have a DistinguishedName. Unable to collect its AD permissions."
            $failedCount++
            continue
        }

        try {
            $permissions = Get-ADPermission -Identity $connector.DistinguishedName -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to collect the AD permissions for Receive Connector '$($connector.Identity)'. Inner Exception: $_"
            Invoke-CatchActions
            $failedCount++
            continue
        }

        # Only keep the ACE values as strings. The full objects from the Exchange remote session
        # are about 18 KB each when exported, and a connector has more than 100 ACEs.
        foreach ($permission in $permissions) {
            [PSCustomObject]@{
                Identity            = [string]$permission.Identity
                User                = [string]$permission.User
                Deny                = $permission.Deny
                IsInherited         = $permission.IsInherited
                InheritanceType     = [string]$permission.InheritanceType
                AccessRights        = [string[]]@(foreach ($value in $permission.AccessRights) { [string]$value })
                ExtendedRights      = [string[]]@(foreach ($value in $permission.ExtendedRights) { [string]$value })
                Properties          = [string[]]@(foreach ($value in $permission.Properties) { [string]$value })
                ChildObjectTypes    = [string[]]@(foreach ($value in $permission.ChildObjectTypes) { [string]$value })
                InheritedObjectType = [string]$permission.InheritedObjectType
            }
        }
    }

    if ($failedCount -gt 0) {
        Write-Host "Failed to collect the AD permissions for $failedCount of $connectorCount Receive Connectors on $ServerName." -ForegroundColor "Yellow"
    }

    Write-Verbose "Function Exit: $($MyInvocation.MyCommand)"
}
