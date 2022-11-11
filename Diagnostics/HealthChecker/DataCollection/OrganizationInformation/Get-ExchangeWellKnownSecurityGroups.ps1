# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeOtherWellKnownObjects.ps1
function Get-ExchangeWellKnownSecurityGroups {
    [CmdletBinding()]
    param()
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeGroups = New-Object 'System.Collections.Generic.List[object]'
    } process {
        try {
            $otherWellKnownObjects = Get-ExchangeOtherWellKnownObjects
        } catch {
            Write-Verbose "Failed to get Get-ExchangeOtherWellKnownObjects"
            Invoke-CatchActions
            return
        }

        foreach ($wkObject in $otherWellKnownObjects) {
            try {
                Write-Verbose "Attempting to get SID from $($wkObject.DistinguishedName)"
                $entry = [ADSI]("LDAP://$($wkObject.DistinguishedName)")
                $wkObject | Add-Member -MemberType NoteProperty -Name SID -Value ((New-Object System.Security.Principal.SecurityIdentifier($entry.objectSid.Value, 0)).Value)
                $exchangeGroups.Add($wkObject)
            } catch {
                Write-Verbose "Failed to find SID"
                Invoke-CatchActions
            }
        }
    } end {
        return $exchangeGroups
    }
}
