# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-UserGroupMemberOf {

    $whoamiOutput = whoami /all

    $whoamiOutput | Select-String "User Name" -Context (0, 3)

    [array]$g = GetGroupMatches $whoamiOutput "Domain Admins"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { "User is a member of $($_.GroupName)   $($_.SID)" | Receive-Output }
    } else {
        "User is not a member of Domain Admins." | Receive-Output -IsWarning
    }

    [array]$g = GetGroupMatches $whoamiOutput "Schema Admins"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { "User is a member of $($_.GroupName)   $($_.SID)" | Receive-Output }
    } else {
        "User is not a member of Schema Admins. - Only required if doing a Schema Update" | Receive-Output -IsWarning
        $Script:NotSchemaAdmin = $true
    }

    [array]$g = GetGroupMatches $whoamiOutput "Enterprise Admins"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { "User is a member of $($_.GroupName)   $($_.SID)" | Receive-Output }
    } else {
        "User is not a member of Enterprise Admins. - Only required if doing a Schema Update or PrepareAD or PrepareDomain" | Receive-Output -IsWarning
        $Script:NotEnterpriseAdmin = $true
    }

    [array]$g = GetGroupMatches $whoamiOutput "Organization Management"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { "User is a member of $($_.GroupName)   $($_.SID)" | Receive-Output }
    } else {
        "User is not a member of Organization Management." | Receive-Output -IsWarning
    }

    $p = Get-ExecutionPolicy
    if ($p -ne "Unrestricted" -and $p -ne "Bypass") {
        "ExecutionPolicy is $p" | Receive-Output -IsWarning
    } else {
        "ExecutionPolicy is $p" | Receive-Output
    }
}

function GetGroupMatches($whoamiOutput, $groupName) {
    $m = @($whoamiOutput | Select-String "(^\w+\\$($groupName))\W+Group")
    if ($m.Count -eq 0) { return $m }
    return $m | ForEach-Object {
        [PSCustomObject]@{
            GroupName = ($_.Matches.Groups[1].Value)
            SID       = (GetSidFromLine $_.Line)
        }
    }
}

Function GetSidFromLine ([string]$Line) {
    $startIndex = $Line.IndexOf("S-")
    return $Line.Substring($startIndex,
        $Line.IndexOf(" ", $startIndex) - $startIndex)
}

