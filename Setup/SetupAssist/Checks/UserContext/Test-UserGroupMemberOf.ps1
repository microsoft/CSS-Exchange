# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\New-TestResult.ps1
Function Test-UserGroupMemberOf {

    function GetGroupMatches($whoamiOutput, $groupName) {
        $m = @($whoamiOutput | Select-String "(^\w+\\$($groupName))\s+")
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

    Function TestGroupResult($WhoamiOutput, $GroupName) {
        [array]$g = GetGroupMatches $WhoamiOutput $GroupName
        $params = @{
            TestName = $GroupName
        }

        if ($g.Count -gt 0) {
            New-TestResult @params -Result "Passed" -Details "$($g.GroupName) $($g.SID)"
        } else {
            New-TestResult @params -Result "Failed"
        }
    }

    $whoami = whoami
    $whoamiAllOutput = whoami /all
    $userSid = ($whoamiAllOutput | Select-String $whoami.Replace("\", "\\")).Line.Replace($whoami, "").Trim()

    $params = @{
        TestName = "User Administrator"
        Details  = "$whoami $userSid"
    }

    if (Confirm-Administrator) {
        New-TestResult @params -Result "Passed"
    } else {
        New-TestResult @params -Result "Failed"
    }

    TestGroupResult $whoamiAllOutput "Domain Admins"
    TestGroupResult $whoamiAllOutput "Schema Admins"
    TestGroupResult $whoamiAllOutput "Enterprise Admins"
    TestGroupResult $whoamiAllOutput "Organization Management"
}

