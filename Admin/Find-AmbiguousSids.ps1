# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param (
    [string]
    $GCName = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.FindGlobalCatalog().Name,

    [bool]
    $IgnoreWellKnown = $true
)

begin {
    function IsAnyWellKnownSid($sid) {
        if ($sid.ToString() -eq "S-1-5-10") {
            return $true
        }

        foreach ($t in [Enum]::GetNames([System.Security.Principal.WellKnownSidType])) {
            if ($sid.IsWellKnown($t)) {
                return $true
            }
        }

        return $false
    }

    function IsInIgnoredContainer($dn) {
        foreach ($container in $containersToIgnore) {
            if ($dn -match $container) {
                return $true
            }
        }

        return $false
    }

    function CheckSid($sid, $distinguishedName) {
        if ($IgnoreWellKnown) {
            if ((IsAnyWellKnownSid $sid) -or (IsInIgnoredContainer $distinguishedName)) {
                return
            }
        }

        $sidString = $sid.ToString()
        if ($null -eq $sidTable[$sidString]) {
            $sidTable[$sidString] = $distinguishedName
        } else {
            [PSCustomObject]@{
                SID     = $sidString
                Object1 = $($sidTable[$sidString])
                Object2 = $($distinguishedName)
            }
        }
    }

    [void][System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    $filter = "(|(objectSid=*)(sidHistory=*)(msExchMasterAccountSid=*))"
    $pageSize = 100
    Write-Host "Using GC $GCName"
    $ldapConn = New-Object System.DirectoryServices.Protocols.LdapConnection("$($GCName):3268")
    $searchReq = New-Object System.DirectoryServices.Protocols.SearchRequest("", $filter, "Subtree", $null)
    $prc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
    [void]$searchReq.Controls.Add($prc)

    $sidProperties = @("objectSid", "sidHistory", "msExchMasterAccountSid")
    $containersToIgnore = @(",CN=WellKnown Security Principals,", ",CN=Builtin,", ",CN=ForeignSecurityPrincipals,")
    $sidTable = @{}
    $objectsProcessed = 0
    $sw = New-Object System.Diagnostics.Stopwatch
    $sw.Start()
}

process {
    do {
        $response = $ldapConn.SendRequest($searchReq)
        foreach ($control in $response.Controls) {
            if ($control -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                $prc.Cookie = $control.Cookie
            }
        }

        if ($sw.ElapsedMilliseconds -gt 1000) {
            $sw.Restart()
            Write-Progress -Activity "Inspecting AD objects" -Status "$objectsProcessed"
        }

        $response.Entries | ForEach-Object {
            $result = $_
            $dn = $result.Attributes["distinguishedName"][0].ToString()
            Write-Verbose "Inspecting $dn"
            foreach ($propName in $sidProperties) {
                foreach ($v in $result.Attributes[$propName]) {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier(($v), 0)
                    CheckSid $sid $dn
                }
            }

            $objectsProcessed++
        }
    } while ($prc.Cookie.Length -gt 0)
}

end {
    Write-Host "Inspected $objectsProcessed objects."
    Write-Host "Done!"
}
