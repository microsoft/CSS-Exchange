# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1
function Get-TokenGroupsGlobalAndUniversal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$GCName,

        [Parameter(Mandatory = $true, ParameterSetName = "DistinguishedName")]
        [string]$DistinguishedName,

        [Parameter(Mandatory = $true, ParameterSetName = "SID")]
        [string]$UserSid,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "GCName: '$GCName' DistinguishedName: '$DistinguishedName'"
        $tokenGroups = New-Object System.Collections.Generic.List[object]
    }
    process {
        try {
            if ([string]::IsNullOrEmpty($GCName)) {
                $rootDSE = [ADSI]("GC://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
                $GCName = $rootDSE.dnsHostName
            }

            if ($PsCmdlet.ParameterSetName -eq "SID") {
                try {
                    $adObject = ([ADSI]("LDAP://<SID=" + $UserSid.ToString() + ">"))
                    $DistinguishedName = $adObject.Properties["distinguishedName"][0].ToString()
                } catch {
                    Invoke-CatchActionError $CatchActionFunction
                    throw "Failed to convert $UserSid to DistinguishedName"
                }
            }

            $searchRoot = [ADSI]("GC://" + $GCName + "/" + $DistinguishedName)
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot, "(objectClass=*)", @("tokenGroupsGlobalAndUniversal"), [System.DirectoryServices.SearchScope]::Base)
            $result = $searcher.FindOne()

            if ($null -eq $result) {
                return
            }

            foreach ($sidBytes in $result.Properties["tokenGroupsGlobalAndUniversal"]) {
                $translated = $null
                $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                try {
                    $translated = $sid.Translate("System.Security.Principal.NTAccount").ToString()
                } catch {
                    try {
                        Write-Verbose "Failed to do sid.Translate. Doing a lookup instead."
                        Invoke-CatchActionError $CatchActionFunction
                        $adObject = ([ADSI]("LDAP://<SID=" + $sid.ToString() + ">"))
                        $translated = $adObject.Properties["samAccountName"][0].ToString()
                    } catch {
                        Write-Verbose "Failed to lookup $sid"
                        Invoke-CatchActionError $CatchActionFunction
                    }
                }

                $tokenGroups.Add([PSCustomObject]@{
                        SID  = $sid.ToString()
                        Name = $translated
                    })
            }
        } catch {
            Write-Verbose "Failed to completely run $($MyInvocation.MyCommand)"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        return $tokenGroups
    }
}
