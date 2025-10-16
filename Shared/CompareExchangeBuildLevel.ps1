﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Test-ExchangeBuildGreaterOrEqualThanBuild {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CurrentExchangeBuild,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$CU,
        [Parameter(Mandatory = $false)]
        [string]$SU
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        if ($CurrentExchangeBuild.MajorVersion -eq $Version) {
            $params = @{
                Version = $Version
                CU      = $CU
            }

            if (-not([string]::IsNullOrEmpty($SU))) {
                $params.SU = $SU
            }
            $testBuild = $null
            Get-ExchangeBuildVersionInformation @params | Invoke-RemotePipelineHandler -Result ([ref]$testBuild)
            $testResult = $CurrentExchangeBuild.BuildVersion -ge $testBuild.BuildVersion
        }
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}

function Test-ExchangeBuildLessThanBuild {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CurrentExchangeBuild,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$CU,
        [Parameter(Mandatory = $false)]
        [string]$SU
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        if ($CurrentExchangeBuild.MajorVersion -eq $Version) {
            $params = @{
                Version = $Version
                CU      = $CU
            }

            if (-not([string]::IsNullOrEmpty($SU))) {
                $params.SU = $SU
            }

            $testBuild = $null
            Get-ExchangeBuildVersionInformation @params | Invoke-RemotePipelineHandler -Result ([ref]$testBuild)
            $testResult = $CurrentExchangeBuild.BuildVersion -lt $testBuild.BuildVersion
        }
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}

function Test-ExchangeBuildEqualBuild {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CurrentExchangeBuild,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$CU,
        [Parameter(Mandatory = $false)]
        [string]$SU
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        if ($CurrentExchangeBuild.MajorVersion -eq $Version) {
            $params = @{
                Version = $Version
                CU      = $CU
            }

            if (-not([string]::IsNullOrEmpty($SU))) {
                $params.SU = $SU
            }
            $testBuild = $null
            Get-ExchangeBuildVersionInformation @params | Invoke-RemotePipelineHandler -Result ([ref]$testBuild)
            $testResult = $CurrentExchangeBuild.BuildVersion -eq $testBuild.BuildVersion
        }
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}

function Test-ExchangeBuildGreaterOrEqualThanSecurityPatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [object]$CurrentExchangeBuild,
        [string]$SUName
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        $allSecurityPatches = $null
        Get-ExchangeBuildVersionInformation -FindBySUName $SUName |
            Invoke-RemotePipelineHandler -Result ([ref]$allSecurityPatches)
        $allSecurityPatches = $allSecurityPatches |
            Where-Object { $_.MajorVersion -eq $CurrentExchangeBuild.MajorVersion } |
            Sort-Object ReleaseDate -Descending

        if ($null -eq $allSecurityPatches -or
            $allSecurityPatches.Count -eq 0) {
            Write-Verbose "We didn't find a security path ($SUName) for this version of Exchange ($CurrentExchangeBuild)."
            Write-Verbose "We assume this means that this version of Exchange $($CurrentExchangeBuild.MajorVersion) isn't vulnerable for this SU $SUName"
            $testResult = $true
            return
        }

        # The first item in the list should be the latest CU for this security patch.
        # If the current exchange build is greater than the latest CU + security patch, then we are good.
        # Otherwise, we need to look at the CU that we are on to make sure we are patched.
        if ($CurrentExchangeBuild.BuildVersion -ge $allSecurityPatches[0].BuildVersion) {
            $testResult = $true
            return
        }
        Write-Verbose "Need to look at particular CU match"
        $matchCU = $allSecurityPatches | Where-Object { $_.CU -eq $CurrentExchangeBuild.CU }
        Write-Verbose "Found match CU $($null -ne $matchCU)"
        $testResult = $null -ne $matchCU -and $CurrentExchangeBuild.BuildVersion -ge $matchCU.BuildVersion
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}
