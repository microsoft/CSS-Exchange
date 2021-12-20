# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\Helpers\Invoke-CatchActions.ps1

Function Invoke-AnalyzerKnownBuildIssues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [string]$CurrentBuild,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    Function GetVersionFromString {
        param(
            [object]$VersionString
        )
        try {
            return New-Object System.Version $VersionString -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to convert '$VersionString' in $($MyInvocation.MyCommand)"
            Invoke-CatchActions
        }
    }

    Function GetKnownIssueInformation {
        param(
            [string]$Name,
            [string]$Url
        )

        return [PSCustomObject]@{
            Name = $Name
            Url  = $Url
        }
    }

    Function GetKnownIssueBuildInformation {
        param(
            [string]$BuildNumber,
            [string]$FixBuildNumber,
            [bool]$BuildBound = $true
        )

        return [PSCustomObject]@{
            BuildNumber    = $BuildNumber
            FixBuildNumber = $FixBuildNumber
            BuildBound     = $BuildBound
        }
    }

    Function TestOnKnownBuildIssue {
        param(
            [object]$IssueBuildInformation,
            [version]$CurrentBuild
        )
        $knownIssue = GetVersionFromString $issue.BuildNumber
        Write-Verbose "Testing Known Issue Build $knownIssue"

        if ($null -eq $knownIssue -or
            $CurrentBuild.Minor -ne $knownIssue.Minor) { return $false }

        $fixValueNull = [string]::IsNullOrEmpty($IssueBuildInformation.FixBuildNumber)
        if ($fixValueNull) {
            $resolvedBuild = GetVersionFromString "0.0.0.0"
        } else {
            $resolvedBuild = GetVersionFromString $IssueBuildInformation.FixBuildNumber
        }

        Write-Verbose "Testing against possible resolved build number $resolvedBuild"
        $buildBound = $IssueBuildInformation.BuildBound
        $withinBuildBoundRange = $CurrentBuild.Build -eq $knownIssue.Build
        $fixNeeded = $fixValueNull -or $CurrentBuild -le $resolvedBuild
        Write-Verbose "BuildBound: $buildBound | WithinBuildBoundRage: $withinBuildBoundRange | FixNeeded: $fixNeeded"
        if ($CurrentBuild -ge $knownIssue) {
            if ($buildBound) {
                return $withinBuildBoundRange -and $fixNeeded
            } else {
                return $fixNeeded
            }
        }

        return $false
    }

    Function TestForKnownBuildIssues {
        param(
            [version]$CurrentVersion,
            [object[]]$KnownBuildIssuesToFixes,
            [object]$InformationUrl
        )
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Testing CurrentVersion $CurrentVersion"

        if ($null -eq $Script:CachedKnownIssues) {
            $Script:CachedKnownIssues = @()
        }

        foreach ($issue in $KnownBuildIssuesToFixes) {

            if ((TestOnKnownBuildIssue $issue $CurrentVersion) -and
                    (-not($Script:CachedKnownIssues.Contains($InformationUrl)))) {
                Write-Verbose "Known issue Match detected"
                if (-not ($Script:DisplayKnownIssueHeader)) {
                    $Script:DisplayKnownIssueHeader = $true

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Known Issue Detected" `
                        -Details "True" `
                        -DisplayGroupingKey $DisplayGroupingKey `
                        -DisplayWriteType "Yellow"

                    $AnalyzeResults | Add-AnalyzedResultInformation -Details "This build has a known issue(s) which may or may not have been addressed. See the below link(s) for more information.`r`n" `
                        -DisplayGroupingKey $DisplayGroupingKey `
                        -DisplayCustomTabNumber 2 `
                        -DisplayWriteType "Yellow"
                }

                $AnalyzeResults | Add-AnalyzedResultInformation -Details "$($InformationUrl.Name):`r`n`t`t`t$($InformationUrl.Url)" `
                    -DisplayGroupingKey $DisplayGroupingKey `
                    -DisplayCustomTabNumber 2 `
                    -DisplayWriteType "Yellow"

                if (-not ($Script:CachedKnownIssues.Contains($InformationUrl))) {
                    $Script:CachedKnownIssues += $InformationUrl
                    Write-Verbose "Added known issue to cache"
                }
            }
        }
    }

    try {
        $currentVersion = New-Object System.Version $CurrentBuild -ErrorAction Stop
    } catch {
        Write-Verbose "Failed to set the current build to a version type object. $CurrentBuild"
        Invoke-CatchActions
    }

    try {
        Write-Verbose "Working on November 2021 Security Updates - OWA redirection"
        TestForKnownBuildIssues -CurrentVersion $currentVersion `
            -KnownBuildIssuesToFixes @(
            (GetKnownIssueBuildInformation "15.2.986.14" $null),
            (GetKnownIssueBuildInformation "15.2.922.19" $null),
            (GetKnownIssueBuildInformation "15.1.2375.17" $null),
            (GetKnownIssueBuildInformation "15.1.2308.20" $null),
            (GetKnownIssueBuildInformation "15.0.1497.26" $null)
        ) `
            -InformationUrl (GetKnownIssueInformation `
                "OWA redirection doesn't work after installing November 2021 security updates for Exchange Server 2019, 2016, or 2013" `
                "https://support.microsoft.com/help/5008997")
    } catch {
        Write-Verbose "Failed to run TestForKnownBuildIssues"
        Invoke-CatchActions
    }
}
