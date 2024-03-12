# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1

function Invoke-AnalyzerKnownBuildIssues {
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
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    # Extract for Pester Testing - Start
    function GetVersionFromString {
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

    function GetKnownIssueInformation {
        param(
            [string]$Name,
            [string]$Url
        )

        return [PSCustomObject]@{
            Name = $Name
            Url  = $Url
        }
    }

    function GetKnownIssueBuildInformation {
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

    function TestOnKnownBuildIssue {
        [CmdletBinding()]
        [OutputType("System.Boolean")]
        param(
            [object]$IssueBuildInformation,
            [version]$CurrentBuild
        )
        $knownIssue = GetVersionFromString $IssueBuildInformation.BuildNumber
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
        $fixNeeded = $fixValueNull -or $CurrentBuild -lt $resolvedBuild
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

    # Extract for Pester Testing - End

    function TestForKnownBuildIssues {
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

                    $params = $baseParams + @{
                        Name             = "Known Issue Detected"
                        Details          = "True"
                        DisplayWriteType = "Yellow"
                    }
                    Add-AnalyzedResultInformation @params

                    $params = $baseParams + @{
                        Details                = "This build has a known issue(s) which may or may not have been addressed. See the below link(s) for more information.`r`n"
                        DisplayWriteType       = "Yellow"
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }

                $params = $baseParams + @{
                    Details                = "$($InformationUrl.Name):`r`n`t`t`t$($InformationUrl.Url)"
                    DisplayWriteType       = "Yellow"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params

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
        $infoParams = @{
            Name = "OWA redirection doesn't work after installing November 2021 security updates for Exchange Server 2019, 2016, or 2013"
            Url  = "https://support.microsoft.com/help/5008997"
        }
        $params = @{
            CurrentVersion          = $currentVersion
            KnownBuildIssuesToFixes = @((GetKnownIssueBuildInformation "15.2.986.14" "15.2.986.15"),
                (GetKnownIssueBuildInformation "15.2.922.19" "15.2.922.20"),
                (GetKnownIssueBuildInformation "15.1.2375.17" "15.1.2375.18"),
                (GetKnownIssueBuildInformation "15.1.2308.20" "15.1.2308.21"),
                (GetKnownIssueBuildInformation "15.0.1497.26" "15.0.1497.28"))
            InformationUrl          = (GetKnownIssueInformation @infoParams)
        }
        TestForKnownBuildIssues @params

        Write-Verbose "Working on March 2022 Security Updates - MSExchangeServiceHost service may crash"
        $infoParams = @{
            Name = "Exchange Service Host service fails after installing March 2022 security update (KB5013118)"
            Url  = "https://support.microsoft.com/kb/5013118"
        }
        $params = @{
            CurrentVersion          = $currentVersion
            KnownBuildIssuesToFixes = @((GetKnownIssueBuildInformation "15.2.1118.7" "15.2.1118.9"),
                (GetKnownIssueBuildInformation "15.2.986.22" "15.2.986.26"),
                (GetKnownIssueBuildInformation "15.2.922.27" $null),
                (GetKnownIssueBuildInformation "15.1.2507.6" "15.1.2507.9"),
                (GetKnownIssueBuildInformation "15.1.2375.24" "15.1.2375.28"),
                (GetKnownIssueBuildInformation "15.1.2308.27" $null),
                (GetKnownIssueBuildInformation "15.0.1497.33" "15.0.1497.36"))
            InformationUrl          = (GetKnownIssueInformation @infoParams)
        }
        TestForKnownBuildIssues @params

        Write-Verbose "Working on January 2023 Security Updates - Management issues after SerializedDataSigning is enabled on Exchange Server 2013"
        $infoParams = @{
            Name = "Management issues after SerializedDataSigning is enabled on Exchange Server 2013"
            Url  = "https://techcommunity.microsoft.com/t5/exchange-team-blog/released-january-2023-exchange-server-security-updates/ba-p/3711808"
        }
        $params = @{
            CurrentVersion          = $currentVersion
            KnownBuildIssuesToFixes = @((GetKnownIssueBuildInformation "15.0.1497.45" "15.0.1497.47"))
            InformationUrl          = (GetKnownIssueInformation @infoParams)
        }
        TestForKnownBuildIssues @params

        Write-Verbose "Working on January 2023 Security Updates - Other known issues"
        $infoParams = @{
            Name = "Known Issues with Jan 2023 Security for Exchange 2016 and 2019"
            Url  = "https://techcommunity.microsoft.com/t5/exchange-team-blog/released-january-2023-exchange-server-security-updates/ba-p/3711808"
        }
        $params = @{
            CurrentVersion          = $currentVersion
            KnownBuildIssuesToFixes = @((GetKnownIssueBuildInformation "15.1.2507.17" "15.1.2507.21"),
                (GetKnownIssueBuildInformation "15.2.986.37" "15.2.986.41"),
                (GetKnownIssueBuildInformation "15.2.1118.21" "15.2.1118.25"))
            InformationUrl          = (GetKnownIssueInformation @infoParams)
        }
        TestForKnownBuildIssues @params

        Write-Verbose "Working on February 2023 Security Updates"
        $infoParams = @{
            Name = "Known Issues with Feb 2023 Security Updates"
            Url  = "https://techcommunity.microsoft.com/t5/exchange-team-blog/released-february-2023-exchange-server-security-updates/ba-p/3741058"
        }
        $params = @{
            CurrentVersion          = $currentVersion
            KnownBuildIssuesToFixes = @((GetKnownIssueBuildInformation "15.2.1118.25" "15.2.1118.26"),
                (GetKnownIssueBuildInformation "15.2.986.41" "15.2.986.42"),
                (GetKnownIssueBuildInformation "15.1.2507.21" "15.1.2507.23"))
            InformationUrl          = (GetKnownIssueInformation @infoParams)
        }
        TestForKnownBuildIssues @params

        Write-Verbose "Work on March 2024 Security Updates"
        $infoParams = @{
            Name = "Known Issues with Mar 2024 Security Updates"
            Url  = "https://support.microsoft.com/help/5037171"
        }
        $params = @{
            CurrentVersion          = $currentVersion
            KnownBuildIssuesToFixes = @((GetKnownIssueBuildInformation "15.2.1544.9" $null),
                (GetKnownIssueBuildInformation "15.2.1258.32" $null),
                (GetKnownIssueBuildInformation "15.1.2507.37", $null))
            InformationUrl          = (GetKnownIssueInformation @infoParams)
        }
        TestForKnownBuildIssues @params
    } catch {
        Write-Verbose "Failed to run TestForKnownBuildIssues"
        Invoke-CatchActions
    }
}
