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

    Function TestForKnownBuildIssues {
        param(
            [version]$CurrentVersion,
            [hashtable]$KnownBuildIssuesToFixes,
            [object]$InformationUrl
        )
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Testing CurrentVersion $CurrentVersion"

        if ($null -eq $Script:CachedKnownIssues) {
            $Script:CachedKnownIssues = @()
        }

        foreach ($key in $KnownBuildIssuesToFixes.Keys) {
            $knownIssue = GetVersionFromString $key
            Write-Verbose "Testing Known Issue Build $knownIssue"

            if ($null -ne $knownIssue -and
                $CurrentVersion.Minor -eq $knownIssue.Minor) {

                $resolvedBuild = GetVersionFromString $KnownBuildIssuesToFixes[$key]
                Write-Verbose "Testing against possible resolved build number $resolvedBuild"
                if (($null -eq $KnownBuildIssuesToFixes[$key] -and
                    (-not($Script:CachedKnownIssues.Contains($InformationUrl)))) -or
                    ($CurrentVersion -ge $knownIssue -and
                    $CurrentVersion -lt $resolvedBuild)) {
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
            -KnownBuildIssuesToFixes @{
            "15.2.986.14"  = $null
            "15.2.922.19"  = $null
            "15.1.2375.17" = $null
            "15.1.2308.20" = $null
            "15.0.1497.26" = $null
        } `
            -InformationUrl (GetKnownIssueInformation `
                "OWA redirection doesn't work after installing November 2021 security updates for Exchange Server 2019, 2016, or 2013" `
                "https://support.microsoft.com/help/5008997")
    } catch {
        Write-Verbose "Failed to run TestForKnownBuildIssues"
        Invoke-CatchActions
    }
}
