. $PSScriptRoot\Get-EmbeddedFileList.ps1

<#
.SYNOPSIS
    Gets the most recent commit, considering all files related to the specified script,
    including any embedded dot-sourced scripts or other files.
#>
function Get-ScriptProjectMostRecentCommit {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $File
    )

    process {
        Write-Verbose "Get-ScriptProjectMostRecentCommit called for file $File"
        $mostRecentCommit = [DateTime]::MinValue
        if ([DateTime]::TryParse((git log -n 1 --format="%ad" --date=rfc $File), [ref] $mostRecentCommit)) {
            Get-EmbeddedFileList $File | ForEach-Object {
                Write-Verbose "Getting commit time for $_"
                $commitTime = [DateTime]::Parse((git log -n 1 --format="%ad" --date=rfc $_))
                if ($commitTime -gt $mostRecentCommit) {
                    $mostRecentCommit = $commitTime
                    Write-Host ("Changing commit time to: $($commitTime.ToString("yy.MM.dd.HHmm"))")
                }
            }
        }

        $mostRecentCommit
    }
}
