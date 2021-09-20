# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function SelectStringLastRunOfExchangeSetup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true )]
        [object]$LogReviewer,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Pattern
    )
    process {
        $results = Select-String $Pattern $LogReviewer.SetupLog | Select-Object -Last 1

        if ($null -ne $results -and
            $results.LineNumber -gt $LogReviewer.LastSetupRunLine) {
            return $results
        }

        return $null
    }
}

Function GetEvaluatedSettingOrRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true )]
        [object]$LogReviewer,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$SettingName,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$SettingOrRule = "Setting",

        [Parameter(Mandatory = $false, Position = 3)]
        [string]$ValueType = "\w"
    )
    process {
        Select-String ("Evaluated \[{0}:{1}\].+\[Value:`"({2}+)`"\] \[ParentValue:" -f $SettingOrRule, $SettingName, $ValueType) $LogReviewer.SetupLog |
            Select-Object -Last 1
    }
}

Function TestEvaluatedSettingOrRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true )]
        [object]$LogReviewer,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$SettingName,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$SettingOrRule = "Setting"
    )
    process {
        $results = $LogReviewer | GetEvaluatedSettingOrRule $SettingName $SettingOrRule

        if ($null -ne $results -and
            $results.LineNumber -gt $LogReviewer.LastSetupRunLine -and
            $null -ne $results.Matches) {
            $value = $results.Matches.Groups[1].Value

            if ($value -ne "True" -and
                $value -ne "False") {
                throw "$SettingName check has unexpected value: $value"
            }
            return $value
        }
        return $null
    }
}

Function GetFirstErrorWithContextToLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true )]
        [object]$LogReviewer,

        [Parameter(Mandatory = $true, Position = 1)]
        [int]$ToLine,

        [Parameter(Mandatory = $false, Position = 2)]
        [int]$Before = 0,

        [Parameter(Mandatory = $false, Position = 3)]
        [int]$After = 200
    )
    process {
        $errorContext = New-Object 'System.Collections.Generic.List[string]'
        $allErrors = Select-String "\[ERROR\]" $LogReviewer.SetupLog -Context $Before, $After

        foreach ($currentError in $allErrors) {
            if ($currentError.LineNumber -gt $LogReviewer.LastSetupRunLine) {

                if ($Before -ne 0) {
                    $errorContext.AddRange($currentError.Context.PreContext)
                }

                $errorContext.Add($currentError.Line)
                $linesWant = $After

                if ($ToLine -ne -1) {
                    $linesWant = $ToLine - $currentError.LineNumber
                }

                for ($i = 0; $i -lt $linesWant; $i++) {
                    $line = $currentError.Context.PostContext[$i]

                    if (-not([string]::IsNullOrEmpty($line))) {
                        $errorContext.Add($line)
                    }
                }
                return $errorContext
            }
        }
    }
}

Function Get-SetupLogReviewer {
    [CmdletBinding()]
    param(
        [string]$SetupLog
    )

    $validSetupLog = Select-String "Starting Microsoft Exchange Server \d\d\d\d Setup" $SetupLog | Select-Object -Last 1

    if ($null -eq $validSetupLog) {
        throw "Failed to provide valid Exchange Setup Log"
    }

    $setupBuildNumber = Select-String "Setup version: (.+)\." $SetupLog | Select-Object -Last 1
    $runDate = [DateTime]::Parse(
        $SetupBuildNumber.Line.Substring(1,
            $SetupBuildNumber.Line.IndexOf("]") - 1),
        [System.Globalization.DateTimeFormatInfo]::InvariantInfo
    )
    $setupBuildNumber = $setupBuildNumber.Matches.Groups[1].Value
    $currentLogOnUser = Select-String "Logged on user: (.+)." $SetupLog | Select-Object -Last 1

    $logReviewer = [PSCustomObject]@{
        SetupLog         = $SetupLog
        LastSetupRunLine = $validSetupLog.LineNumber
        User             = $currentLogOnUser.Matches.Groups[1].Value
        SetupRunDate     = $runDate
        LocalBuildNumber = [string]::Empty
        SetupBuildNumber = $setupBuildNumber
    }

    $localInstall = $logReviewer | SelectStringLastRunOfExchangeSetup -Pattern "The locally installed version is (.+)\."

    if ($null -ne $localInstall) {
        $logReviewer.LocalBuildNumber = $localInstall.Matches.Groups[1].Value
    }

    $backupLocalInstall = $logReviewer | SelectStringLastRunOfExchangeSetup -Pattern "The backup copy of the previously installed version is '(.+)'\."

    if ($null -ne $backupLocalInstall) {
        $logReviewer.LocalBuildNumber = $backupLocalInstall.Matches.Groups[1].Value
    }

    return $logReviewer
}
