# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function SelectStringLastRunOfExchangeSetup {
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

function GetEvaluatedSettingOrRule {
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

function GetMultiEvaluatedSettingOrRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
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
            Where-Object { $_.LineNumber -gt $LogReviewer.LastSetupRunLine }
    }
}

function TestMultiEvaluatedSettingOrRule {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true )]
        [object]$LogReviewer,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$SettingName,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$SettingOrRule = "Setting",

        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateSet("True", "False")]
        [string]$TestValue
    )
    process {
        $results = $LogReviewer | GetMultiEvaluatedSettingOrRule $SettingName $SettingOrRule
        $testResult = $false

        if ($null -ne $results -and
            $null -ne $results.Matches) {

            foreach ($result in $results) {
                if ($result.Matches.Groups[1].Value -eq $TestValue) {
                    $testResult = $true
                    return
                }
            }
        }
    } end {
        return $testResult
    }
}

function TestEvaluatedSettingOrRule {
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

function GetFirstErrorWithContextToLine {
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

function Get-SetupLogReviewer {
    [CmdletBinding()]
    param(
        [string]$SetupLog
    )

    function GetDateTimeFromLine {
        param(
            [string]$line
        )
        return [DateTime]::Parse(
            $line.Substring(1,
                $line.IndexOf("]") - 1),
            [System.Globalization.DateTimeFormatInfo]::InvariantInfo)
    }

    $contextLength = 30
    $validSetupLog = Select-String "Starting Microsoft Exchange Server \d\d\d\d Setup" $SetupLog -Context 0, $contextLength

    if ($null -eq $validSetupLog) {
        throw "Failed to provide valid Exchange Setup Log"
    }

    $temp = $validSetupLog | Select-Object -Last 1

    if ($temp.Context.PostContext.Count -eq $contextLength) {
        Write-Verbose "Found enough lines in the log to be good to work with."
        $validSetupLog = $temp
    } else {
        $temp = $validSetupLog | Select-Object -Last 2
        if ($temp.Count -ne 2) {
            Write-Warning "Might not have enough data to properly determine what is wrong and script might fail out."
            $validSetupLog = $temp[-1]
        } else {
            $lastAttemptDateTime = GetDateTimeFromLine $temp[1].Line
            $previousAttemptDateTime = GetDateTimeFromLine $temp[0].Line

            if ($lastAttemptDateTime.AddDays(-30) -lt $previousAttemptDateTime) {
                Write-Warning "The last setup attempt doesn't appear to be enough data. Going to try the previous setup attempt to look at."
                $validSetupLog = $temp[0]
            } else {
                Write-Warning "The last setup attempt doesn't appear to be enough data. However, the previous setup attempt is over 30 days old. Continuing with the last attempt..."
                $validSetupLog = $temp[1]
            }
        }
    }

    $runDate = GetDateTimeFromLine $validSetupLog.Line
    $setupBuildNumberSls = Select-String "Setup version: (.+)\." $SetupLog | Select-Object -Last 1
    $setupBuildNumber = $setupBuildNumberSls.Matches.Groups[1].Value
    $currentLogOnUser = Select-String "Logged on user: (.+)." $SetupLog | Select-Object -Last 1

    if ($currentLogOnUser.LineNumber -lt $validSetupLog.LineNumber -or
        $setupBuildNumberSls.LineNumber -lt $validSetupLog.LineNumber) {
        Write-Warning "The Setup Version or Logged On User line isn't greater than the current last setup run. Results might not be accurate."
    }

    $logReviewer = [PSCustomObject]@{
        SetupLog         = $SetupLog
        LastSetupRunLine = $validSetupLog.LineNumber
        User             = $currentLogOnUser.Matches.Groups[1].Value
        SetupRunDate     = $runDate
        SetupMode        = "Unknown"
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

    $setupMode = $logReviewer | SelectStringLastRunOfExchangeSetup -Pattern "Command Line Parameter Name='mode', Value='(.+)'\."

    if ($null -ne $setupMode) {
        $logReviewer.SetupMode = $setupMode.Matches.Groups[1].Value
    }

    return $logReviewer
}
