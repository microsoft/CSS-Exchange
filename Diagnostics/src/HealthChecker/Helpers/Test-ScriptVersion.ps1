Function Test-IsCurrentVersion {
    param(
        [Parameter(Mandatory = $true)][string]$CurrentVersion,
        [Parameter(Mandatory = $true)][string]$TestingVersion
    )
    Write-VerboseOutput("Calling: Test-IsCurrentVersion")
    $splitCurrentVersion = $CurrentVersion.Split(".")
    $splitTestingVersion = $TestingVersion.Split(".")
    if ($splitCurrentVersion.Count -eq $splitTestingVersion.Count) {
        for ($i = 0; $i -lt $splitCurrentVersion.Count; $i++) {
            if ($splitCurrentVersion[$i] -lt $splitTestingVersion[$i]) {
                return $false
            }
        }
        return $true
    } else {
        Write-VerboseOutput("Split count isn't the same, assuming that we are not on current version.")
        return $false
    }
}

Function Test-ScriptVersion {
    param(
        [Parameter(Mandatory = $true)][string]$ApiUri,
        [Parameter(Mandatory = $true)][string]$RepoOwner,
        [Parameter(Mandatory = $true)][string]$RepoName,
        [Parameter(Mandatory = $true)][string]$CurrentVersion,
        [Parameter(Mandatory = $true)][int]$DaysOldLimit,
        [Parameter(Mandatory = $false)][Scriptblock]$CatchActionFunction
    )
    Write-VerboseOutput("Calling: Test-ScriptVersion")
    $isCurrent = $false

    if (Test-Connection -ComputerName $ApiUri -Count 1 -Quiet) {
        try {
            $ScriptBlock = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $uri = "https://$($args[0])/repos/$($args[1])/$($args[2])/releases/latest"
                ConvertFrom-Json(Invoke-WebRequest -Uri $uri)
            }
            $WebRequestJob = Start-Job -ScriptBlock $ScriptBlock -Name "WebRequestJob" -ArgumentList $ApiUri, $RepoOwner, $RepoName

            do {
                $i++

                if ((Get-Job -Id $WebRequestJob.Id).State -eq "Completed") {
                    Write-VerboseOutput("WebRequest after {0} attempts successfully completed. Receiving results." -f $i)

                    try {
                        $releaseInformation = Receive-Job -Id $WebRequestJob.Id -Keep -ErrorAction Stop
                    } catch {

                        if ($CatchActionFunction -ne $null) {
                            & $CatchActionFunction
                        }
                    }

                    Write-VerboseOutput("Removing background worker job")
                    Remove-Job -Id $WebRequestJob.Id
                    Break
                } else {
                    Write-VerboseOutput("Attempt: {0} WebRequest not yet complete." -f $i)

                    if ($i -eq 30) {
                        Write-VerboseOutput("Reached 30 attempts. Removing background worker job.")
                        Remove-Job -Id $WebRequestJob.Id
                    }
                    Start-Sleep -Seconds 1
                }
            }
            while ($i -lt 30)
        } catch {
            Invoke-CatchActions
            Write-VerboseOutput("Failed to run Invoke-WebRequest")
        }

        if ($null -ne $releaseInformation) {
            Write-VerboseOutput("We're online: {0} connected successfully." -f $uri)
            $latestVersion = ($releaseInformation.tag_name).Split("v")[1]

            if (Test-IsCurrentVersion -CurrentVersion $CurrentVersion -TestingVersion $latestVersion) {
                Write-VerboseOutput("Version '{0}' is the latest version." -f $latestVersion)
                $isCurrent = $true
            } else {
                Write-VerboseOutput("Version '{0}' is outdated. Lastest version is '{1}'" -f $CurrentVersion, $latestVersion)
            }
        } else {
            Write-VerboseOutput("Release information was null.")
        }
    } else {
        Write-VerboseOutput("We're offline: Unable to connect to '{0}" -f $ApiUri)
        Write-VerboseOutput("Unable to determine if this version '{0}' is current. Checking to see if the file is older than {1} days." -f $CurrentVersion, $DaysOldLimit)
        $writeTime = (Get-ChildItem ($MyInvocation.ScriptName)).LastWriteTime

        if ($writeTime -gt ($testDate = ([datetime]::Now).AddDays(-$DaysOldLimit))) {
            Write-VerboseOutput("Determined that the script write time '{0}' is new than our our test date '{1}'." -f $writeTime, $testDate)
            $isCurrent = $true
        } else {
            Write-VerboseOutput("Script doesn't appear to be on the latest possible version. Script write time '{0}' vs out test date '{1}'" -f $writeTime, $testDate)
        }
    }

    Write-VerboseOutput("Exiting: Test-ScriptVersion | Returning: {0}" -f $isCurrent)
    return $isCurrent
}