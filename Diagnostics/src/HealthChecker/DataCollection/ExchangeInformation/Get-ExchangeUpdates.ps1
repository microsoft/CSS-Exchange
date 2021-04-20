Function Get-ExchangeUpdates {
    param(
        [Parameter(Mandatory = $true)][HealthChecker.ExchangeMajorVersion]$ExchangeMajorVersion
    )
    Write-VerboseOutput("Calling: Get-ExchangeUpdates")
    Write-VerboseOutput("Passed: {0}" -f $ExchangeMajorVersion.ToString())
    $RegLocation = [string]::Empty

    if ([HealthChecker.ExchangeMajorVersion]::Exchange2013 -eq $ExchangeMajorVersion) {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2013"
    } elseif ([HealthChecker.ExchangeMajorVersion]::Exchange2016 -eq $ExchangeMajorVersion) {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2016"
    } else {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2019"
    }

    $RegKey = Invoke-RegistryGetValue -MachineName $Script:Server -SubKey $RegLocation -ReturnAfterOpenSubKey $true -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($null -ne $RegKey) {
        $IU = $RegKey.GetSubKeyNames()
        if ($null -ne $IU) {
            Write-VerboseOutput("Detected fixes installed on the server")
            $fixes = @()
            foreach ($key in $IU) {
                $IUKey = $RegKey.OpenSubKey($key)
                $IUName = $IUKey.GetValue("PackageName")
                Write-VerboseOutput("Found: " + $IUName)
                $fixes += $IUName
            }
            return $fixes
        } else {
            Write-VerboseOutput("No IUs found in the registry")
        }
    } else {
        Write-VerboseOutput("No RegKey returned")
    }

    Write-VerboseOutput("Exiting: Get-ExchangeUpdates")
    return $null
}