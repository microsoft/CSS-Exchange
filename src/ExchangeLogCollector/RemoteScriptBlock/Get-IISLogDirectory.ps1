Function Get-IISLogDirectory {
    Write-ScriptDebug("Function Enter: Get-IISLogDirectory")

    Function Get-IISDirectoryFromGetWebSite {
        Write-ScriptDebug("Get-WebSite command exists")
        return Get-WebSite |
            ForEach-Object {
                $logFile = "$($_.LogFile.Directory)\W3SVC$($_.id)".Replace("%SystemDrive%", $env:SystemDrive)
                Write-ScriptDebug("Found Directory: $logFile")
                return $logFile
            }
    }

    if ((Test-CommandExists -command "Get-WebSite")) {
        [array]$iisLogDirectory = Get-IISDirectoryFromGetWebSite
    } else {
        #May need to load the module
        try {
            Write-ScriptDebug("Going to attempt to load the WebAdministration Module")
            Import-Module WebAdministration -ErrorAction Stop
            Write-ScriptDebug("Successful loading the module")

            if ((Test-CommandExists -command "Get-WebSite")) {
                [array]$iisLogDirectory = Get-IISDirectoryFromGetWebSite
            }
        } catch {
            Invoke-CatchBlockActions
            [array]$iisLogDirectory = "C:\inetpub\logs\LogFiles\" #Default location for IIS Logs
            Write-ScriptDebug("Get-WebSite command doesn't exists. Set IISLogDirectory to: {0}" -f $iisLogDirectory)
        }
    }
    #Test out the directories that we found.
    $iisLogDirectory |
        ForEach-Object {

            if (!(Test-Path $_)) {
                Write-ScriptDebug("Failed to find a valid path for at least one of the IIS directories. Test path: {0}" -f $_)
                Write-ScriptHost -ShowServer $true -WriteString ("Failed to determine where the IIS Logs are located at. Unable to collect them.") -ForegroundColor "Red"
                $Script:iisLogDirectory = $null
            }
        }

    Write-ScriptDebug("Function Exit: Get-IISLogDirectory")
    return $iisLogDirectory
}