Function Set-IISDirectoryInfo {
    Write-ScriptDebug("Function Enter: Set-IISDirectoryInfo")

    Function Get-IISDirectoryFromGetWebSite {
        Write-ScriptDebug("Get-WebSite command exists")
        foreach ($WebSite in $(Get-WebSite)) {
            $logFile = "$($Website.logFile.directory)\W3SVC$($website.id)".replace("%SystemDrive%", $env:SystemDrive)
            $Script:IISLogDirectory += $logFile + ";"
            Write-ScriptDebug("Found Directory: {0}" -f $logFile)
        }
        #remove the last ; 
        $Script:IISLogDirectory = $Script:IISLogDirectory.Substring(0, $Script:IISLogDirectory.Length - 1)
        #$Script:IISLogDirectory = ((Get-WebConfigurationProperty "system.applicationHost/sites/siteDefaults" -Name logFile).directory).Replace("%SystemDrive%",$env:SystemDrive) 
        Write-ScriptDebug("Set IISLogDirectory: {0}" -f $Script:IISLogDirectory)
    }

    Function Get-IISDirectoryFromDefaultSettings {
        $Script:IISLogDirectory = "C:\inetpub\logs\LogFiles\" #Default location for IIS Logs 
        Write-ScriptDebug("Get-WebSite command doesn't exists. Set IISLogDirectory to: {0}" -f $Script:IISLogDirectory)
    }

    if ((Test-CommandExists -command "Get-WebSite")) {
        Get-IISDirectoryFromGetWebSite
    } else {
        #May need to load the module 
        try {
            Write-ScriptDebug("Going to attempt to load the WebAdministration Module")
            Import-Module WebAdministration
            Write-ScriptDebug("Successful loading the module")
            if ((Test-CommandExists -command "Get-WebSite")) {
                Get-IISDirectoryFromGetWebSite
            }
        } catch {
            Get-IISDirectoryFromDefaultSettings
        }
        
    }
    #Test out the directories that we found. 
    foreach ($directory in $Script:IISLogDirectory.Split(";")) {
        if (-not (Test-Path $directory)) {
            Write-ScriptDebug("Failed to find a valid path for at least one of the IIS directories. Test path: {0}" -f $directory)
            Write-ScriptDebug("Function Exit: Set-IISDirectoryInfo - Failed")
            Write-ScriptHost -ShowServer $true -WriteString ("Failed to determine where the IIS Logs are located at. Unable to collect them.") -ForegroundColor "Red"
            return $false
        }
    }

    Write-ScriptDebug("Function Exit: Set-IISDirectoryInfo - Passed")
    return $true 
}