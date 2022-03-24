# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Test-CommandExists.ps1
Function Get-IISLogDirectory {
    Write-Verbose("Function Enter: Get-IISLogDirectory")

    Function Get-IISDirectoryFromGetWebSite {
        Write-Verbose("Get-WebSite command exists")
        return Get-WebSite |
            ForEach-Object {
                $logFile = "$($_.LogFile.Directory)\W3SVC$($_.id)".Replace("%SystemDrive%", $env:SystemDrive)
                Write-Verbose("Found Directory: $logFile")
                return $logFile
            }
    }

    if ((Test-CommandExists -command "Get-WebSite")) {
        [array]$iisLogDirectory = Get-IISDirectoryFromGetWebSite
    } else {
        #May need to load the module
        try {
            Write-Verbose("Going to attempt to load the WebAdministration Module")
            Import-Module WebAdministration -ErrorAction Stop
            Write-Verbose("Successful loading the module")

            if ((Test-CommandExists -command "Get-WebSite")) {
                [array]$iisLogDirectory = Get-IISDirectoryFromGetWebSite
            }
        } catch {
            Invoke-CatchBlockActions
            [array]$iisLogDirectory = "C:\inetpub\logs\LogFiles\" #Default location for IIS Logs
            Write-Verbose("Get-WebSite command doesn't exists. Set IISLogDirectory to: {0}" -f $iisLogDirectory)
        }
    }

    Write-Verbose("Function Exit: Get-IISLogDirectory")
    return $iisLogDirectory
}
