# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-ScriptBlockHandler.ps1

Function Get-VisualCRedistributableVersion {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: Get-VisualCRedistributableVersion"
        $softwareList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        $installedSoftware = Invoke-ScriptBlockHandler -ComputerName $ComputerName `
            -ScriptBlock { Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* } `
            -ScriptBlockDescription "Querying for software" `
            -CatchActionFunction $CatchActionFunction

        foreach ($software in $installedSoftware) {

            if ($software.DisplayName -like "Microsoft Visual C++ *") {
                Write-Verbose "Microsoft Visual C++ Found: $($software.DisplayName)"
                $softwareList.Add([PSCustomObject]@{
                        DisplayName       = $software.DisplayName
                        DisplayVersion    = $software.DisplayVersion
                        InstallDate       = $software.InstallDate
                        VersionIdentifier = $software.Version
                    })
            }
        }
    }
    end {
        Write-Verbose "Exiting: Get-VisualCRedistributableVersion"
        return $softwareList
    }
}

Function Get-VisualCRedistributable2012Information {
    return [PSCustomObject]@{
        VersionNumber = 184610406
        DownloadUrl   = "https://www.microsoft.com/en-us/download/details.aspx?id=30679"
        DisplayName   = "Microsoft Visual C++ 2012*"
    }
}

Function Get-VisualCRedistributable2013Information {
    return [PSCustomObject]@{
        VersionNumber = 201367256
        DownloadUrl   = "https://support.microsoft.com/en-us/topic/update-for-visual-c-2013-redistributable-package-d8ccd6a5-4e26-c290-517b-8da6cfdf4f10"
        DisplayName   = "Microsoft Visual C++ 2013*"
    }
}

#Returns a 0 if no version is detected
#Returns a 1 if version is detected, but the the version we wanted.
#Returns a 2 if version is up to date.
Function Get-VcRedistributableVersionStatus {
    [CmdletBinding()]
    param(
        [object]$VisualCRedistributableVersion,
        [Parameter(Mandatory = $true)]
        [object]$VersionInformation
    )
    begin {
        $versionDetected = $true
        $value = 0
    }
    process {
        foreach ($detectVersion in $VisualCRedistributableVersion) {
            if ($detectVersion.DisplayName -like $VersionInformation.DisplayName) {
                $versionDetected = $true

                if ($detectVersion.VersionIdentifier -eq $VersionInformation.VersionNumber) {
                    $value += 1
                    return
                }
            }
        }
    }
    end {
        if ($versionDetected) {
            $value += 1
        }
        return $value
    }
}
