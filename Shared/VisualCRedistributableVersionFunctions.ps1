# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-ScriptBlockHandler.ps1

Function Get-VisualCRedistributableInstalledVersion {
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

Function Get-VisualCRedistributableInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet(2012, 2013)]
        [int]
        $Year
    )

    if ($Year -eq 2012) {
        return [PSCustomObject]@{
            VersionNumber = 184610406
            DownloadUrl   = "https://www.microsoft.com/en-us/download/details.aspx?id=30679"
            DisplayName   = "Microsoft Visual C++ 2012*"
        }
    } else {
        return [PSCustomObject]@{
            VersionNumber = 201367256
            DownloadUrl   = "https://support.microsoft.com/en-us/topic/update-for-visual-c-2013-redistributable-package-d8ccd6a5-4e26-c290-517b-8da6cfdf4f10"
            DisplayName   = "Microsoft Visual C++ 2013*"
        }
    }
}

Function Test-VisualCRedistributableDesiredVersionInstalled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]
        $Installed,

        [Parameter(Mandatory = $true)]
        [object]
        $Desired
    )

    return ($null -ne $Installed | Where-Object { $_.DisplayName -like $Desired.DisplayName })
}

Function Test-VisualCRedistributableDesiredVersionUpToDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]
        $Installed,

        [Parameter(Mandatory = $true)]
        [object]
        $Desired
    )

    return ($null -ne ($Installed | Where-Object {
                $_.DisplayName -like $Desired.DisplayName -and $_.VersionIdentifier -eq $Desired.VersionNumber
            }))
}


Function Test-VisualCRedistributableInstalled {
    [CmdletBinding()]
    param (
        [ValidateSet(2012, 2013)]
        [int]
        $Year,

        [Parameter(Mandatory = $true)]
        [object]
        $Installed
    )

    $desired = Get-VisualCRedistributableInfo $Year
    Test-VisualCRedistributableDesiredVersionInstalled $Installed $desired
}

Function Test-VisualCRedistributableUpToDate {
    [CmdletBinding()]
    param (
        [ValidateSet(2012, 2013)]
        [int]
        $Year,

        [Parameter(Mandatory = $true)]
        [object]
        $Installed
    )

    $desired = Get-VisualCRedistributableInfo $Year
    Test-VisualCRedistributableDesiredVersionUpToDate $Installed $desired
}
