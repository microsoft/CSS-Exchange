# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
function Get-ServerOperatingSystemVersion {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,

        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $osReturnValue = [string]::Empty
        $baseParams = @{
            MachineName         = $ComputerName
            CatchActionFunction = $CatchActionFunction
        }

        # Get ProductName via registry call as this is more accurate when running on Server Core
        $productNameParams = $baseParams + @{
            SubKey   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            GetValue = "ProductName"
        }

        # Find out if we're running on Server Core to output on the 'Operating System Information' page
        $installationTypeParams = $baseParams + @{
            SubKey   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            GetValue = "InstallationType"
        }
    }
    process {
        Write-Verbose "Getting the version build information for computer: $ComputerName"
        $osCaption = Get-RemoteRegistryValue @productNameParams
        $installationType = Get-RemoteRegistryValue @installationTypeParams
        Write-Verbose "OsCaption: '$osCaption' InstallationType: '$installationType'"

        switch -Wildcard ($osCaption) {
            "*Server 2008 R2*" { $osReturnValue = "Windows2008R2"; break }
            "*Server 2008*" { $osReturnValue = "Windows2008" }
            "*Server 2012 R2*" { $osReturnValue = "Windows2012R2"; break }
            "*Server 2012*" { $osReturnValue = "Windows2012" }
            "*Server 2016*" { $osReturnValue = "Windows2016" }
            "*Server 2019*" { $osReturnValue = "Windows2019" }
            "*Server 2022*" { $osReturnValue = "Windows2022" }
            default { $osReturnValue = "Unknown" }
        }
    }
    end {
        Write-Verbose "OsReturnValue: '$osReturnValue'"
        return [PSCustomObject]@{
            MajorVersion     = $osReturnValue
            InstallationType = $installationType
            FriendlyName     = if ($installationType -eq "Server Core") { "$osCaption ($installationType)" } else { $osCaption }
        }
    }
}
