# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectHandler.ps1
Function Get-ServerOperatingSystemVersion {
    [CmdletBinding()]
    [OutputType("System.String")]
    param(
        [string]$OsCaption
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $osReturnValue = [string]::Empty
    }
    process {
        if ([string]::IsNullOrEmpty($OsCaption)) {
            Write-Verbose "Getting the local machine version build number"
            $OsCaption = (Get-WmiObjectHandler -Class "Win32_OperatingSystem").Caption
        }
        Write-Verbose "OsCaption: '$OsCaption'"

        switch -Wildcard ($OsCaption) {
            "*Server 2008 R2*" { $osReturnValue = "Windows2008R2"; break }
            "*Server 2008*" { $osReturnValue = "Windows2008" }
            "*Server 2012 R2*" { $osReturnValue = "Windows2012R2"; break }
            "*Server 2012*" { $osReturnValue = "Windows2012" }
            "*Server 2016*" { $osReturnValue = "Windows2016" }
            "*Server 2019*" { $osReturnValue = "Windows2019" }
            "Microsoft Windows Server Standard" { $osReturnValue = "WindowsCore" }
            "Microsoft Windows Server Datacenter" { $osReturnValue = "WindowsCore" }
            default { $osReturnValue = "Unknown" }
        }
    }
    end {
        Write-Verbose "Returned: '$osReturnValue'"
        return [string]$osReturnValue
    }
}
