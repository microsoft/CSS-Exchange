# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
<#
Unknown 0
Failed to get Install Setting 1
Install is set to true 2
Install is set to false 4
Failed to get Block Setting 8
SMB1 is not being blocked 16
SMB1 is being blocked 32
#>
Function Get-Smb1ServerSettings {
    [CmdletBinding()]
    param(
        [string]$ServerName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $smb1Status = 0
    }
    process {
        $smbServerConfiguration = Invoke-ScriptBlockHandler -ComputerName $ServerName `
            -ScriptBlock { Get-SmbServerConfiguration } `
            -CatchActionFunction $CatchActionFunction `
            -ScriptBlockDescription "Get-SmbServerConfiguration"

        try {
            $windowsFeature = Get-WindowsFeature "FS-SMB1" -ComputerName $ServerName -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to Get-WindowsFeature for FS-SMB1"
            Invoke-CatchActionError $CatchActionFunction
        }

        if ($null -eq $windowsFeature) {
            $smb1Status += 1
        } elseif ($windowsFeature.Installed) {
            $smb1Status += 2
        } else {
            $smb1Status += 4
        }

        if ($null -eq $smbServerConfiguration) {
            $smb1Status += 8
        } elseif ($smbServerConfiguration.EnableSMB1Protocol) {
            $smb1Status += 16
        } else {
            $smb1Status += 32
        }
    }
    end {
        return [PSCustomObject]@{
            SmbServerConfiguration = $smbServerConfiguration
            WindowsFeature         = $windowsFeature
            Smb1Status             = $smb1Status
        }
    }
}
