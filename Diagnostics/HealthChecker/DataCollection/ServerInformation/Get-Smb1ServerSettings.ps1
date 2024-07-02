# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
function Get-Smb1ServerSettings {
    [CmdletBinding()]
    param(
        [string]$ServerName = $env:COMPUTERNAME,
        [object[]]$GetWindowsFeature,
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $smbServerConfiguration = $null
        $windowsFeature = $null
    }
    process {
        $params = @{
            ComputerName           = $ServerName
            ScriptBlock            = { Get-SmbServerConfiguration -ErrorAction Stop }
            CatchActionFunction    = $CatchActionFunction
            ScriptBlockDescription = "Get-SmbServerConfiguration"
        }
        $smbServerConfiguration = Invoke-ScriptBlockHandler @params

        if ($null -ne $GetWindowsFeature -and
            $GetWindowsFeature.Count -gt 0) {
            $windowsFeature = $GetWindowsFeature | Where-Object { $_.Name -eq "FS-SMB1" }
        } else {
            try {
                Write-Verbose "Get-WindowsFeature results wasn't provided, need to manually find FS-SMB1"
                $windowsFeature = Get-WindowsFeature "FS-SMB1" -ComputerName $ServerName -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to Get-WindowsFeature for FS-SMB1"
                Invoke-CatchActionError $CatchActionFunction
            }
        }
    }
    end {
        return [PSCustomObject]@{
            SmbServerConfiguration = $smbServerConfiguration
            WindowsFeature         = $windowsFeature
            SuccessfulGetInstall   = $null -ne $windowsFeature
            SuccessfulGetBlocked   = $null -ne $smbServerConfiguration
            Installed              = $windowsFeature.Installed -eq $true
            IsBlocked              = $smbServerConfiguration.EnableSMB1Protocol -eq $false
        }
    }
}
