# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\IISManagement\New-IISConfigurationAction.ps1
. $PSScriptRoot\..\..\IISManagement\Invoke-IISConfigurationManagerAction.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-DisableExtendedProtection {
    [CmdletBinding()]
    param(
        [string[]]$ExchangeServers
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $counter = 0
        $totalCount = $ExchangeServers.Count
        $failedServers = New-Object 'System.Collections.Generic.List[string]'
        $updatedServers = New-Object 'System.Collections.Generic.List[string]'
        $iisConfigurationManagements = New-Object System.Collections.Generic.List[object]
        $progressParams = @{
            Id              = 1
            Activity        = "Disabling Extended Protection"
            Status          = [string]::Empty
            PercentComplete = 0
        }
    }
    process {
        <#
            We need to loop through each of the servers and set extended protection to None for each virtual directory for exchange that we did set.
            This list of virtual directories for exchange will be managed within Get-ExtendedProtectionConfiguration.
            To avoid a second list here of the names of vDirs, we will call Get-ExtendedProtectionConfiguration for each server prior to setting EP to none.
            This will result in a few calls to that server, but rather do that then have a double list of vDirs that we want to manage.
        #>

        foreach ($server in $ExchangeServers) {
            $counter++
            $baseStatus = "Processing: $($server) -"
            $progressParams.Status = "$baseStatus Gathering Information"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            Write-Progress @progressParams

            $serverExtendedProtection = Get-ExtendedProtectionConfiguration -ComputerName $server

            if (-not ($serverExtendedProtection.ServerConnected)) {
                Write-Warning "$($server): Server not online. Unable to execute remotely."
                $failedServers.Add($server)
                continue
            }

            if ($serverExtendedProtection.ExtendedProtectionConfiguration.Count -eq 0) {
                Write-Warning "$($server): Server wasn't able to collect Extended Protection configuration."
                $failedServers.Add($server)
                continue
            }

            #$iisConfigurationManagement = New-IISConfigurationManager -ServerName $server
            $actionList = New-Object System.Collections.Generic.List[object]

            foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
                Write-Verbose "$($server): Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection)"
                $actionList.Add((New-IISConfigurationAction -Action ([PSCustomObject]@{
                                Cmdlet     = "Set-WebConfigurationProperty"
                                Parameters = @{
                                    Filter   = "system.WebServer/security/authentication/windowsAuthentication"
                                    Name     = "extendedProtection.tokenChecking"
                                    Value    = "None"
                                    PSPath   = "IIS:\"
                                    Location = $virtualDirectory.VirtualDirectoryName
                                }
                            })))
            }
            $iisConfigurationManagements.Add([PSCustomObject]@{
                    ServerName = $server
                    Actions    = $actionList
                })
        }
        Invoke-IISConfigurationManagerAction $iisConfigurationManagements -ConfigurationDescription "Disable Extended Protection"
    }
    end {
        Write-Progress @progressParams -Completed
        Write-Host

        if ($failedServers.Count -gt 0) {
            Write-Warning "Failed to disable Extended Protection: $([string]::Join(", ", $failedServers))"
        }

        if ($updatedServers.Count -gt 0) {
            Write-Host "Successfully disabled Extended Protection: $([string]::Join(",", $updatedServers))"
        }
    }
}
