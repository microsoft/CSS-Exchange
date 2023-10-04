# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1

function Get-ExchangeVirtualDirectories {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $failedString = "Failed to get {0} virtual directory."
        $getActiveSyncVirtualDirectory = $null
        $getAutoDiscoverVirtualDirectory = $null
        $getEcpVirtualDirectory = $null
        $getMapiVirtualDirectory = $null
        $getOabVirtualDirectory = $null
        $getOutlookAnywhere = $null
        $getOwaVirtualDirectory = $null
        $getPowerShellVirtualDirectory = $null
        $getWebServicesVirtualDirectory = $null
        $paramsNoShow = @{
            Server           = $Server
            ErrorAction      = "Stop"
            ADPropertiesOnly = $true
        }
        $params = $paramsNoShow + @{
            ShowMailboxVirtualDirectories = $true
        }
    }
    process {
        try {
            $getActiveSyncVirtualDirectory = Get-ActiveSyncVirtualDirectory @params
        } catch {
            Write-Verbose ($failedString -f "EAS")
            Invoke-CatchActions
        }

        try {
            $getAutoDiscoverVirtualDirectory = Get-AutodiscoverVirtualDirectory @params
        } catch {
            Write-Verbose ($failedString -f "Autodiscover")
            Invoke-CatchActions
        }

        try {
            $getEcpVirtualDirectory = Get-EcpVirtualDirectory @params
        } catch {
            Write-Verbose ($failedString -f "ECP")
            Invoke-CatchActions
        }

        try {
            # Doesn't have ShowMailboxVirtualDirectories
            $getMapiVirtualDirectory = Get-MapiVirtualDirectory @paramsNoShow
        } catch {
            Write-Verbose ($failedString -f "Mapi")
            Invoke-CatchActions
        }

        try {
            $getOabVirtualDirectory = Get-OabVirtualDirectory @params
        } catch {
            Write-Verbose ($failedString -f "OAB")
            Invoke-CatchActions
        }

        try {
            $getOutlookAnywhere = Get-OutlookAnywhere @params
        } catch {
            Write-Verbose ($failedString -f "Outlook Anywhere")
            Invoke-CatchActions
        }

        try {
            $getOwaVirtualDirectory = Get-OwaVirtualDirectory @params
        } catch {
            Write-Verbose ($failedString -f "OWA")
            Invoke-CatchActions
        }

        try {
            $getPowerShellVirtualDirectory = Get-PowerShellVirtualDirectory @params
        } catch {
            Write-Verbose ($failedString -f "PowerShell")
            Invoke-CatchActions
        }

        try {
            $getWebServicesVirtualDirectory = Get-WebServicesVirtualDirectory @params
        } catch {
            Write-Verbose ($failedString -f "EWS")
            Invoke-CatchActions
        }
    }
    end {
        return [PSCustomObject]@{
            GetActiveSyncVirtualDirectory   = $getActiveSyncVirtualDirectory
            GetAutoDiscoverVirtualDirectory = $getAutoDiscoverVirtualDirectory
            GetEcpVirtualDirectory          = $getEcpVirtualDirectory
            GetMapiVirtualDirectory         = $getMapiVirtualDirectory
            GetOabVirtualDirectory          = $getOabVirtualDirectory
            GetOutlookAnywhere              = $getOutlookAnywhere
            GetOwaVirtualDirectory          = $getOwaVirtualDirectory
            GetPowerShellVirtualDirectory   = $getPowerShellVirtualDirectory
            GetWebServicesVirtualDirectory  = $getWebServicesVirtualDirectory
        }
    }
}
