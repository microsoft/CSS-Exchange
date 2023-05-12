# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-WmiObjectHandler.ps1
function Get-WmiObjectCriticalHandler {
    [CmdletBinding()]
    param(
        [string]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string]
        $Class,

        [string]
        $Filter,

        [string]
        $Namespace,

        [ScriptBlock]
        $CatchActionFunction
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $params = @{
        ComputerName        = $ComputerName
        Class               = $Class
        Filter              = $Filter
        Namespace           = $Namespace
        CatchActionFunction = $CatchActionFunction
    }

    $wmi = Get-WmiObjectHandler @params

    if ($null -eq $wmi) {
        # Check for common issues that have been seen. If common issue, Write-Warning the re-throw the error up.

        if ($Error[0].Exception.ErrorCode -eq 0x800703FA) {
            Write-Verbose "Registry key marked for deletion."
            $message = "A registry key is marked for deletion that was attempted to read from for the cmdlet 'Get-WmiObject -Class $Class'.`r`n"
            $message += "`tThis error goes away after some time and/or a reboot of the computer. At that time you should be able to run Health Checker again."
            Write-Warning $message
        }

        # Grab the English version of hte message and/or the error code. Could get a different error code if service is not disabled.
        if ($Error[0].Exception.Message -like "The service cannot be started, either because it is disabled or because it has no enabled devices associated with it. *" -or
            $Error[0].Exception.ErrorCode -eq 0x80070422) {
            Write-Verbose "winMgmt service is disabled or not working."
            Write-Warning "The 'winMgmt' service appears to not be working correctly. Please make sure it is set to Automatic and in a running state. This script will fail unless this is working correctly."
        }

        Write-Error $($Error[0]) -ErrorAction Stop
    }

    return $wmi
}
