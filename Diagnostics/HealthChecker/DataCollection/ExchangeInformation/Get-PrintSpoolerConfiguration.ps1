# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1

function Get-PrintSpoolerConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $ComputerName
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    if ([System.String]::IsNullOrEmpty($ComputerName)) {
        Write-Verbose "ComputerName was not set - calls will be executed against the local machine"
        $ComputerName = $env:COMPUTERNAME
    }
    Write-Verbose "Working on computer: $ComputerName"

    try {
        Write-Verbose "Trying to query print spooler service state on: $ComputerName"
        $spoolerServiceInfo = Get-Service -Name Spooler -ComputerName $ComputerName -ErrorAction Stop
        $spoolerStatus = ($spoolerServiceInfo.Status).ToString()
        $spoolerStartType = ($spoolerServiceInfo.StartType).ToString()
        Write-Verbose "Print spooler StartType: $spoolerStartType Print spooler Status: $spoolerStatus"

        return [PSCustomObject]@{
            SpoolerStatus       = $spoolerStatus
            SpoolerStartType    = $spoolerStartType
            SpoolerConfigSecure = (($spoolerStartType -eq "Disabled") -and ($spoolerStatus -eq "Stopped"))
        }
    } catch {
        Write-Verbose "Unable to query print spooler service status and start type"
        Invoke-CatchActions
        return $null
    }
}
