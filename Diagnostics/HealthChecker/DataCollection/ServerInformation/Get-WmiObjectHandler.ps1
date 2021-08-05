# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-WmiObjectHandler {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'This is what this function is for')]
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

        [scriptblock]
        $CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - ComputerName: '$ComputerName' | Class: '$Class' | Filter: '$Filter' | Namespace: '$Namespace'"

        $execute = @{
            ComputerName = $ComputerName
            Class        = $Class
        }

        if (-not ([string]::IsNullOrEmpty($Filter))) {
            $execute.Add("Filter", $Filter)
        }

        if (-not ([string]::IsNullOrEmpty($Namespace))) {
            $execute.Add("Namespace", $Namespace)
        }
    }
    process {
        try {
            $wmi = Get-WmiObject @execute -ErrorAction Stop
            return $wmi
        } catch {
            Write-Verbose "Failed to run Get-WmiObject on class '$class'"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }
        }
    }
}
