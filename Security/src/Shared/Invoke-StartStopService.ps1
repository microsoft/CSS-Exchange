# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
This is used to start or stop services locally on the server. It will return a value of $true if we do not hit an exception.
If an exception does occur, a throw will occur so the caller needs to handle this.
#>
function Invoke-StartStopService {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServiceName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Start", "Stop")]
        [string]$Action
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        try {
            if ($Action -eq "Stop") {
                Write-Verbose "Stopping Services: $([string]::Join(", ", $ServiceName))"
                foreach ($name in $ServiceName) {
                    Stop-Service -Name $name -Force -ErrorAction Stop
                }
            } else {
                Write-Verbose "Starting Services: $([string]::Join(", ", $ServiceName))"
                foreach ($name in $ServiceName) {
                    Start-Service -Name $name -ErrorAction Stop
                }
            }
        } catch {
            Write-Verbose "Unable able to perform $Action action on the server. Inner Exception $_"
            # caller should be handling the exceptions that are occurring. So we should throw if we run into an issue.
            throw
        }

        return $true
    }
}
