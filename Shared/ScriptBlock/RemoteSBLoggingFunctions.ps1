# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Collection of functions that handles how to properly add
    Write-Verbose, Write-Host, Write-Process to the pipeline as an object for logging, and how to pull them off it.
#>
function New-RemotePipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [object]$Object,
        [ValidateSet("Verbose", "Host", "Process")]
        [string]$Type
    )
    process {
        [PSCustomObject]@{
            RemoteLoggingValue = $Object
            RemoteLoggingType  = $Type
        }
    }
}

function Invoke-RemotePipelineHandler {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object[]]$Object
    )
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType
            $value = $instance.RemoteLoggingValue

            if ($type -eq "Verbose" -or
                $type -eq "Process") {
                Write-Verbose $value
            } elseif ($type -eq "Host") {
                Write-Host $value
            } else {
                $value
            }
        }
    }
}

function New-RemoteVerbosePipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [string]$Message
    )
    process {
        New-RemotePipelineObject $Message "Verbose"
    }
}
