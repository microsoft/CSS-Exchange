# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Collection of functions that handles how to properly add
    Write-Verbose, Write-Host, Write-Progress to the pipeline as an object for logging, and how to pull them off it.
#>
function New-RemoteLoggingPipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [object]$Object,
        [ValidateSet("Verbose", "Host", "Progress")]
        [string]$Type
    )
    process {
        [PSCustomObject]@{
            RemoteLoggingValue = $Object
            RemoteLoggingType  = $Type
        }
    }
}

<#
    TODO
    This might need to be removed. If it does, just remove it. Otherwise, I need to update this comment section.
#>
function Get-RemotePipelineNonLoggingObject {
    [CmdletBinding()]
    param(
        [object[]]$Object
    )
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($type -match "Verbose|Progress|Host") {
                continue
            }

            $instance
        }
    }
}

<#
    After calling the remote script block, you need to the log the information locally.
    This loops through all the logging objects that was returned, then log everything with Write-Verbose.
    Then proceeds to place the other returned objects back onto the pipeline to be handled.
#>
function Invoke-RemotePipelineLoggingLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$Object
    )
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($type -match "Verbose|Host|Progress") {
                # Follow the process for logging locally with Write-Verbose for everything.
                # These values should have been manipulated already.
                # TODO: Verify if we should revert local manipulation or not.
                Write-Verbose $instance.RemoteLoggingValue
            } else {
                # Place the other object back onto the pipeline to be handled.
                $instance
            }
        }
    }
}

<#
    This function is used for when you are in a remote context to still be able to have
    debug logging within a secondary function that you just called and returning a object from that function.
    This then prevents all the objects from New-RemoteLoggingPipelineObject to also be stored in your variable.
#>
function Invoke-RemotePipelineHandler {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object[]]$Object,

        [Parameter(Mandatory = $true)]
        [ref]$Result
    )
    process {
        $nonLoggingInfo = New-Object System.Collections.Generic.List[object]
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($type -match "Verbose|Progress|Host") {
                #place it back onto the pipeline
                $instance
            } else {
                $nonLoggingInfo.Add($instance)
            }
        }
        $Result.Value = $nonLoggingInfo
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
        New-RemoteLoggingPipelineObject $Message "Verbose"
    }
}

function New-RemoteHostPipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [object]$Object
    )
    process {
        New-RemoteLoggingPipelineObject $Object "Host"
    }
}

function New-RemoteProgressPipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [object]$Object
    )
    process {
        New-RemoteLoggingPipelineObject $Object "Progress"
    }
}
