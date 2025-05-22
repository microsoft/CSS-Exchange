# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
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
    begin {
        $nonLoggingInfo = New-Object System.Collections.Generic.List[object]
    }
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($null -ne $type -and
                $type.GetType().Name -ne "PSMethod" -and
                $type -match "Verbose|Progress|Host|Warning") {
                #place it back onto the pipeline
                $instance
            } else {
                $nonLoggingInfo.Add($instance)
            }
        }
    }
    end {
        # If only a single result, return that vs a list
        if ($nonLoggingInfo.Count -eq 1) {
            $Result.Value = $nonLoggingInfo[0]
        } elseif ($nonLoggingInfo.Count -eq 0) {
            # Return null value because nothing is in the list.
            # If you still want to return an empty array here, use Invoke-RemotePipelineHandlerList
            $Result.Value = $null
        } else {
            $Result.Value = $nonLoggingInfo
        }
    }
}

<#
.DESCRIPTION
    This does the same as Invoke-RemotePipelineHandler but we will return an empty list and always return the results as a list.
#>
function Invoke-RemotePipelineHandlerList {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object[]]$Object,

        [Parameter(Mandatory = $true)]
        [ref]$Result
    )
    begin {
        $nonLoggingInfo = New-Object System.Collections.Generic.List[object]
    }
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($null -ne $type -and
                $type.GetType().Name -ne "PSMethod" -and
                $type -match "Verbose|Progress|Host|Warning") {
                #place it back onto the pipeline
                $instance
            } else {
                $nonLoggingInfo.Add($instance)
            }
        }
    }
    end {
        # This could be an empty list, up to the caller to determine this.
        $Result.Value = $nonLoggingInfo
    }
}
