# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        [ref]$Result,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnAsList
    )
    begin {
        $nonLoggingInfo = New-Object System.Collections.Generic.List[object]
    }
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($null -ne $type -and
                $type.GetType().Name -ne "PSMethod" -and
                $type -match "Verbose|Progress|Host") {
                #place it back onto the pipeline
                $instance
            } else {
                $nonLoggingInfo.Add($instance)
            }
        }
    }
    end {
        # If only a single result, return that vs a list unless requested by ReturnAsList.
        if ($nonLoggingInfo.Count -eq 1 -and $ReturnAsList) {
            $Result.Value = $nonLoggingInfo
        } elseif ($nonLoggingInfo.Count -eq 1) {
            $Result.Value = $nonLoggingInfo[0]
        } elseif ($nonLoggingInfo.Count -eq 0) {
            $Result.Value = $null
        } else {
            $Result.Value = $nonLoggingInfo
        }
    }
}
