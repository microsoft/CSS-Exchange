# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function New-PipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Caller knows that this is an action')]
    [CmdletBinding()]
    param(
        [object]$Object,
        [string]$Type
    )
    process {
        return [PSCustomObject]@{
            Object = $Object
            Type   = $Type
        }
    }
}

Function Invoke-PipelineHandler {
    [CmdletBinding()]
    param(
        [object[]]$Object
    )
    process {
        foreach ($instance in $Object) {
            if ($instance.Type -eq "Verbose") {
                Write-Verbose $instance.Object
            } elseif ($instance.Type -eq "Host") {
                Write-Host $instance.Object
            } else {
                return $instance
            }
        }
    }
}

Function New-VerbosePipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Caller knows that this is an action')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [string]$Message
    )
    process {
        New-PipelineObject $Message "Verbose"
    }
}
