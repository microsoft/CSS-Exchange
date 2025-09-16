# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Collection of functions that handles how to properly add
    Write-Verbose, Write-Host, Write-Progress, Write-Warning, Write-Error to the pipeline as an object for logging, and how to pull them off it.
#>
function New-RemoteLoggingPipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [object]$Object,
        [ValidateSet("Verbose", "Host", "Progress", "Warning", "Error")]
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
    begin {
        # Store everything into a list so we can just write it to the log once and makes it easier for log review.
        $logToVerbose = New-Object System.Collections.Generic.List[string]
        $logToVerbose.Add("")
        $logToVerbose.Add("")
        $logToVerbose.Add("------------------- Remote Pipeline Logging -------------------------")
    }
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($type -match "Verbose|Host|Progress|Warning|Error") {
                # Follow the process for logging locally with Write-Verbose for everything.
                # These values should have been manipulated already.
                $logToVerbose.Add(($instance.RemoteLoggingValue))
            } else {
                # Place the other object back onto the pipeline to be handled.
                $instance
            }
        }
    }
    end {
        $logToVerbose.Add("----------------- End Remote Pipeline Logging -----------------------")
        $logToVerbose | Out-String | Write-Verbose
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

function New-RemoteWarningPipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [string]$Message
    )
    process {
        New-RemoteLoggingPipelineObject $Message "Warning"
    }
}

function New-RemoteErrorPipelineObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [string]$Message
    )
    process {
        New-RemoteLoggingPipelineObject $Message "Error"
    }
}
