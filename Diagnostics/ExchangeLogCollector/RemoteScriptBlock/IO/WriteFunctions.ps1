# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Small set of functions that are used to help override the Write-Host and Write-Verbose functions
function Get-ManipulateWriteHostValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {
        return "[$env:COMPUTERNAME] : $Message"
    }
}

function Get-ManipulateWriteVerboseValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {
        return "[$env:COMPUTERNAME - Script Debug] : $Message"
    }
}

#Calls the $Script:Logger object to write the data to file only.
function Write-DebugLog($message) {
    if ($null -ne $message -and
        ![string]::IsNullOrEmpty($message) -and
        $null -ne $Script:Logger) {
        $Script:Logger = $Script:Logger | Write-LoggerInstance $message
    }
}
