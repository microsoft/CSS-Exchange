# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-Error {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Error from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = 1, ValueFromPipeline)]
        [string]$Message
    )
    process {

        if ($null -ne $Script:WriteErrorManipulateMessageAction) {
            $Message = & $Script:WriteErrorManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Error $Message

        # Add ERROR to beginning of the message by default.
        $Message = "ERROR: $Message"

        if ($null -ne $Script:WriteErrorDebugAction) {
            & $Script:WriteErrorDebugAction $Message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteErrorDebugAction) {
            & $Script:WriteRemoteErrorDebugAction $Message
        }
    }
}

function SetWriteErrorAction ($DebugAction) {
    $Script:WriteErrorDebugAction = $DebugAction
}

function SetWriteRemoteErrorAction ($DebugAction) {
    $Script:WriteRemoteErrorDebugAction = $DebugAction
}

function SetWriteErrorManipulateMessageAction ($DebugAction) {
    $Script:WriteErrorManipulateMessageAction = $DebugAction
}
