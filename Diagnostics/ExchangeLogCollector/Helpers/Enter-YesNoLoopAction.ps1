# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Enter-YesNoLoopAction {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Question,

        [Parameter(Mandatory = $false)]
        [string]$Target = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$YesAction,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$NoAction
    )

    Write-Verbose "Calling: Enter-YesNoLoopAction"
    Write-Verbose "Passed: [string]Question: $Question"

    if ($PSCmdlet.ShouldProcess($Target, $Question)) {
        & $YesAction
    } else {
        & $NoAction
    }
}
