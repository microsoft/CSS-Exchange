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
        [scriptblock]$YesAction,

        [Parameter(Mandatory = $true)]
        [scriptblock]$NoAction
    )

    Write-Verbose "Calling: Enter-YesNoLoopAction"
    Write-Verbose "Passed: [string]Question: $Question"

    if ($PSCmdlet.ShouldProcess($Target, $Question)) {
        & $YesAction
    } else {
        & $NoAction
    }
}
