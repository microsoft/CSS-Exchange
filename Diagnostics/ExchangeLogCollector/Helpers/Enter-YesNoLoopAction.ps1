# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Enter-YesNoLoopAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Question,
        [Parameter(Mandatory = $true)][scriptblock]$YesAction,
        [Parameter(Mandatory = $true)][scriptblock]$NoAction
    )

    Write-Verbose "Calling: Enter-YesNoLoopAction"
    Write-Verbose "Passed: [string]Question: $Question"

    do {
        $answer = Read-Host ("{0} ('y' or 'n')" -f $Question)
        Write-Verbose "Read-Host answer: $answer"
    }while ($answer -ne 'n' -and $answer -ne 'y')

    if ($answer -eq 'y') {
        &$YesAction
    } else {
        &$NoAction
    }
}
