# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Enter-YesNoLoopAction/Enter-YesNoLoopAction.ps1
#v21.01.22.2234
Function Enter-YesNoLoopAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Question,
        [Parameter(Mandatory = $true)][scriptblock]$YesAction,
        [Parameter(Mandatory = $true)][scriptblock]$NoAction
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Enter-YesNoLoopAction")
    Write-VerboseWriter("Passed: [string]Question: {0}" -f $Question)

    do {
        $answer = Read-Host ("{0} ('y' or 'n')" -f $Question)
        Write-VerboseWriter("Read-Host answer: {0}" -f $answer)
    }while ($answer -ne 'n' -and $answer -ne 'y')

    if ($answer -eq 'y') {
        &$YesAction
    } else {
        &$NoAction
    }
}
