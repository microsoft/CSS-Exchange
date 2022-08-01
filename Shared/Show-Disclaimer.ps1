# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Show-Disclaimer {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [ValidateNotNullOrEmpty()]
        [string]$Headline
    )

    if ($PSCmdlet.ShouldProcess('MESSAGE', $Message, $Headline)) {
        return
    } else {
        exit
    }
}
