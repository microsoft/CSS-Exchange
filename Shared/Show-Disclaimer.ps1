# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Show-Disclaimer {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [ValidateNotNullOrEmpty()]
        [string]$Target,
        [ValidateNotNullOrEmpty()]
        [string]$Operation
    )

    if ($PSCmdlet.ShouldProcess($Message, $Target, $Operation) -or
        $WhatIfPreference) {
        return
    } else {
        exit
    }
}
