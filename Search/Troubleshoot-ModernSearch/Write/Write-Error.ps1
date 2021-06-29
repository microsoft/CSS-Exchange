# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Write-LogInformation.ps1
Function Write-Error {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Error')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )
    process {
        Write-LogInformation "Error - $Message"
        Microsoft.PowerShell.Utility\Write-Error $Message
    }
}
