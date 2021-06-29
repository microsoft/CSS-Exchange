# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Write-LogInformation.ps1
Function Write-Warning {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )
    process {
        Write-LogInformation "Warning - $Message"
        Microsoft.PowerShell.Utility\Write-Warning $Message
    }
}
