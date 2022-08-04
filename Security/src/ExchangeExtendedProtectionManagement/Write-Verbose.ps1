# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# TODO: Once on public, move Write-Verbose from ExchangeLogCollector to root Shared
function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {
        #write to the debug log and call Write-Verbose normally
        Write-VerboseLog $Message
        Microsoft.PowerShell.Utility\Write-Verbose $Message
    }
}
