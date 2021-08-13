# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Proper handling of write host with colors')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [object]$Object,
        [switch]$NoNewLine,
        [string]$ForegroundColor
    )
    begin {
        $params = @{
            Object    = $Object
            NoNewLine = $NoNewLine
        }
    }
    process {

        if ([string]::IsNullOrEmpty($ForegroundColor)) {
            if ($null -ne $host.UI.RawUI.ForegroundColor) {
                $params.Add("ForegroundColor", $host.UI.RawUI.ForegroundColor)
            }
        } elseif ($ForegroundColor -eq "Yellow" -and
            $null -ne $host.PrivateData.WarningForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.WarningForegroundColor)
        } elseif ($ForegroundColor -eq "Red" -and
            $null -ne $host.PrivateData.ErrorForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.ErrorForegroundColor)
        } else {
            $params.Add("ForegroundColor", $ForegroundColor)
        }

        Microsoft.PowerShell.Utility\Write-Host @params
    }
}
