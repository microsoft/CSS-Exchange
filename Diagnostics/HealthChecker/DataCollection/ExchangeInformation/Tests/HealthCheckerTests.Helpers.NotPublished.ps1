# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function ConvertTimeToUtcHelper {
    [CmdletBinding()]
    [OutputType("System.DateTime")]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]
        $TimeToConvert
    )

    $invariantTime = [System.Convert]::ToDateTime($TimeToConvert, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)
    return $invariantTime.AddHours((Get-TimeZone).BaseUtcOffset.Hours)
}
