# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    Use this function to pass in a hashtable object that you were going to splat to a cmdlet.
    It will return a string value of the parameters that are going to be
     passed to the cmdlet as if you typed it out manually.
#>
function Get-ParameterString {
    [CmdletBinding()]
    param(
        [hashtable]$InputObject
    )
    process {
        $value = [string]::Empty

        foreach ($key in $InputObject.Keys) {
            $value += "-$key `"$($InputObject[$key])`" "
        }
        return $value.Trim()
    }
}
