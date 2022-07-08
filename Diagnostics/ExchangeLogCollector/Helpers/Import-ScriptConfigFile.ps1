# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Import-ScriptConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ScriptConfigFileLocation
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Passed: [string]ScriptConfigFileLocation: '$ScriptConfigFileLocation'"

    try {
        $content = Get-Content $ScriptConfigFileLocation -ErrorAction Stop
        $jsonContent = $content | ConvertFrom-Json
    } catch {
        throw "Failed to convert ScriptConfigFileLocation from a json type object."
    }

    $jsonContent |
        Get-Member |
        Where-Object { $_.Name -ne "Method" } |
        ForEach-Object {
            Write-Verbose "Adding variable $($_.Name)"
            Set-Variable -Name $_.Name -Value ($jsonContent.$($_.Name)) -Scope Script
        }
}
