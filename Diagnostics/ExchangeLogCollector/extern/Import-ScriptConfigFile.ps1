# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Import-ScriptConfigFile/Import-ScriptConfigFile.ps1
#v21.02.07.1240
Function Import-ScriptConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [string]$ScriptConfigFileLocation
    )
    #Function Version #v21.02.07.1240

    Write-VerboseWriter("Calling: Import-ScriptConfigFile")
    Write-VerboseWriter("Passed: [string]ScriptConfigFileLocation: '$ScriptConfigFileLocation'")

    if (!(Test-Path $ScriptConfigFileLocation)) {
        throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid ScriptConfigFileLocation"
    }

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
            Write-VerboseWriter("Adding variable $($_.Name)")
            Set-Variable -Name $_.Name -Value ($jsonContent.$($_.Name)) -Scope Script
        }
}
