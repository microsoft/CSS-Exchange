# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
function Get-ExchangeApplicationConfigurationFileValidation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [string[]]$ConfigFileLocation
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $results = @{}
    $ConfigFileLocation |
        ForEach-Object {
            $obj = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlockDescription "Getting Exchange Application Configuration File Validation" `
                -CatchActionFunction ${Function:Invoke-CatchActions} `
                -ScriptBlock {
                param($Location)
                return [PSCustomObject]@{
                    Present  = ((Test-Path $Location))
                    FileName = ([IO.Path]::GetFileName($Location))
                    FilePath = $Location
                }
            } -ArgumentList $_
            $results.Add($obj.FileName, $obj)
        }
    return $results
}
