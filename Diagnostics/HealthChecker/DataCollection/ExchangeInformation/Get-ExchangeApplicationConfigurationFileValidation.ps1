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

            $params = @{
                ComputerName           = $ComputerName
                ScriptBlockDescription = "Getting Exchange Application Configuration File Validation"
                ArgumentList           = $_
                ScriptBlock            = {
                    param($Location)
                    return [PSCustomObject]@{
                        Present  = ((Test-Path $Location))
                        FileName = ([IO.Path]::GetFileName($Location))
                        FilePath = $Location
                        Content  = (Get-Content $Location -Raw)
                    }
                }
            }

            $obj = Invoke-ScriptBlockHandler @params
            $results.Add($obj.FileName, $obj)
        }
    return $results
}
