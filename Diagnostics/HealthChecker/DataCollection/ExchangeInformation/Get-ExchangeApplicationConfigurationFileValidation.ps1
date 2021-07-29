# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-ExchangeApplicationConfigurationFileValidation {
    param(
        [string[]]$ConfigFileLocation
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $results = @{}
    $ConfigFileLocation |
        ForEach-Object {
            $obj = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlockDescription "Getting Exchange Application Configuration File Validation" `
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
