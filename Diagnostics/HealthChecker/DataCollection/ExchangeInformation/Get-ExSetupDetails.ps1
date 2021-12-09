# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-ExSetupDetails {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exSetupDetails = [string]::Empty
    Function Get-ExSetupDetailsScriptBlock {
        Get-Command ExSetup | ForEach-Object { $_.FileVersionInfo }
    }

    $exSetupDetails = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-ExSetupDetailsScriptBlock} -ScriptBlockDescription "Getting ExSetup remotely" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $exSetupDetails
}
