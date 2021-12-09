# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ExchangeInformation/Get-ExchangeInstallDirectory/Get-ExchangeInstallDirectory.ps1
#v21.01.22.2234
Function Get-ExchangeInstallDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Different types returned')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][bool]$InvokeCommandReturnWriteArray
    )
    #Function Version #v21.01.22.2234

    $stringArray = @()
    Write-InvokeCommandReturnVerboseWriter("Calling: Get-ExchangeInstallDirectory")
    Write-InvokeCommandReturnVerboseWriter("Passed: [bool]InvokeCommandReturnWriteArray: {0}" -f $InvokeCommandReturnWriteArray)

    $installDirectory = [string]::Empty
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup') {
        Write-InvokeCommandReturnVerboseWriter("Detected v14")
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath
    } elseif (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup') {
        Write-InvokeCommandReturnVerboseWriter("Detected v15")
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
    } else {
        Write-InvokeCommandReturnHostWriter -WriteString ("Something went wrong trying to find Exchange Install path on this server: {0}" -f $env:COMPUTERNAME)
    }
    Write-InvokeCommandReturnVerboseWriter("Returning: {0}" -f $installDirectory)
    if ($InvokeCommandReturnWriteArray) {
        $hashTable = @{"ReturnObject" = $installDirectory }
        $stringArray += $hashTable
        return $stringArray
    }
    return $installDirectory
}
