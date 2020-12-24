#Template Master: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ExchangeInstallDirectory/Get-ExchangeInstallDirectory.ps1
Function Get-ExchangeInstallDirectory {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][bool]$InvokeCommandReturnWriteArray
    )
    
    #Function Version 1.2
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-InvokeCommandReturnVerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-InvokeCommandReturnHostWriter.ps1
    #>
    $stringArray = @()
    Write-InvokeCommandReturnVerboseWriter("Calling: Get-ExchangeInstallDirectory")
    Write-InvokeCommandReturnVerboseWriter("Passed: [bool]InvokeCommandReturnWriteArray: {0}" -f $InvokeCommandReturnWriteArray)
    
    $installDirectory = [string]::Empty
    if(Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup')
    {
        Write-InvokeCommandReturnVerboseWriter("Detected v14")
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath 
    }
    elseif(Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup')
    {
        Write-InvokeCommandReturnVerboseWriter("Detected v15")
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath	
    }
    else 
    {
        Write-InvokeCommandReturnHostWriter -WriteString ("Something went wrong trying to find Exchange Install path on this server: {0}" -f $env:COMPUTERNAME)  
    }
    Write-InvokeCommandReturnVerboseWriter("Returning: {0}" -f $installDirectory)
    if($InvokeCommandReturnWriteArray)
    {
        $hashTable = @{"ReturnObject"=$installDirectory}
        $stringArray += $hashTable
        return $stringArray
    }
    return $installDirectory
}