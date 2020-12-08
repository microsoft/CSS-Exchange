#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ExchangeMajorVersion/Get-ExchangeMajorVersion.ps1
Function Get-ExchangeMajorVersion {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][object]$AdminDisplayVersion 
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Get-ExchangeMajorVersion")
    Write-VerboseWriter("Passed: {0}" -f $AdminDisplayVersion.ToString())
    if($AdminDisplayVersion.GetType().Name -eq "string")
    {
        $split = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).split('.')
        $build = [int]$split[0] + ($split[1] / 10)
    }
    else 
    {
        $build = $AdminDisplayVersion.Major + ($AdminDisplayVersion.Minor / 10)
    }
    Write-VerboseWriter("Determing build based off of: {0}" -f $build)
    $exchangeMajorVersion = [string]::Empty
    switch($build)
    {
        14.3 {$exchangeMajorVersion = "Exchange2010"}
        15 {$exchangeMajorVersion = "Exchange2013"}
        15.1 {$exchangeMajorVersion = "Exchange2016"}
        15.2 {$exchangeMajorVersion = "Exchange2019"}
        default {$exchangeMajorVersion = "Unknown"}
    }
    Write-VerboseWriter("Returned: {0}" -f $exchangeMajorVersion)
    return $exchangeMajorVersion 
}