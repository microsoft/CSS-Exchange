#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/ExchangeInformation/Get-ExchangeMajorVersion/Get-ExchangeMajorVersion.ps1
#v21.01.08.2133
Function Get-ExchangeMajorVersion {
    [CmdletBinding()]
    [OutputType("System.String")]
    param(
        [Parameter(Mandatory = $true)][object]$AdminDisplayVersion
    )
    #Function Version #v21.01.08.2133

    Write-VerboseWriter("Calling: Get-ExchangeMajorVersion")
    Write-VerboseWriter("Passed: {0}" -f $AdminDisplayVersion.ToString())
    if ($AdminDisplayVersion.GetType().Name -eq "string") {
        $split = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).split('.')
        $build = [int]$split[0] + ($split[1] / 10)
    } else {
        $build = $AdminDisplayVersion.Major + ($AdminDisplayVersion.Minor / 10)
    }
    Write-VerboseWriter("Determing build based off of: {0}" -f $build)
    $exchangeVersion = [string]::Empty
    switch ($build) {
        14.3 { $exchangeVersion = "Exchange2010" }
        15 { $exchangeVersion = "Exchange2013" }
        15.1 { $exchangeVersion = "Exchange2016" }
        15.2 { $exchangeVersion = "Exchange2019" }
        default { $exchangeVersion = "Unknown" }
    }
    Write-VerboseWriter("Returned: {0}" -f $exchangeVersion)
    return $exchangeVersion
}
