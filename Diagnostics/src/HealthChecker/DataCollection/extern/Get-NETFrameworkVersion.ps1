#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-NETFrameworkVersion/Get-NETFrameworkVersion.ps1
#v21.01.22.2234
Function Get-NETFrameworkVersion {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [int]$NetVersionKey = -1,
        [scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Get-NETFrameworkVersion")
    if ($NetVersionKey -eq -1) {
        [int]$NetVersionKey = Invoke-RegistryGetValue -MachineName $MachineName `
            -SubKey "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" `
            -GetValue "Release" `
            -CatchActionFunction $CatchActionFunction
    }

    #Using Minimum Version as per https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed?redirectedfrom=MSDN#minimum-version
    if ($NetVersionKey -lt 378389) {
        $friendlyName = "Unknown"
        $minValue = -1
    } elseif ($NetVersionKey -lt 378675) {
        $friendlyName = "4.5"
        $minValue = 378389
    } elseif ($NetVersionKey -lt 379893) {
        $friendlyName = "4.5.1"
        $minValue = 378675
    } elseif ($NetVersionKey -lt 393295) {
        $friendlyName = "4.5.2"
        $minValue = 379893
    } elseif ($NetVersionKey -lt 394254) {
        $friendlyName = "4.6"
        $minValue = 393295
    } elseif ($NetVersionKey -lt 394802) {
        $friendlyName = "4.6.1"
        $minValue = 394254
    } elseif ($NetVersionKey -lt 460798) {
        $friendlyName = "4.6.2"
        $minValue = 394802
    } elseif ($NetVersionKey -lt 461308) {
        $friendlyName = "4.7"
        $minValue = 460798
    } elseif ($NetVersionKey -lt 461808) {
        $friendlyName = "4.7.1"
        $minValue = 461308
    } elseif ($NetVersionKey -lt 528040) {
        $friendlyName = "4.7.2"
        $minValue = 461808
    } elseif ($NetVersionKey -ge 528040) {
        $friendlyName = "4.8"
        $minValue = 528040
    }

    $netObject = New-Object PSCustomObject
    $netObject | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $friendlyName
    $netObject | Add-Member -MemberType NoteProperty -Name "RegistryValue" -Value $NetVersionKey
    $netObject | Add-Member -MemberType NoteProperty -Name "MinimumValue" -Value $minValue

    Write-VerboseWriter("Returning FriendlyName: {0} | RegistryValue: {1}" -f $friendlyName, $NetVersionKey)

    return $netObject
}
