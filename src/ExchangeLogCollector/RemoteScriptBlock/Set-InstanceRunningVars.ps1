Function Set-InstanceRunningVars {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Function name fits')]
    param()

    #Set the local Server Object Information
    Get-ThisServerObject

    $Script:TotalBytesSizeCopied = 0
    $Script:TotalBytesSizeCompressed = 0
    $Script:AdditionalFreeSpaceCushionGB = $PassedInfo.StandardFreeSpaceInGBCheckSize
    $Script:CurrentFreeSpaceGB = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
    $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:CurrentFreeSpaceGB
    $Script:localExinstall = Get-ExchangeInstallDirectory
    #shortcut to Exbin directory (probably not really needed)
    $Script:localExBin = $Script:localExinstall + "Bin\"
}