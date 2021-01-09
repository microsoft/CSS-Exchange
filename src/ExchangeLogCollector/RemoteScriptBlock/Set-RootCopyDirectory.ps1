Function Set-RootCopyDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Function name fits')]
    param()
    if ($null -eq $Script:RootFilePath) {
        $stringValue = $PassedInfo.RootFilePath
    } else {
        $stringValue = $Script:RootFilePath
    }
    $str = "{0}{1}" -f $stringValue, $env:COMPUTERNAME
    return $str
}
