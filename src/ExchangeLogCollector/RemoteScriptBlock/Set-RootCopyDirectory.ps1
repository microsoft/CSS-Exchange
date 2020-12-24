Function Set-RootCopyDirectory {
    if ($Script:RootFilePath -eq $null) {
        $stringValue = $PassedInfo.RootFilePath
    } else {
        $stringValue = $Script:RootFilePath    
    }
    $str = "{0}{1}" -f $stringValue, $env:COMPUTERNAME
    return $str
}
