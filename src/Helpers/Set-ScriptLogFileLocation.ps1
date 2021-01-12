Function Set-ScriptLogFileLocation {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $false)][bool]$IncludeServerName = $false
    )
    $endName = "-{0}.txt" -f $dateTimeStringFormat

    if ($IncludeServerName) {
        $endName = "-{0}{1}" -f $Script:Server, $endName
    }

    $Script:OutputFullPath = "{0}\{1}{2}" -f $OutputFilePath, $FileName, $endName
    $Script:OutXmlFullPath = $Script:OutputFullPath.Replace(".txt", ".xml")

    if ($AnalyzeDataOnly -or
        $BuildHtmlServersReport) {
        return
    }

    if (!(Confirm-ExchangeShell -CatchActionFunction ${Function:Invoke-CatchActions} )) {
        Write-Yellow("Failed to load Exchange Shell... stopping script")
        exit
    }
}