Function  Save-LogmanExperfwizData {

    $PassedInfo.ExperfwizLogmanName |
        ForEach-Object {
            Get-LogmanData -LogmanName $_ -ServerName $env:COMPUTERNAME
        }
}
