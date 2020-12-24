Function  Save-LogmanExperfwizData {
    Get-LogmanData -LogmanName $PassedInfo.ExperfwizLogmanName -ServerName $env:COMPUTERNAME
}