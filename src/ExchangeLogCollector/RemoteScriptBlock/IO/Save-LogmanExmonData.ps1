Function Save-LogmanExmonData {
    Get-LogmanData -LogmanName $PassedInfo.ExmonLogmanName -ServerName $env:COMPUTERNAME
}