Function Get-DAGInformation {

    $dagName = Get-ExchangeServerDAGName -Server $env:COMPUTERNAME #only going to get the local server's DAG info
    if($dagName -ne $null)
    {
        $dagObj = New-Object PSCustomObject
        $value = Get-DatabaseAvailabilityGroup $dagName -Status 
        $dagObj | Add-Member -MemberType NoteProperty -Name DAGInfo -Value $value 
        $value = Get-DatabaseAvailabilityGroupNetwork $dagName 
        $dagObj | Add-Member -MemberType NoteProperty -Name DAGNetworkInfo -Value $value
        $dagObj | Add-Member -MemberType NoteProperty -Name AllMdbs -Value (Get-MailboxDatabaseInformationFromDAG -DAGInfo $dagObj.DAGInfo)
        return $dagObj
    }
}