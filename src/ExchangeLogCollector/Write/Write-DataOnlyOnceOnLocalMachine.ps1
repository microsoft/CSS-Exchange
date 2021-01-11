Function Write-DataOnlyOnceOnLocalMachine {
    Write-ScriptDebug("Enter Function: Write-DataOnlyOnceOnLocalMachine")
    Write-ScriptDebug("Writting only once data")

    $RootCopyToDirectory = Set-RootCopyDirectory

    if ($GetVdirs -and (-not($Script:EdgeRoleDetected))) {
        $target = $RootCopyToDirectory + "\ConfigNC_msExchVirtualDirectory_All.CSV"
        $data = (Get-VdirsLDAP)
        $data | Sort-Object -Property Server | Export-Csv $target -NoTypeInformation
    }

    if ($OrganizationConfig) {
        $target = $RootCopyToDirectory + "\OrganizationConfig"
        $data = Get-OrganizationConfig
        Save-DataInfoToFile -dataIn (Get-OrganizationConfig) -SaveToLocation $target
    }

    if ($DAGInformation -and (-not($Script:EdgeRoleDetected))) {
        $data = Get-DAGInformation
        if ($null -ne $data) {
            $dagName = $data.DAGInfo.Name
            $create = $RootCopyToDirectory + "\" + $dagName + "_DAG_MDB_Information"
            New-Folder -NewFolder $create -IncludeDisplayCreate $true
            $saveLocation = $create + "\{0}"

            Save-DataInfoToFile -dataIn ($data.DAGInfo) -SaveToLocation ($saveLocation -f ($dagName + "_DAG_Info"))

            Save-DataInfoToFile -dataIn ($data.DAGNetworkInfo) -SaveToLocation ($saveLocation -f ($dagName + "DAG_Network_Info"))

            foreach ($mdb in $data.AllMdbs) {
                Save-DataInfoToFile -dataIn ($mdb.MDBInfo) -SaveToLocation ($saveLocation -f ($mdb.MDBName + "_DB_Info"))
                Save-DataInfoToFile -dataIn ($mdb.MDBCopyStatus) -SaveToLocation ($saveLocation -f ($mdb.MDBName + "_DB_CopyStatus"))
            }

            Invoke-ZipFolder -Folder $create -AddCompressedSize $false
        }
    }

    if ($SendConnectors) {
        $create = $RootCopyToDirectory + "\Connectors"
        New-Folder -NewFolder $create -IncludeDisplayCreate $true
        $saveLocation = $create + "\Send_Connectors"
        Save-DataInfoToFile -dataIn (Get-SendConnector) -SaveToLocation $saveLocation
    }

    Invoke-ZipFolder -Folder $RootCopyToDirectory -ZipItAll $true -AddCompressedSize $false
    Write-ScriptDebug("Exiting Function: Write-DataOnlyOnceOnLocalMachine")
}