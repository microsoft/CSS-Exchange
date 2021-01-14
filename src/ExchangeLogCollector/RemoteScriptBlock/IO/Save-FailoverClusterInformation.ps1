#Save out the failover cluster information for the local node, besides the event logs.
Function Save-FailoverClusterInformation {
    Write-ScriptDebug("Function Enter: Save-FailoverClusterInformation")
    $copyTo = "$Script:RootCopyToDirectory\Cluster_Information"
    New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true

    try {
        Save-DataInfoToFile -DataIn (Get-Cluster -ErrorAction Stop) -SaveToLocation "$copyTo\GetCluster"
    } catch {
        Write-ScriptDebug "Failed to run Get-Cluster"
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterGroup -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterGroup"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterGroup"
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNode -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNode"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNode"
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetwork -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetwork"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNetwork"
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetworkInterface -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetworkInterface"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNetworkInterface"
    }

    try {
        Get-ClusterLog -Node $env:ComputerName -Destination $copyTo -ErrorAction Stop
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterLog"
    }

    try {
        $saveName = "$copyTo\ClusterHive.hiv"
        reg save "HKEY_LOCAL_MACHINE\Cluster" $saveName
        "To read the cluster hive. Run 'reg load HKLM\TempHive ClusterHive.hiv'. Then Open your regedit then go to HKLM:\TempHive to view the data." |
            Out-File -FilePath "$copyTo\ClusterHive_HowToRead.txt"
    } catch {
        Write-ScriptDebug "Failed to get the Cluster Hive"
    }

    Invoke-ZipFolder -Folder $copyTo
    Write-ScriptDebug "Function Exit: Save-FailoverClusterInformation"
}