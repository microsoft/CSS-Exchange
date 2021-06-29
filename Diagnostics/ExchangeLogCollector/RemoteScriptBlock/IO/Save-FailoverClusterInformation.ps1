# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Save out the failover cluster information for the local node, besides the event logs.
Function Save-FailoverClusterInformation {
    Write-ScriptDebug("Function Enter: Save-FailoverClusterInformation")
    $copyTo = "$Script:RootCopyToDirectory\Cluster_Information"
    New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true

    try {
        Save-DataInfoToFile -DataIn (Get-Cluster -ErrorAction Stop) -SaveToLocation "$copyTo\GetCluster"
    } catch {
        Write-ScriptDebug "Failed to run Get-Cluster"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterGroup -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterGroup"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterGroup"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNode -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNode"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNode"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetwork -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetwork"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNetwork"
        Invoke-CatchBlockActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetworkInterface -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetworkInterface"
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNetworkInterface"
        Invoke-CatchBlockActions
    }

    try {
        Get-ClusterLog -Node $env:ComputerName -Destination $copyTo -ErrorAction Stop | Out-Null
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterLog"
        Invoke-CatchBlockActions
    }

    try {
        $clusterNodeFileVersions = Get-ClusterNodeFileVersions
        Save-DataInfoToFile -DataIn $clusterNodeFileVersions -SaveToLocation "$copyTo\ClusterNodeFileVersions" -SaveTextFile $false
        Save-DataInfoToFile -DataIn ($clusterNodeFileVersions.Files.Values) -SaveToLocation "$copyTo\ClusterNodeFileVersions" -SaveXMLFile $false -FormatList $false
    } catch {
        Write-ScriptDebug "Failed to run Get-ClusterNodeFileVersions"
        Invoke-CatchBlockActions
    }

    try {
        $saveName = "$copyTo\ClusterHive.hiv"
        reg save "HKEY_LOCAL_MACHINE\Cluster" $saveName | Out-Null
        "To read the cluster hive. Run 'reg load HKLM\TempHive ClusterHive.hiv'. Then Open your regedit then go to HKLM:\TempHive to view the data." |
            Out-File -FilePath "$copyTo\ClusterHive_HowToRead.txt"
    } catch {
        Write-ScriptDebug "Failed to get the Cluster Hive"
        Invoke-CatchBlockActions
    }

    Invoke-ZipFolder -Folder $copyTo
    Write-ScriptDebug "Function Exit: Save-FailoverClusterInformation"
}
