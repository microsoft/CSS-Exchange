# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Save-DataInfoToFile.ps1
. $PSScriptRoot\Save-RegistryHive.ps1
. $PSScriptRoot\..\Get-ClusterNodeFileVersions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
#Save out the failover cluster information for the local node, besides the event logs.
function Save-FailoverClusterInformation {
    Write-Verbose("Function Enter: Save-FailoverClusterInformation")
    $copyTo = "$Script:RootCopyToDirectory\Cluster_Information"
    New-Item -ItemType Directory -Path $copyTo -Force | Out-Null

    try {
        Save-DataInfoToFile -DataIn (Get-Cluster -ErrorAction Stop) -SaveToLocation "$copyTo\GetCluster"
    } catch {
        Write-Verbose "Failed to run Get-Cluster"
        Invoke-CatchActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterGroup -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterGroup"
    } catch {
        Write-Verbose "Failed to run Get-ClusterGroup"
        Invoke-CatchActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNode -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNode"
    } catch {
        Write-Verbose "Failed to run Get-ClusterNode"
        Invoke-CatchActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetwork -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetwork"
    } catch {
        Write-Verbose "Failed to run Get-ClusterNetwork"
        Invoke-CatchActions
    }

    try {
        Save-DataInfoToFile -DataIn (Get-ClusterNetworkInterface -ErrorAction Stop) -SaveToLocation "$copyTo\GetClusterNetworkInterface"
    } catch {
        Write-Verbose "Failed to run Get-ClusterNetworkInterface"
        Invoke-CatchActions
    }

    try {
        Get-ClusterLog -Node $env:ComputerName -Destination $copyTo -ErrorAction Stop | Out-Null
    } catch {
        Write-Verbose "Failed to run Get-ClusterLog"
        Invoke-CatchActions
    }

    try {
        $clusterNodeFileVersions = Get-ClusterNodeFileVersions
        Save-DataInfoToFile -DataIn $clusterNodeFileVersions -SaveToLocation "$copyTo\ClusterNodeFileVersions" -SaveTextFile $false
        Save-DataInfoToFile -DataIn ($clusterNodeFileVersions.Files.Values) -SaveToLocation "$copyTo\ClusterNodeFileVersions" -SaveXMLFile $false -FormatList $false
    } catch {
        Write-Verbose "Failed to run Get-ClusterNodeFileVersions"
        Invoke-CatchActions
    }

    $params = @{
        RegistryPath    = "HKLM:Cluster"
        SaveName        = "Cluster_Hive"
        SaveToPath      = $copyTo
        UseGetChildItem = $true
    }
    Save-RegistryHive @params
    Invoke-ZipFolder -Folder $copyTo
    Write-Verbose "Function Exit: Save-FailoverClusterInformation"
}
