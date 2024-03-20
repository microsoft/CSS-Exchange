# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-CreateExTRATracingConfig {
    [OutputType([System.Void])]
    param()

    function Out-ExTRAConfigFile {
        param ([string]$FileLine)
        $FileLine | Out-File -FilePath "C:\EnabledTraces.Config" -Encoding ASCII -Append
    }

    Write-Host "$(Get-Date) Enabling ExTRA Tracing..."
    New-Item -Path "C:\EnabledTraces.Config" -type file -Force | Out-Null

    Out-ExTRAConfigFile "TraceLevels:Debug,Warning,Error,Fatal,Info,Performance,Function,Pfd"
    Out-ExTRAConfigFile "ManagedStore.PhysicalAccess:JetBackup,JetRestore,JetEventlog,SnapshotOperation"
    Out-ExTRAConfigFile "Cluster.Replay:LogTruncater,ReplayApi,ReplicaInstance,ReplicaVssWriterInterop"
    Out-ExTRAConfigFile "ManagedStore.HA:BlockModeSender,Eseback"
    Out-ExTRAConfigFile "FilteredTracing:No"
    Out-ExTRAConfigFile "InMemoryTracing:No"

    Write-Debug "ExTRA trace config file created successfully"
}
