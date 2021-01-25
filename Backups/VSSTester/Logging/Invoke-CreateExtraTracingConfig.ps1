function Invoke-CreateExTRATracingConfig {

    function Out-ExTRAConfigFile {
        param ([string]$fileline)
        $fileline | Out-File -FilePath "C:\EnabledTraces.Config" -Encoding ASCII -Append
    }

    " "
    Get-Date
    Write-Host "Enabling ExTRA Tracing..." -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    New-Item -Path "C:\EnabledTraces.Config" -type file -Force

    Out-ExTRAConfigFile "TraceLevels:Debug,Warning,Error,Fatal,Info,Performance,Function,Pfd"
    if ($exchVer -eq "2010") {
        Out-ExTRAConfigFile "Store:tagEseBack,tagVSS,tagJetBackup,tagJetRestore"
    } elseif ($exchVer -eq "2013" -or $exchVer -eq "2016" -or $exchVer -eq "2019") {
        Out-ExTRAConfigFile "ManagedStore.PhysicalAccess:JetBackup,JetRestore"
    }
    Out-ExTRAConfigFile "Cluster.Replay:ReplicaVssWriterInterop,ReplicaInstance,LogTruncater"
    Out-ExTRAConfigFile "FilteredTracing:No"
    Out-ExTRAConfigFile "InMemoryTracing:No"
    " "
    Write-Debug "ExTRA trace config file created successfully"
}