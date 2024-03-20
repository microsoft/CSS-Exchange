# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-EnableExTRATracing {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ServerName,

        [Parameter(Mandatory = $false)]
        [object]
        $DatabaseToBackup,

        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath,

        [Parameter(Mandatory = $true)]
        [bool]
        $Circular
    )

    function Invoke-ExtraTracingCreate {
        param(
            [string]$ComputerName,
            [string]$LogmanName,
            [string]$OutputPath,
            [bool]$Circular
        )

        if ($Circular) {
            logman create trace $LogmanName -p '{79bb49e6-2a2c-46e4-9167-fa122525d540}' -o $OutputPath\$LogmanName.etl -ow -s $ComputerName -mode globalsequence -f bincirc -max 1024
        } else {
            logman create trace $LogmanName -p '{79bb49e6-2a2c-46e4-9167-fa122525d540}' -o $OutputPath\$LogmanName.etl -ow -s $ComputerName -mode globalsequence
        }

        if ($LASTEXITCODE) {
            Write-Host "Exchange Trace data Collector set already created. Removing it and trying again"
            logman stop $LogmanName -s $ComputerName
            logman delete $LogmanName -s $ComputerName

            if ($Circular) {
                logman create trace $LogmanName -p '{79bb49e6-2a2c-46e4-9167-fa122525d540}' -o $OutputPath\$LogmanName.etl -ow -s $ComputerName -mode globalsequence -f bincirc -max 1024
            } else {
                logman create trace $LogmanName -p '{79bb49e6-2a2c-46e4-9167-fa122525d540}' -o $OutputPath\$LogmanName.etl -ow -s $ComputerName -mode globalsequence
            }
        }

        if ($LASTEXITCODE) {
            Write-Warning "Failed to create the extra trace. Stopping the VSSTester Script"
            exit
        }
    }

    $traceLocalServerOnly = $null -eq $DatabaseToBackup -or $DatabaseToBackup.Server.Name -eq $ServerName

    if ($traceLocalServerOnly) {
        Write-Host "Creating Exchange Trace data collector set..."
        Invoke-ExtraTracingCreate -ComputerName $ServerName -LogmanName "VSSTester" -OutputPath $OutputPath
        Write-Host "Starting Exchange Trace data collector..."
        logman start VSSTester

        if ($LASTEXITCODE) {
            Write-Warning "Failed to start the extra trace. Stopping the VSSTester Script"
            exit
        }

        Write-Host
    } else {
        #passive server, get tracing from both active and passive nodes
        $dbMountedOn = $DatabaseToBackup.Server.Name
        Write-Host "Copying the ExTRA config file 'EnabledTraces.config' file to $dbMountedOn..."
        #copy EnabledTraces.config from current passive copy to active copy server
        Copy-Item "c:\EnabledTraces.Config" "\\$dbMountedOn\c$\EnabledTraces.config" -Force

        #create trace on passive copy
        Write-Host "Creating Exchange Trace data collector set on $ServerName..."
        Invoke-ExtraTracingCreate -ComputerName $ServerName -LogmanName "VSSTester-Passive" -OutputPath $OutputPath
        #create trace on active copy
        Write-Host "Creating Exchange Trace data collector set on $dbMountedOn..."
        Invoke-ExtraTracingCreate -ComputerName $dbMountedOn -LogmanName "VSSTester-Active" -OutputPath $OutputPath
        #start trace on passive copy
        Write-Host "Starting Exchange Trace data collector on $ServerName..."
        logman start VSSTester-Passive -s $ServerName

        if ($LASTEXITCODE) {
            Write-Warning "Failed to start the extra trace. Stopping the VSSTester Script"
            exit
        }
        #start trace on active copy
        Write-Host "Starting Exchange Trace data collector on $dbMountedOn..."
        logman start VSSTester-Active -s $dbMountedOn

        if ($LASTEXITCODE) {
            Write-Warning "Failed to start the extra trace. Stopping the VSSTester Script"
            exit
        }
    }

    Write-Debug "ExTRA trace started successfully"
}
