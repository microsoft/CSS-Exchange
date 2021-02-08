function Invoke-EnableExTRATracing {

    Function Invoke-ExtraTracingCreate {
        param(
            [string]$ComputerName,
            [string]$LogmanName
        )
        [array]$results = logman create trace $LogmanName -p '{79bb49e6-2a2c-46e4-9167-fa122525d540}' -o $path\$LogmanName.etl -ow -s $ComputerName -mode globalsequence
        $results

        if ($results[-1] -eq "Data Collector already exists.") {
            Write-Host "Exchange Trace data Collector set already created. Removing it and trying again"
            [array]$results = logman delete $LogmanName -s $ComputerName
            $results

            [array]$results = logman create trace $LogmanName -p '{79bb49e6-2a2c-46e4-9167-fa122525d540}' -o $path\$LogmanName.etl -ow -s $ComputerName -mode globalsequence
            $results
        }

        if ($results[-1] -ne "The command completed successfully.") {
            Write-Host "Failed to create the extra trace. Stopping the VSSTester Script" -ForegroundColor Red
            exit
        }
    }

    #active server, only get tracing from active node
    if ($dbMountedOn -eq $serverName) {
        " "
        "Creating Exchange Trace data collector set..."
        Invoke-ExtraTracingCreate -ComputerName $serverName -LogmanName "VSSTester"
        "Starting Exchange Trace data collector..."
        [array]$results = logman start VSSTester
        $results

        if ($results[-1] -ne "The command completed successfully.") {
            Write-Host "Failed to start the extra trace. Stopping the VSSTester Script" -ForegroundColor Red
            exit
        }
        " "
    } else {
        #passive server, get tracing from both active and passive nodes
        " "
        "Copying the ExTRA config file 'EnabledTraces.config' file to $dbMountedOn..."
        #copy enabledtraces.config from current passive copy to active copy server
        Copy-Item "c:\EnabledTraces.Config" "\\$dbMountedOn\c$\enabledtraces.config" -Force

        #create trace on passive copy
        "Creating Exchange Trace data collector set on $serverName..."
        Invoke-ExtraTracingCreate -ComputerName $serverName -LogmanName "VSSTester-Passive"
        #create trace on active copy
        "Creating Exchange Trace data collector set on $dbMountedOn..."
        Invoke-ExtraTracingCreate -ComputerName $dbMountedOn -LogmanName "VSSTester-Active"
        #start trace on passive copy
        "Starting Exchange Trace data collector on $serverName..."
        [array]$results = logman start VSSTester-Passive -s $serverName
        $results

        if ($results[-1] -ne "The command completed successfully.") {
            Write-Host "Failed to start the extra trace. Stopping the VSSTester Script" -ForegroundColor Red
            exit
        }
        #start trace on active copy
        "Starting Exchange Trace data collector on $dbMountedOn..."
        [array]$results = logman start VSSTester-Active -s $dbMountedOn
        $results

        if ($results[-1] -ne "The command completed successfully.") {
            Write-Host "Failed to start the extra trace. Stopping the VSSTester Script" -ForegroundColor Red
            exit
        }
        " "
    }

    Write-Debug "ExTRA trace started successfully"
}