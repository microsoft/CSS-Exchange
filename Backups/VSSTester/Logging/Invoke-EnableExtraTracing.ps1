function Invoke-EnableExTRATracing {

    #active server, only get tracing from active node
    if ($dbMountedOn -eq $serverName) {
        " "
        "Creating Exchange Trace data collector set..."
        logman create trace VSSTester -p "Microsoft Exchange Server 2010" -o $path\vsstester.etl -ow
        "Starting Exchange Trace data collector..."
        logman start VSSTester
        " "
    } else {
        #passive server, get tracing from both active and passive nodes
        " "
        "Copying the ExTRA config file 'EnabledTraces.config' file to $dbMountedOn..."
        #copy enabledtraces.config from current passive copy to active copy server
        Copy-Item "c:\EnabledTraces.Config" "\\$dbMountedOn\c$\enabledtraces.config" -Force

        #create trace on passive copy
        "Creating Exchange Trace data collector set on $serverName..."
        logman create trace VSSTester-Passive -p "Microsoft Exchange Server 2010" -o $path\vsstester-passive.etl -s $serverName -ow
        #create trace on active copy
        "Creating Exchange Trace data collector set on $dbMountedOn..."
        logman create trace VSSTester-Active -p "Microsoft Exchange Server 2010" -o $path\vsstester-active.etl -s $dbMountedOn -ow
        #start trace on passive copy
        "Starting Exchange Trace data collector on $serverName..."
        logman start VSSTester-Passive -s $serverName
        #start trace on active copy
        "Starting Exchange Trace data collector on $dbMountedOn..."
        logman start VSSTester-Active -s $dbMountedOn
        " "
    }

    Write-Debug "ExTRA trace started successfully"
}