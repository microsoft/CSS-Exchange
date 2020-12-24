Function Get-ThisServerObject {

    foreach($srv in $PassedInfo.ServerObjects)
    {
        if($srv.ServerName -eq $env:COMPUTERNAME)
        {
            $Script:localServerObject = $srv 
        }
    }
    if($Script:localServerObject -eq $null -or $Script:localServerObject.ServerName -ne $env:COMPUTERNAME)
    {
        #Something went wrong.... 
        Write-ScriptHost -WriteString ("Something went wrong trying to find the correct Server Object for this server. Stopping this instance of Execution")
        exit 
    }
}