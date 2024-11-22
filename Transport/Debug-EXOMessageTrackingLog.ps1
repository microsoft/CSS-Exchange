# Import and validate the MTL file.
Function Import-MTL {
    [CmdletBinding()]
    [OutputType([array])]
    Param(
        # File path for MTL to import
        [Parameter(Mandatory = $true)]
        [string]
        $FilePath
    )

    # Test the path of the MTL
    if (!(Test-Path $FilePath)) {
        Write-Error "Unable to find the specified file" -ErrorAction Stop
    }

    # Try to load the file with Unicode since we need to start somewhere.
    $initial_mtl = Import-Csv $FilePath -Encoding Unicode

    # If it is null then we need to try without Unicode
    if ($null -eq $initial_mtl) {
        Write-Host "Failed to Load as Unicode; trying normal load"
        $initial_mtl = Import-Csv $FilePath
        # If we still have nothing then log an error and fail
        if ($null -eq $initial_mtl) {
            Write-Error "Failed to load CSV" -ErrorAction Stop
        }
        # Need to know that we loaded without Unicode.
        else {
            Write-Host "Loaded CSV without Unicode"
        }
    } else {
        Write-Host "Loaded MTL with Unicode"
    }

    # Making sure the MTL contains the fields we want.
    if (!(Test-CSVData -CSV $initial_mtl -ColumnsToCheck "date_time_utc", "source_context", "connector_id", "source", "event_id", "message_id", "recipient_address", "recipient_status", "recipient_count", "related_recipient_address", "reference", "message_subject", "sender_address", "return_path", "message_info", "directionality", "custom_data")) {
        Write-Error "MTL is missing one or more required fields." -ErrorAction Stop
    }

    # Converting our strings into [DateTime]
    Write-Host "Converting date_time_utc values"
    for ($i = 0; $i -lt $initial_mtl.Count; $i++) {
        $initial_mtl[$i].date_time_utc = Get-Date($initial_mtl[$i].date_time_utc)
    }

    return $initial_mtl

}

# Gather up all of the entries related to a single MessageID
Function Group-ByMessageID {
    [CmdletBinding()]
    [OutputType([array])]
    param (
        # MTL array to process
        [Parameter(Mandatory = $true)]
        [array]
        $MTL,
        # MessageID to group by
        [Parameter(Mandatory = $true)]
        [string]
        $MessageID
    )

    # Filter the MTL by our messageID
    [array]$Output = $MTL | Where-Object { $_.message_id -eq $MessageID }

    # Make sure we found the messageID
    If ($null -eq $Output) {
        Write-Error ("MessageID " + $MessageID + " not found in provide MTL.") -ErrorAction Stop
    }

    ### Do we want to search the reference coloum here as well??

    Return $Output
}

# Test if we have only a single MessageID provided in the MTL
Function Test-UniqueMessageID {

    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $MTL
    )

    if ((Select-Object -Property message_id -Unique).count -gt 1){
        Return $false
    }
    else {
        Return $true
    }
}



