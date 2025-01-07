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

    ### Do we want to search the reference Colum here as well??

    Return $Output
}

# Gather up all of the entries by recipient
Function Group-ByRecipient {
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
        $Recipient
    )

    # Filter the MTL by the provided recipient
    [array]$Output = $MTL | Where-Object { $_.recipient_address -like ('*' + $Recipient + '*') }

    # Make sure we found the recipient
    If ($null -eq $Output) {
        Write-Error ("Recipient " + $Recipient + " not found in provide MTL.") -ErrorAction Stop
    }

    ### Do we want to search the reference Colum here as well??

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

    if (($MTL | Select-Object -Property message_id -Unique).count -gt 1) {
        Return $false
    } else {
        Return $true
    }
}

# Determine if we have a unique recipient in the MTL
Function Test-UniqueRecipient {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $MTL
    )

    if (($MTL | Select-Object -Property recipient_address -Unique).count -gt 1) {
        Return $false
    } else {
        Return $true
    }

}

function Test-CSVData {
    param(
        [array]$CSV,
        [array]$ColumnsToCheck
    )

    # Check to make sure we have data in the CSV
    if (($null -eq $CSV) -or !($CSV.count -gt 0)) {
        Write-Error "Provided CSV null or empty" -ErrorAction Stop
        return $false
    }

    # Read thru the data and make sure we have the needed columns
    $ColumnHeaders = ($CSV | Get-Member -MemberType NoteProperty).Name
    foreach ( $ColumnToCheck in $ColumnsToCheck) {
        if (!($ColumnHeaders.ToLower().Contains($ColumnToCheck.ToLower())) ) {
            return $false
        }
    }
    return $true
}

# Take a StorDriver Receive event and format the output into HTML with all critical data
function Format-StoreDriverReceive {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [array]
        $Entry
    )

    # Make sure our return object is null
    $object = $null
    $hash = $null

    #### Need to add all of the data we want to a PSCustomobject
    $hash = @{
        DateTime        = $Entry.date_time
        Source          = $Entry.source
        event_id        = $Entry.event_id
        client_type     = (Get-SubmissionClientType -Data $Entry.source_context)
        recipient_count = $Entry.recipient_count
        reference       = (Get-ReferencePopulated -Data $Entry.reference)



    }



    # Convert the hash table to an object
    $object = [pscustomobject]$hash
}

# Get the submission client type from a storedriver receive event
Function Get-SubmissionClientType {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Data
    )

    $hash = ConvertFrom-StringData ($Data -replace ",", " `n") -Delimiter ":"

    switch ($hash.ClientType) {
        MoMT { Return "Outlook Client" }
        OWA { Return "OWA" }
        Default { Return $hash.ClientType }
    }
}

# Determine if the message is a reply/forward/response based on reference being populated
Function Get-ReferencePopulated {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Data
    )

    if ([string]::IsNullOrEmpty($Data)) {
        Return "Reply/Forward/Response"
    } else { Return "Empty" }
}

