. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Write-SimpleLogfile.ps1
. $PSScriptRoot\..\..\Shared\Start-SleepWithProgress.ps1

# List of base Folders
[array]$BaseFolders = (Join-Path $env:SystemRoot '\Cluster'),
(Join-Path $env:ExchangeInstallPath '\ClientAccess\OAB'),
(Join-Path $env:ExchangeInstallPath '\FIP-FS'),
(Join-Path $env:ExchangeInstallPath '\GroupMetrics'),
(Join-Path $env:ExchangeInstallPath '\Logging'),
(Join-Path $env:ExchangeInstallPath '\Mailbox'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\Adam'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\IpFilter'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\Queue'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\SenderReputation'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\Temp'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Logs'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Pickup'),
(Join-Path $env:ExchangeInstallPath '\TransportRoles\Replay'),
(Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Grammars'),
(Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Prompts'),
(Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Temp'),
(Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Voicemail'),
(Join-Path $env:ExchangeInstallPath '\Working\OleConverter'),
(Join-Path $env:SystemDrive '\inetpub\temp\IIS Temporary Compressed Files'),
(Join-Path $env:SystemRoot '\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files'),
(Join-Path $env:SystemRoot '\System32\Inetsrv')
#'$env:SystemRoot\Temp\OICE_<GUID>'
#'$env:SystemDrive\DAGFileShareWitnesses\<DAGFQDN>'

# Log file name
$LogFile = "ExchAvExclusions.log"
Write-SimpleLogfile -String "Starting Test" -Name $LogFile

# Create list object to hold all Folders we are going to test
$FolderList = New-Object Collections.Generic.List[string]

# Confirm that we are an administrator
if (Confirm-Administrator) {}
else { Write-Error "Please run as Administrator" }

# Make sure each folder in our list resolves
foreach ($path in $BaseFolders) {
    try {
        # Resolve path only returns a bool so we have to manuall throw to catch
        if (!(Resolve-Path -Path $path -ErrorAction SilentlyContinue)) {
            throw "Failed to resolve"
        }
        # If -recurse then we need to find all subfolders and add them to the list to be tested
        if ($Recurse) {

            # Add the root folder
            $FolderList.add($path)

            # Get the Folder and all subFolders and just return the fullname value as a string
            Get-ChildItem $Folder -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | ForEach-Object { $FolderList.add($_) }
        }
        # Just add the root folder
        else { $FolderList.add($path) }
    } catch { Write-SimpleLogfile -string ("[ERROR] - Failed to resolve folder " + $path) -Name $LogFile }
}

Write-SimpleLogfile -String "Creating EICAR Files" -name $LogFile -OutHost
# Create the EICAR file in each path
foreach ($Folder in $FolderList) {

    [string] $FilePath = (Join-Path $Folder eicar.com)
    Write-SimpleLogfile -String ("Creating EICAR file " + $FilePath) -name $LogFile

    #Base64 of Eicar string
    [string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

    If (!(Test-Path -Path $FilePath)) {

        # Try writing the encoded string to a the file
        Try {
            [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
            [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
            Set-Content -Value $Eicar -Encoding ascii -Path $FilePath -Force
        }

        Catch {
            Write-Warning "$Folder Eicar.com file couldn't be created. Either permissions or AV prevented file creation."
        }
    }

    Else {
        Write-Warning "Eicar.com already exists!"
    }
}

# Sleeping 5 minutes for AV to "find" the files
Start-SleepWithProgress -sleeptime 300 -message "Allowing time for AV to Scan"

# Create a list of folders that are probably being scanned by AV
$BadFolderList = New-Object Collections.Generic.List[string]

Write-SimpleLogfile -string "Testing for EICAR files" -name $LogFile -OutHost
# Test each location for the EICAR file
foreach ($Folder in $FolderList) {

    $FilePath = (Join-Path $Folder eicar.com)

    # If the file exists delete it -- this means the folder is not being scanned
    if (Test-Path $FilePath ) {
        Write-SimpleLogfile -String ("Removing " + $FilePath) -name $LogFile
        Remove-Item $FilePath -Confirm:$false -Force
    }
    # If the file doesn't exist add that to the bad folder list -- means the folder is being scanned
    else {
        Write-SimpleLogfile -String ("[FAIL] Possible AV Scanning: " + $FilePath) -name $LogFile -OutHost
        $BadFolderList.Add($Folder)
    }
}

# Report what we found
if ($BadFolderList.count -gt 0) {
    $OutputPath = Join-Path $env:LOCALAPPDATA BadFolders.txt
    $BadFolderList | Out-File $OutputPath

    Write-SimpleLogfile -String "Possbile AV Scanning found" -name $LogFile
    Write-Warning ("Found " + $BadFolderList.count + " folders that are possibly being scanned!")
    Write-Warning ("Review " + $OutputPath + " For the full list.")
} else {
    Write-SimpleLogfile -String "All EICAR files found; Exclusions appear to be set properly" -Name $LogFile -OutHost
}
