<#
.NOTES
	Name: UnifiedContentCorrector.ps1
    Author: Josh Jerdon
    Email: jojerd@microsoft.com
	Requires: Administrative Priveleges
	Version History:
    1.0 - 12/16/2019 - Initial Release
    1.1 - 3/25/2020 - Fixed XML element mishandling, added file check to confirm changes were made, removed experimental network config plan to release at a later date.
    1.2 - 3/25/2020 - Fixed XML loading behavior
    1.3 - 4/3/2020  - Added ability for script to change UnifiedContent folder paths for mutliple Exchange servers within a given Active Directory site.
    1.3.1 - 4/27/2010 - Fixed Path Seperator issue with space in the new UnifedContent Path, also optimized XML Loading behavior to preserve whitespace.
    
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
    Corrects the Unified Content folder path so that the cleanup probe can check the directory for 
    files that need to be cleaned up and removed. This only needs to be run on Exchange 2013,2016, and 2019 servers
    if both conditions are met.
    1.) Exchange 2013, 2016, 2019 installed outside of the default installation path (example C:\Program Files\Microsoft\Exchange Server\v15\)
    2.) You are actively utilizing the built in Antimalware agent. If you are not, then this behavior is a non-issue.
#>
param(
    [switch]$ListOfServers,
    [switch]$GenerateReport
)
function GenerateReport {
    # Check if script has been executed as an Administrator
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
    #Check PowerShell version for compliance
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        Write-Host " "
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    
        #Add Exchange Management Capabilities Into The Current PowerShell Session.
        $CheckSnapin = (Get-PSSnapin | Where-Object { $_.Name -eq "Microsoft.Exchange.Management.PowerShell.E2010" } | Select-Object Name)
        if ($CheckSnapin -like "*Exchange.Management.PowerShell*") {
            Write-Host " "
            Write-Host "Exchange Snap-in already loaded, continuing...." -ForegroundColor Green
            Clear-Host
        }
        else {
            Write-Host " "
            Write-Host "Loading Exchange Snap-in Please Wait..."
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction Stop
            Clear-Host
        }
        #Search local AD Site for all Exchange Servers.
        $ADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
        Write-Host " "
        Write-Host "Searching Active Directory Site $ADSite for Exchange Servers, Please Wait..."
        $Servers = Get-ExchangeServer | Where-Object { $_.Site -match $ADSite }
        
        #File output declarations
        $OutputFilePath = "."
        $OutputReportName = "ExchangeInstallPathReport" + "-" + (Get-Date).ToString("MMddyyyHHmmss") + ".csv"
        $OutputReport = $OutputFilePath + "\" + $OutputReportName
        

        if ($Servers.count -gt 0) {
            foreach ($Server in $Servers) {

                Write-Host "Checking Server $Server"
                $ExchServer = $Server.Name
                $Version = $Server.AdminDisplayVersion
                $ResolveDNS = Resolve-DnsName -Name $Server -Type A
                $IPAddress = $ResolveDNS.IPAddress
                $CheckConnection = Test-Connection $ExchServer -Count 1 -Bytes 32 -Quiet
                if ($CheckConnection -eq 'True') {
                    try {
                        $Installpath = Invoke-Command -ComputerName $ExchServer -ScriptBlock { $env:Exchangeinstallpath }
                    }
                    catch {
                        Write-Warning $_.Exception.Message
                        $Installpath = "Unable to connect to Server"
                    }
                }
                else {
                    $Installpath = "Unable to connect to Server"
                }
                
                
                $Report = [PSCustomObject]@{
                    "Server"           = $ExchServer;
                    "Exchange Version" = $Version;
                    "IP Address"       = $IPAddress;
                    "Install Path"     = $Installpath
                }

                $Report | Export-Csv ($OutputReport) -Append -NoTypeInformation
            }
        }

    }
}
function ListOfServers {
    # Check if script has been executed as an Administrator
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
    $File = Test-Path .\ServerList.txt
    if ($File -eq "True") { $Servers = Get-Content .\ServerList.txt }        
    
    else {
        Write-Error "Unable to load server list, appears to be missing" -ErrorAction Stop
    }
    if ($Servers.count -gt 0) {
        foreach ($Server in $Servers) {
            # Check if server is online.
            $CheckConnection = Test-Connection $Server -Count 1 -Bytes 32 -Quiet
            # If server is online proceed.
            if ($CheckConnection -eq 'True') {
                Write-Host "Modifying server $Server"
                $Session = New-PSSession -ComputerName $Server
                Invoke-Command -Session $Session -ScriptBlock {
                
                    # Set file path attributes.
                    $ExchangePath = $env:Exchangeinstallpath
                    $UnifiedContentPath = $ExchangePath + "TransportRoles\data\Temp\UnifiedContent"
                    $AntimalwareFile = $ExchangePath + "Bin\Monitoring\Config\Antimalware.xml"
                    $AntimalwareFilePath = $ExchangePath + "Bin\Monitoring\Config"

                    #Check to confirm file to modify exists.
                    if ([System.IO.File]::Exists($AntimalwareFile) -eq 'True') {
                        $LoadFile = New-Object System.Xml.XmlDocument
                        $LoadFile.PreserveWhitespace = $true
                        $LoadFile.Load($AntimalwareFile)
                    }
                    # If script is not able to verify the Antimalware.xml file exit foreach loop and PSSession, return.
                    else {
                        Exit-PSSession
                        Write-Error "Unable to locate file to modify for server $Server"
                        return
                    }
                    # Test UnifiedContent file Path to confirm it exists before file modification.
                    $TestUnifiedPath = Test-Path -Path $UnifiedContentPath -IsValid
                    # If test path is successful, change working location.
                    if ($TestUnifiedPath -eq 'True') {
                        Set-Location $AntimalwareFilePath
                    }
                    # If test path fails, exit loop and return.
                    else {
                        Exit-PSSession
                        Write-Error "Unified Content Folder Path is not valid on server $Server"
                        return
                    }
                    # Verify if backup directory exists, if so copy Antimalware.xml file.
                    $xmlbackuppath = $AntimalwareFilePath + "\xmlbackup"
                    if ([System.IO.Directory]::Exists($xmlbackuppath) -eq 'True') {
                        Copy-Item Antimalware.xml .\xmlbackup -Force
                        
                    }
                    else {
                        # If directory does not exist, create it and copy Antimalware.xml file.
                        New-Item -Name xmlbackup -ItemType Directory | Out-Null
                        Copy-Item Antimalware.xml .\xmlbackup -Force
                        
                    }   
                    # Confirm backup is successfully saved, if so make xml file changes.
                    $BackupFile = $AntimalwareFilePath + "\xmlbackup\Antimalware.xml" 
                    [string]$NewPath = "D:\ExchangeTemp\TransportCts\UnifiedContent;C:\Windows\Temp\UnifiedContent;$UnifiedContentPath"
                    if ([System.IO.File]::Exists($BackupFile) -eq 'True') {
                        $LoadFile.Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths = $NewPath
                        $LoadFile.Save((Resolve-Path "Antimalware.xml")) 
                    }
                    else {
                        # If not able to locate the backup file, stop script no changes will be made.
                        Exit-PSSession
                        Write-Error "Unable to confirm file backup."
                        return
                    }
                    # Verify that Antimalware file has been updated.
                    $LoadModifiedFile = [xml](Get-Content .\Antimalware.xml)
                    if ($LoadModifiedFile.Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths -eq $NewPath) {
                        Exit-PSSession
                        Write-Host "Antimalware file has been successfully modified" -ForegroundColor Green
                        Write-Host "Please Reboot server for changes to take effect" -ForegroundColor Yellow
                        
                    }
                    else {
                        Exit-PSSession
                        Write-Error "Antimalware file modification failed."                                               
                    }
        
                    # Exit Powershell session proceed to next server in loop
                    Exit-PSSession
                }

        
            }
            else {
                #Server did not return a ping response, check firewall and or if server is online.
                Write-Error "Unable to connect to server $Server Check firewall and or confirm if server is online"
            }
            
        
        }
      
    }
    else {
        # Error for ServerList.txt either being empty or inaccessible.
        Write-Error "Server list appears to be emtpy, check file to make sure there are servers in the list" -ErrorAction Stop
    }
    
}
if ($ListOfServers) { ListOfServers; Exit }
if ($GenerateReport) { GenerateReport; Clear-Host; Exit }

# Check if script has been executed as an Administrator
$Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if ($Admin -eq 'True') {
    Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
    Start-Sleep -Seconds 3
    Clear-Host
}
# If script is not executed as an Administrator, stop the script.
else {
    Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
}
# Get Exchange installation path, set pathing variables, load file to be modified into memory.
$ExchangePath = $env:Exchangeinstallpath
$UnifiedContentPath = $ExchangePath + "TransportRoles\data\Temp\UnifiedContent"
$AntimalwareFile = $ExchangePath + "Bin\Monitoring\Config\Antimalware.xml"
$AntimalwareFilePath = $ExchangePath + "Bin\Monitoring\Config"
if ([System.IO.File]::Exists($AntimalwareFile) -eq 'True') {
    Clear-Host
    Write-Host "Located Antimalware.xml file to modify, loading file into memory..." -ForegroundColor Green
    Start-Sleep -Seconds 3
    $LoadFile = New-Object System.Xml.XmlDocument
    $LoadFile.PreserveWhitespace = $true
    $LoadFile.Load($AntimalwareFile)
    Clear-Host
}
# If script is not able to verify the UnifiedContent folder path, end script execution.
else {
    Write-Error 'Unable to locate file to modify' -ErrorAction Stop
}
# Test UnifiedContent file Path to confirm it exists before file modification.
$TestUnifiedPath = Test-Path -Path $UnifiedContentPath -IsValid
# If test path is successful, change working location.
if ($TestUnifiedPath -eq 'True') {
    Write-Host "UnifiedContent Folder path is correct, creating a backup of the original file before proceeding..." -ForegroundColor Green
    Start-Sleep -Seconds 3
    Clear-Host
    Set-Location $AntimalwareFilePath
}
# If test path fails, halt script.
else {
    Write-Error 'Unified Content Folder Path is not valid no changes will be made' -ErrorAction Stop
}
# Verify if backup directory exists, if so copy Antimalware.xml file.
$xmlbackuppath = $AntimalwareFilePath + "\xmlbackup"
if ([System.IO.Directory]::Exists($xmlbackuppath) -eq 'True') {
    Write-Host "Creating file backup..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    Clear-Host 
    Copy-Item Antimalware.xml .\xmlbackup -Force
}
else {
    # If directory does not exist, create it and copy Antimalware.xml file.
    New-Item -Name xmlbackup -ItemType Directory
    Copy-Item Antimalware.xml .\xmlbackup -Force
}   
# Confirm backup is successfully saved, if so make xml file changes.
$BackupFile = $AntimalwareFilePath + "\xmlbackup\Antimalware.xml"
[string]$NewPath = "D:\ExchangeTemp\TransportCts\UnifiedContent;C:\Windows\Temp\UnifiedContent;$UnifiedContentPath"
if ([System.IO.File]::Exists($BackupFile) -eq 'True') {
    Clear-Host
    Write-Host "Previous Antimalware file was backed up successfully, making required changes" -ForegroundColor Green
    Start-Sleep -Seconds 3
    $LoadFile.Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths = $NewPath
    $LoadFile.Save((Resolve-Path "Antimalware.xml")) 
}
else {
    # If not able to locate the backup file, stop script no changes will be made.
    Write-Error "Unable to confirm file backup, script will not continue..." -ErrorAction Stop
}
# Confirm that the Antimalware.xml file has been updated with the correct file path.
Clear-Host
Write-Host 'Checking to confirm file was updated as expected...' -ForegroundColor Green
Start-Sleep -Seconds 3
Clear-Host

$LoadModifiedFile = [xml](Get-Content .\Antimalware.xml)
if ($LoadModifiedFile.Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths -eq $NewPath) {
    Clear-Host
    Write-Host " "
    Write-Host 'Antimalware file has been modified to reflect the accurate UnifiedContent folder location' -ForegroundColor Green
    Write-Host 'Please reboot the server for the changes to take effect...' -ForegroundColor Green
    Write-Host " "
    Read-Host  'Press Enter key to exit.'
    Exit
}
else {
    Write-Error "File has not been modifed."
    Read-Host 'Press Enter key to exit.'
    Exit
}
