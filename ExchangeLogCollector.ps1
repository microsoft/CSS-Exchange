<#
.NOTES
    Name: ExchangeLogCollector.ps1
    Author: David Paulson
    Requires: Powershell on an Exchange 2010+ Server with Adminstrator rights
    Version History:
    2.0.0 - Major updates have been made to the script and a new publish of it was done.
    2.0.1 - Missing HTTPErr Logs to the script.
    2.0.2 - Fix Bug with loading EMS and search directory
    2.0.3 - Switch "ClusterLogs" to "High_Availabilty_Logs" and adjust the switch as well to avoid confusion.
            Added a feature that checks to see if you pass some switches or it throws a warning asking are you sure to continue. 
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
    Collects the requested logs off the Exchange server based off the switches that are used.
.DESCRIPTION
    Collects the requested logs off the Exchange server based off the switches that are used.
.PARAMETER FilePath
    The Location of where you would like the data to be copied over to 
.PARAMETER EWSLogs
    Will collect the EWS logs from the Exchange Server 
.PARAMETER IISLogs 
    Will Collect the IIS Logs from the Exchange Server 
.PARAMETER IISLogDirectory
    Used for Exchange 2010 if the IIS logs are not in the default location 
.PARAMETER DailyPerformanceLogs
    Used to collect Exchange 2013+ Daily Performance Logs 
.PARAMETER PerformanceLogs 
    Old switch that was used for the Daily Performance Logs 
.PARAMETER ManagedAvailability 
    Used to collect managed Availability Logs from the Exchange 2013+ Server
.PARAMETER Experfwiz 
    Used to collect Experfwiz data from the server 
.PARAMETER RPCLogs
    Used to collect the PRC Logs from the server 
.PARAMETER EASLogs
    Used to collect the Exchange Active Sync Proxy Logs 
.PARAMETER ECPLogs
    Used to collect the ECP Logs from the Exchange server 
.PARAMETER AutoDLogs
    Used to Collect the AutoD Logs from the server 
.PARAMETER OWALogs
    Used to collect the OWA Logs from the server 
.PARAMETER ADDriverLogs
    Used to collect the AD Driver Logs from the server 
.PARAMETER SearchLogs
    Used to collect the Search Logs from the server 
.PARAMETER ClusterLogs
    Used to collect the Clustering Information from the server 
.PARAMETER MapiLogs
    Used to collect the Mapi Logs from the server 
.PARAMETER MessageTrackingLogs
    Used to collect the Message Tracking Logs from the server 
.PARAMETER HubProtocolLogs
    Used to collect the Hub Protocol Logs from the server
.PARAMETER HubConnectivityLogs
    Used to collect the Hub Connectivity Logs from the server 
.PARAMETER FrontEndConnectivityLogs
    Used to collect the Front End Connectivity Logs from the server 
.PARAMETER FrontEndProtocolLogs
    Used to collect the Front End Protocol Logs from the server 
.PARAMETER MailboxConnectivityLogs
    Used to collect the Mailbox Connectivity Logs from the server 
.PARAMETER MailboxProtocolLogs
    Used to collect the Mailbox Protocol Logs from the server 
.PARAMETER QueueInformationThisServer
    Used to collect the Queue Information from this server 
.PARAMETER ReceiveConnectors
    Used to collect the Receive Connector information from this server 
.PARAMETER SendConnectors
    Used to collect the Send connector information from the Org 
.PARAMETER DAGInformation
    Used to collect the DAG Information for this DAG
.PARAMETER GetVdirs
    Used to collect the Virtual Directories of the environment 
.PARAMETER TransportConfig
    Used to collect the Transport Configuration from this Exchange Server 
.PARAMETER DefaultTransportLogging
    Used to Get all the default logging that is enabled on the Exchange Server for Transport Information 
.PARAMETER Exmon 
    Used to Collect the Exmon Information 
.PARAMETER ServerInfo
    Used to collect the general Server information from the server 
.PARAMETER MSInfo 
    Old switch that was used for collecting the general Server information 
.PARAMETER SevenZipIt 
    Used for Exchange 2010 if .NET framework 4.5 is not installed in order to zip up data 
.PARAMETER CollectAllLogsBasedOnDaysWorth
    Used to collect some of the default logging based off Days Worth vs the whole directory 
.PARAMETER DiskCheckOverride
    Used to over the Availalbe Disk space required in order this script to run 
.PARAMETER AppSysLogs
    Used to collect the Application and System Logs. Default is set to true
.PARAMETER NoZip
    Used to not zip up the data by default 
.PARAMETER CustomData
    Used to collect data from a custom directory 
.PARAMETER CustomDataDirectory
    Tell which directory you would like to collect data from 
.PARAMETER DaysWorth
    To determine how far back we would like to collect data from 
.PARAMETER ScriptLoggingDebug
    To enable Debug Logging for the script to determine what might be wrong with the script 
.PARAMETER DatabaseFailoverIssue
    To enable the common switches to assist with determine the cause of database failover issues 

#>

#Parameters 

Param (

[string]$FilePath = "C:\MS_Logs_Collection",
[switch]$EWSLogs,
[switch]$IISLogs,
[string]$IISLogDirectory,
[switch]$DailyPerformanceLogs,
[switch]$PerformanceLogs,
[switch]$ManagedAvailability,
[switch]$Experfwiz,
[switch]$RPCLogs,
[switch]$EASLogs,
[switch]$ECPLogs,
[switch]$AutoDLogs,
[switch]$OWALogs,
[switch]$ADDriverLogs,
[switch]$SearchLogs,
[switch]$HighAvailabilityLogs,
[switch]$ClusterLogs,
[switch]$MapiLogs,
[switch]$MessageTrackingLogs,
[switch]$HubProtocolLogs,
[switch]$HubConnectivityLogs,
[switch]$FrontEndConnectivityLogs,
[switch]$FrontEndProtocolLogs,
[switch]$MailboxConnectivityLogs,
[switch]$MailboxProtocolLogs,
[switch]$QueueInformationThisServer,
[switch]$ReceiveConnectors,
[switch]$SendConnectors,
[switch]$DAGInformation,
[switch]$GetVdirs,
[switch]$TransportConfig,
[switch]$DefaultTransportLogging,
[switch]$Exmon,
[switch]$ServerInfo,
[switch]$MSInfo,
[switch]$SevenZipIt,
[switch]$CollectAllLogsBasedOnDaysWorth = $false, 
[switch]$DiskCheckOverride,
[switch]$AppSysLogs = $true,
[switch]$AllPossibleLogs,
[switch]$NoZip,
[switch]$CustomData,
[string]$CustomDataDirectory,
[int]$DaysWorth = 3,
[switch]$ScriptLoggingDebug,
[switch]$DatabaseFailoverIssue

)

$ScriptLoggingDebug = $false #Still needs work 

<#

Set up switches for common scenarios 

#>

Function CommonScenarios {

    $Script:TransportSwitchesEnabled = $false 
    if($PerformanceLogs){ $Script:DailyPerformanceLogs = $true}
    if($MSInfo) {$Script:ServerInfo = $true}
    if($ClusterLogs) {$Script:HighAvailabilityLogs = $true}

    if($HubProtocolLogs -or 
       $HubConnectivityLogs -or 
       $MessageTrackingLogs -or 
       $QueueInformationThisServer -or
       $SendConnectors -or 
       $ReceiveConnectors -or 
       $TransportConfig -or
       $FrontEndConnectivityLogs -or 
       $FrontEndProtocolLogs -or 
       $MailboxConnectivityLogs -or 
       $MailboxProtocolLogs -or 
       $DefaultTransportLogging) {$Script:TransportSwitchesEnabled = $true}

    if($DefaultTransportLogging){
       $Script:HubConnectivityLogs = $true
       $Script:MessageTrackingLogs = $true
       $Script:QueueInformationThisServer = $true
       $Script:SendConnectors = $true
       $Script:ReceiveConnectors = $true
       $Script:TransportConfig = $true
       $Script:FrontEndConnectivityLogs = $true
       $Script:MailboxConnectivityLogs = $true
       $Script:FrontEndProtocolLogs = $true
      }


    #All Possible Default Logs 
    if($AllPossibleLogs) {

        $Script:EWSLogs = $true
        $Script:IISLogs = $true
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailability = $true
        $Script:RPCLogs = $true
        $Script:EASLogs = $true
        $Script:AutoDLogs = $true
        $Script:OWALogs = $true
        $Script:ADDriverLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ServerInfo = $true 
        $Script:GetVdirs = $true 
        $Script:DAGInformation = $true
        $Script:MessageTrackingLogs = $true
        $Script:MapiLogs = $true
    }

    #Data to collect for Database Failover Issues 
    if($DatabaseFailoverIssue) {

        $Script:DailyPerformanceLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ManagedAvailability = $true
    }



}

Function Dectect-IfNoSwitchesProvided {

    if($EWSLogs -or
        $IISLogs -or
        $DailyPerformanceLogs -or 
        $PerformanceLogs -or 
        $ManagedAvailability -or 
        $Experfwiz -or
        $RPCLogs -or 
        $EASLogs -or 
        $ECPLogs -or 
        $AutoDLogs -or 
        $OWALogs -or 
        $ADDriverLogs -or 
        $SearchLogs -or 
        $HighAvailabilityLogs -or 
        $ClusterLogs -or 
        $MapiLogs -or 
        $MessageTrackingLogs -or
        $HubProtocolLogs -or
        $HubConnectivityLogs -or 
        $FrontEndConnectivityLogs -or 
        $FrontEndProtocolLogs -or 
        $MailboxConnectivityLogs -or 
        $MailboxProtocolLogs -or 
        $QueueInformationThisServer -or 
        $ReceiveConnectors -or 
        $SendConnectors -or 
        $DAGInformation -or 
        $GetVdirs -or 
        $TransportConfig -or 
        $DefaultTransportLogging -or 
        $Exmon -or
        $ServerInfo -or 
        $MSInfo -or 
        $SevenZipIt -or 
        $AllPossibleLogs -or 
        $CustomData -or 
        $DatabaseFailoverIssue) {return}
    else{
        Write-Host ""
        Write-Warning "Doesn't look like any parameters were provided, are you sure you are running the correct command? This is only going to collect the Application and Sytem Logs."
        do{
            $a = Read-Host "Please enter 'y' or 'n'" 
        }while($a -ne 'y' -and $a -ne 'n') 
    }

    if($a -eq "n"){exit}
    else {#Add debug 
        Write-Host "Okay moving on..." 
    }

}

###############################################
#                                             #
#                 Classes                     #
#                                             #
###############################################

Add-Type @"

public class ServerObject {

    public string ServerName;
    public int Version; 
    public bool Mailbox;
    public bool Hub;
    public bool Cas; 

}

"@


Function Build-TransportClasses {
Add-Type @"

public class MailboxTransportServiceLogPathClass
{

    public string ConnectivityLogPath; 
    public string ReceiveProtocolLogPath;
    public string SendProtocolLogPath;
    public string PipelineTracingPath;
    public string MailboxSubmissionAgentLogPath;
    public string MailboxDeliveryAgentLogPath; 
    public string MailboxDeliveryThrottlingLogPath;

}

public class FrontendTransportServiceLogPathClass

{
    public string ConnectivityLogPath; 
    public string ReceiveProtocolLogPath;
    public string SendProtocolLogPath; 
    public string AgentLogPath; 
    public string ResourceLogPath; 
    public string AttributionLogPath;

}

public class TransportServiceLogPathClass

{
    public string ConnectivityLogPath; 
    public string MessageTrackingLogPath; 
    public string IrmLogPath; 
    public string ActiveUserStatisticsLogPath; 
    public string ServerStatisticsLogPath; 
    public string PipelineTracingPath; 
    public string ReceiveProtocolLogPath; 
    public string RoutingTableLogPath; 
    public string SendProtocolLogPath; 
    public string HttpProtocolLogFilePath; 
    public string TransportSyncLogFilePath; 
    public string TransportSyncHubHealthLogFilePath; 
    public string QueueLogPath; 
    public string WlmLogPath; 
    public string AgentLogPath; 
    public string FlowControlLogPath; 
    public string ProcessingSchedulerLogPath; 
    public string ResourceLogPath; 
    public string DnsLogPath;
    public string JournalLogPath; 
    public string TransportMaintenanceLogPath; 
}


"@
}

###############################################
#                                             #
#                Functions                    #
#                                             #
###############################################


#Function to load the ExShell 
Function Load-ExShell {

    if($exinstall -eq $null){
    $testV14 = Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup'
    $testV15 = Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'

    if($testV14){
        $Script:exinstall = (get-itemproperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath	
    }
    elseif ($testV15) {
        $Script:exinstall = (get-itemproperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath	
    }
    else{
        Write-Host "It appears that you are not on an Exchange 2010 or newer server. Sorry I am going to quit."
		exit
    }

    $script:exbin = $Script:exinstall + "\Bin"

    Write-Host "Loading Exchange PowerShell Module..."
    add-pssnapin Microsoft.Exchange.Management.PowerShell.E2010
    }
}

Function Write-CombineStrings([string]$sOne,[string]$sTwo) {

    $wData = $sOne + " " + $sTwo
    Write-ToLogScript $wData

}

#Function to load all the variables for the log directories 
Function Load-VarScripts {


#systemRoot Root Location 
$Script:systemRoot = "$env:systemroot" 

#AppLogs
$Script:AppLog = "$systemRoot\System32\Winevt\Logs\Application.evtx"

#SystemLogs 
$Script:SysLog = "$systemRoot\System32\Winevt\Logs\system.evtx"

#Microsoft Exchange Management Logs 
$Script:MSManLogs = "$systemRoot\System32\Winevt\Logs\MSExchange Management.evtx"

#
# Managed Availability  Logs 
#

$Script:ProbeResultsLogs = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-ActiveMonitoring%4ProbeResult.evtx"
$Script:RecoveryActionResultsLogs = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-ManagedAvailability%4RecoveryActionResults.evtx"
$Script:RecoveryActionLogs = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-ManagedAvailability%4RecoveryActionLogs.evtx"
$Script:ResponderDefLogs = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-ActiveMonitoring%4ResponderDefinition.evtx"
$Script:ResponderResultsLogs = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-ActiveMonitoring%4ResponderResult.evtx"
$Script:MonitorDefLogs = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-ActiveMonitoring%4MonitorDefinition.evtx"
$Script:MonitoringLogs = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-ManagedAvailability%4Monitoring.evtx"

#
#  High Availability Logs  
#  Exchange 2013 

$Script:HAAppLogMirror = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4AppLogMirror.evtx"
$Script:HABlockReplication = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4BlockReplication.evtx"
$Script:HADebug = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4Debug.evtx"
$Script:HAMonitoring = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4Monitoring.evtx"
$Script:HANetwork = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4Network.evtx"
$Script:HAOperational = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4Operational.evtx"
$Script:HASeeding = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4Seeding.evtx"
$Script:HATruncationDebug = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4TruncationDebug.evtx"
$Script:MDFOperational = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-MailboxDatabaseFailureItems%4Operational.evtx"
$Script:MDFDebug = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-MailboxDatabaseFailureItems%4Debug.evtx"

#Seeding Debug E2K10
$Script:HASeedingDebug = "$systemRoot\System32\Winevt\Logs\Microsoft-Exchange-HighAvailability%4SeedingDebug.evtx"

#ECP Proxy Logs 
$Script:ECPProxyLogFilePath = $exinstall + "\Logging\HttpProxy\Ecp"

#ECP Logs
$Script:ECPLogFilePath = $exinstall + "\Logging\ECP"

#EWS Proxy Logs Directory 
$Script:EWSProxyLogFilePath = $exinstall + "Logging\HttpProxy\Ews"
#EWS BE Logs Directory 
$Script:EWSBELogFilePath = $exinstall + "Logging\Ews"
#Performance Log Directory
$Script:DailyPerformanceDirectory = $exinstall + "Logging\Diagnostics\DailyPerformanceLogs"

#RPC Proxy Log Directory 
$Script:RPCProxyLogFilePath = $exinstall + "Logging\HttpProxy\RpcHttp"

#RPCHttp Log Directory
$Script:RPCHttpLogFilePath = $exinstall + "Logging\RpcHttp"

#RPC Client Access Log Directory
$Script:RCALogFilePath = $exinstall + "Logging\RPC Client Access"

#EAS Proxy Log Directory
$Script:EASProxyLogFilePath = $exinstall + "Logging\HttpProxy\Eas"

#Autodiscover Proxy Log Directory
$Script:AutoDProxyLogFilePath = $exinstall + "Logging\HttpProxy\Autodiscover"

#Autodiscover Log Directory
$Script:AutoDLogFilePath = $exinstall + "Logging\Autodiscover"

#OWA Proxy Log Directory
$Script:OWAProxyLogFilePath = $exinstall + "Logging\HttpProxy\Owa"

#OWA Log Directory
$Script:OWALogFilePath = $exinstall + "Logging\OWA"

#OWA Calendar Proxy Log Directory
$Script:OWACalendarProxyLogFilePath = $exinstall + "Logging\HttpProxy\OwaCalendar"

#ADDriver Log Directory
$Script:ADDriverLogFilePath = $exinstall + "Logging\ADDriver"

#for the folder that we are going to create 
$Script:todaysDate = Get-Date -Format Mdyyyy

#HTTPErr 
$Script:HttpErrDirectory = "$systemRoot\System32\LogFiles\HTTPERR"


#MAPI Proxy Logs 
$Script:MAPIProxyFilePath = $exinstall + "Logging\HttpProxy\Mapi"

#MAPI Log Directory 
$Script:MapiLogsFilePath = $exinstall + "Logging\MAPI Client Access"

#Default Search Logs 
$Script:SearchDiagnosticLogs = $exbin + "Search\Ceres\Diagnostics\Logs"
$Script:SearchDiagnosticETLTraces = $exbin + "Search\Ceres\Diagnostics\ETLTraces"

#Set the copy to location hostname and 
$Script:serverName = hostname 
$Script:targetDir = "$filepath\$todaysDate\$serverName"

#check disk space set to 15 GB
$Script:checkSize = 15

#Experfwiz name 
$Script:Experf_Logman_Name = "Exchange_Perfwiz"; 

$Script:Exmon_Logman_Name = "Exmon_Trace"

}


Function CreateLogFile ($Directory, $FileName, $ext) {

    create-Folder $Directory
    $logLocation = $Directory + "\" + $FileName + $ext
    $i = 0
    while((Test-Path $logLocation) -eq $true) {
        $i++
        $logLocation = $Directory + "\" + $FileName + "-$i" + $ext
    }

    $c = $FileName + "-$i"  + $ext

    if($logLocation.Contains($c)){
        $FileName = $FileName + "-$i" + $ext
    }
    else {
        
        $FileName = $FileName + $ext 
    }

    $temp = New-Item -Name $FileName -Path $Directory -ItemType File 
    
    $Script:logLocation = $Directory + "\" + $FileName 
    
}

Function Bool-CheckNETFrameVersion45GT($Server){
   if(Test-Path 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'){
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")
    [int]$NetVersionKey= $RegKey.GetValue("Release")
    if($NetVersionKey -ge 378389) {return $true}
    }
    return $false
  
}

#Function will get the current date and time of the local system and place it in the following format 
# [MM/DD/YYYY hh:mm:ss]
Function Get-DateTimeLogFormat {
    $date = Get-Date
    $dtFormat = "[" + $date.Month + "/" + $date.Day + "/" + $date.Year + " " + $date.Hour + ":" + $date.Minute + ":" + $date.Second + "]"
    return $dtFormat
}

Function Write-ToLog([string]$LogPath,$WriteData) {
    if(Test-Path $LogPath){
    $time = Get-DateTimeLogFormat
    if($WriteData.Gettype().Name -eq "String"){
        
        $log = $time + " : " + $WriteData
        $log | Out-File $LogPath -Append
    }
    else {
        $log = $time + " : "
        $log | Out-File $LogPath -Append
        $WriteData | Out-File $LogPath -Append
    }
    }
}

#This function will write the data that you would like to the log file 
Function Write-ToLogScript ($WriteData) {
    Write-ToLog $logLocation $WriteData     
}


#Function to check and create folder if needed
Function create-Folder ($checker) {

    if((Test-Path -Path $checker) -eq $False) {
        $wData = "Creating Directory $checker" 
        Write-Host $wData
        if($ScriptLoggingDebug) {
            Write-ToLogScript $wData
        }
        $temp = [System.IO.Directory]::CreateDirectory($checker)
    }

    else{
        $wData = "$checker is already created!" 
        Write-Host $wData
        if($ScriptLoggingDebug) {
            Write-ToLogScript $wData
        }
    }

}

#Function to adjust the date 
Function AdjustMyDate() {

$Date = (get-date).AddDays(0-$DaysWorth)
$copyToDate = "$($Date.Month)/$($Date.Day)/$($Date.Year)"
return $copyToDate

}



Function zipAllIt {

	#Change to the Script Location 
	cd $scriptLocation
	
    #if no zip is not selected 
    if($NOZIP -eq $False){
	    
        #Date For the zip folder 
	    $date = Get-Date -Format Md
	
	    #file Name
	    $zipFolder = "$targetDir-$date.zip"
		
		$i = 1
		while((Test-Path $zipFolder) -eq $True){
		
			$zipFolder = "$targetDir-$date-$i.zip"
			$i++
		}
	    $wData = "Almost done....zipping everything up now"
        Write-Host $wData

        if($ScriptLoggingDebug) {
            Write-ToLogScript $wData
            $wData = "Target Folder:"
            Write-CombineStrings $wData $targetDir
            $wData = "Zip Location:"
            Write-CombineStrings $wData $zipFolder
        }

	    #zip the file 
	    if($SevenZipIt -eq $True) {
	        if($ScriptLoggingDebug){
                $wData = "Using Seven Zip"
                Write-ToLogScript $wData
            }
		    .\7za.exe a -tzip -r $zipFolder $targetDir
	
	    }
	
	    elseif ($SevenZipIt -eq $False) {
            
            if($ScriptLoggingDebug) {
                $wData = ".NET Framework is Zipping up the folder"
                Write-ToLogScript $wData
            }
		    [system.io.compression.zipfile]::CreateFromDirectory($targetDir, $zipFolder)
	
	    }
		
        if((Test-Path -Path $zipFolder) -eq $true) {

            Remove-Item $targetDir -Force -Recurse
            if($ScriptLoggingDebug) {
            $wData = "Sucessfull at zipping up the folder" 
            Write-ToLogScript $wData
            }
        }

   }

}



#Function Zip it Folder
Function zipItFolder($Folder) {

	#Zip up the folder that you want 
	#Change to the Script Location 
	cd $scriptLocation

    if ($NoZip -eq $False) {
	    $zipFolder = "$Folder.zip"
        $wData = "Zipping up the $Folder"
        Write-Host $wData
        
        if($ScriptLoggingDebug) {
                Write-ToLogScript $wData
                $wData = "Zip Folder Name:"
                Write-CombineStrings $wData $zipFolder
                $wData = "Folder Name:"
                Write-CombineStrings $wData $Folder
        }

	    #if we have 7za on the server 
	    if($SevenZipIt -eq $True) {
            $wData = "Seven Zip is Zipping up the folder: " + $Folder 
            if($ScriptLoggingDebug){ Write-ToLogScript $wData}
		    .\7za.exe a -tzip -r $zipFolder $Folder
	    }
	    else{
            $wData = ".NET Framework is Zipping up the folder: " + $Folder
            if($ScriptLoggingDebug){ Write-ToLogScript $wData}
		    [system.io.compression.zipfile]::CreateFromDirectory($Folder, $zipFolder)	
	    }

        #We want to remove the original only if we were able to create the zip folder 
        if((Test-Path -Path $zipFolder) -eq $true) {
            if($ScriptLoggingDebug) {
            $wData = "Sucessfull at zipping up the folder" 
            Write-ToLogScript $wData
            }
            Remove-Item $folder -Force -Recurse
        }

    } #end of No zip eq false 

    else {
        if($ScriptLoggingDebug) {
            $wData = "No Zip was set to true...moving onto the next folder"
            Write-ToLogScript $wData
        }
    }

}

#Function to test if you are an admin on the server 
Function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    If( $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    }
    else {
        return $false
    }
}

Function Bulk-CopyItems([string]$CopyTo,[array]$ItemsToCopy) {
    
    create-Folder($CopyTo)
    foreach($item in $ItemsToCopy) {
        if($ScriptLoggingDebug){
            $wData = "Copying Item:"
            Write-CombineStrings $wData $item
            $wData = "To Location:"
            Write-CombineStrings $wData $item
        }
        copy $item $CopyTo
    }

}

Function Copy-FullLogFolderPathRecurse([string]$FolderName, [string]$LogPath) {
    
    $copyTo = "$targetDir\$FolderName"
    create-Folder $copyTo
    copy $LogPath\* $copyTo -Recurse
    zipItFolder $copyTo

}

Function FilesToCopyFunction() {
	

	$CopyToDate = AdjustMyDate
	$Files = Get-ChildItem | Sort LastWriteTime -Descending | ?{$_.LastWriteTime -ge $CopyToDate}
	
	if($Files -eq $null){
	
		Write-Warning "Oops! Looks like I wasn't able to find what you are looking for, so I am going to collect the newest log for you"
		$Files = Get-ChildItem | Sort LastWriteTime -Descending | Select -First 1 
		
		#Now check again to see if it is null 
		if($Files -eq $null){
			
			$here = Get-Location
			Write-Warning "Hey, it doesn't look like you have any data in this location $here.path"
			Write-Warning "I am going to throw an error now, please look into this issue"
			sleep 5 
		
		}
	
	}
	
	return $Files
	
}


Function Collect-LogsBasedOnTime ($FolderName, $LogPath) {
    
    $copyTo = "$targetDir\$FolderName"

    create-Folder $copyTo
    #Need to CD into that directory as FilesToCopyFunction requires you to be in that directory 
    cd $LogPath
    $FilesToCopy = FilesToCopyFunction

    if($FilesToCopy -ne $null) {
        if($ScriptLoggingDebug) {
            $wData = "Copying These Files:" 
            Write-ToLogScript $wData
            Write-ToLogScript $FilesToCopy
            $wData = "Copying to this location:"
            Write-ToLogScript $copyTo
        }
        copy $FilesToCopy $copyTo
        zipItFolder $copyTo 
    }

    else{
        $wData = "Didn't attempt to copy over any data into this folder $FolderName from this folder path"
        Write-Warning $wData
        Write-Warning $LogPath
        $tempFile = $copyTo + "\NoFiles.txt"
        New-Item $tempFile -ItemType file -Value $LogPath
        if($ScriptLoggingDebug) {
            Write-ToLogScript $wData
            $wData = "Log Folder Location:"
            Write-CombineStrings $wData $LogPath
        }
    }
    

    cd $scriptLocation
}


Function Collect-ManagedAvailabilityLogs {
    $Logs = $ProbeResultsLogs, $RecoveryActionResultsLogs, $RecoveryActionLogs, $ResponderDefLogs, $ResponderResultsLogs, $MonitorDefLogs, $MonitoringLogs
	#Create AppSysLogsDirectory 
	$Folder = "MA_Logs"
	#copy items to this location
	$copyTo = "$targetDir\$Folder"
    Bulk-CopyItems $copyTo $Logs
    RemoveEventLogChar $copyTo 
	#Zip the folder 
	zipItFolder($copyTo)
}

Function RemoveEventLogChar ($location) {
    Get-ChildItem $location | Rename-Item -NewName {$_.Name -replace "%4","-"}
}

#NOTETOCHECKHERE - include csv export type by default - Tried this but it took too long the way I found to do it
Function Collect-AppSysLogs {
    $Logs = $AppLog, $SysLog, $MSManLogs
	#Create AppSysLogsDirectory 
	$Folder = "App_Sys_Logs"
	#copy items to this location
	$copyTo = "$targetDir\$Folder"
    Bulk-CopyItems $copyTo $Logs
    #Get-WinEvent -LogName Application | Select TimeCreated, MachineName, LevelDisplayName, ID, ProviderName, TaskDisplayName, Message | Export-Csv "$copyTo\App.csv"
    #Get-WinEvent -LogName Application | Select TimeCreated, MachineName, LevelDisplayName, ID, ProviderName, TaskDisplayName, Message | Export-Csv "$copyTo\Sys.csv"
    #This takes way to long to do
	zipItFolder $copyTo
}

Function Bool-CheckServerIsDAGMember($serverName) {
	
	$dags = Get-DatabaseAvailabilityGroup 
	foreach($dag in $dags) {
		foreach($server in $dag.Servers){
			if($server.Name -eq $serverName) { return $true} 
		}
	}	
	return $false 	
}

Function Collect-HighAvailabilityLogs{

    if($ServerObject.Mailbox) {
        $Folder = "High_Availability_Logs"
        $copyTo = "$targetDir\$Folder"

        create-Folder $copyTo
        if(Bool-CheckServerIsDAGMember $serverName){
            if($ScriptLoggingDebug) {
                $wData = "We are a mailbox server and have the cluster feature installed. Collecting Cluster logs"
                Write-ToLogScript $wData
            }
	        Cluster log /g
            if($ScriptLoggingDebug) {
                $wData = "We finished running 'cluster log /g' "
                Write-ToLogScript $wData
            
            }
	        $logFile = "$systemRoot\Cluster\Reports\Cluster.log"
            if($ScriptLoggingDebug){
                $wData = "Copying the cluster logs over"
                Write-ToLogScript 
            }
	        Copy $logFile $copyTo

        }

        #If it is 2013 or 2010 would determine the HA logs we need to collect 
        if($ServerObject.Version -eq 15){
            Collect-HighAvailabilityLogs_2013 $copyTo 
        }
        else {
            Collect-HighAvailabilityLogs_2010 $copyTo 
        }

        RemoveEventLogChar $copyTo
        zipItFolder($copyTo)
    }

    else {
        
        $wData = "Doesn't look like you have the Mailbox Role, not going to collect the clustering information" 
        Write-Host $wData 
        if($ScriptLoggingDebug) {
            Write-ToLogScript $wData
        }

    }

}

Function Collect-HighAvailabilityLogs_2013 ($copyTo) {

    $AllLogs = $HAAppLogMirror, $HABlockReplication, $HADebug, $HAMonitoring, $HANetwork, $HAOperational, $HASeeding, $HATruncationDebug, $MDFOperational, $MDFDebug
    Bulk-CopyItems $copyTo $AllLogs 

}

Function Collect-HighAvailabilityLogs_2010 ($copyTo) {
    
    $AllLogs = $HABlockReplication, $HADebug, $HAOperational, $HASeedingDebug, $HATruncationDebug, $MDFOperational, $MDFDebug
    Bulk-CopyItems $copyTo $AllLogs

}

Function Is-Mailbox ([string]$ServerRole) {
    
    if($ExServerRole -like "*Mailbox*") {
        return $True
    }
    $false 
}

Function Is-Hub([string]$ServerRole){

    if($ExServerRole -like "*HubTransport*") {
        return $True
    }
    $false     
}

Function Is-ClientAccess([string]$ServerRole){
    if($ExServerRole -like "*ClientAccess*") {
        return $True
    }
    $false   
}

Function Build-ServerObject {

    $serverName = hostname 
    $ExVersion = (get-exchangeserver -Identity $ServerName).AdminDisplayVersion.Major
    $ExServerRole = (get-exchangeserver -Identity $ServerName).ServerRole
    $obj = New-Object -TypeName ServerObject 
    $obj.ServerName =  $serverName
    $obj.Version = $ExVersion
    $obj.Mailbox = (Is-Mailbox $ExServerRole)
    $obj.Hub = (Is-Hub $ExServerRole)
    $obj.Cas = (Is-ClientAccess $ExServerRole)
    $Script:ServerObject = $obj 
}


Function Collect-CustomData {

	#Label EWS Folder 
	$Folder = "Custom_Folder_Logs"
	
	#copy items to this location
	$copyTo = "$targetDir\$Folder"
	
	createFolder($copyTo)

	#copy all the data in that directory 
	copy $CustomDataDirectory\* $copyTo -Recurse
	
	#Zip the folder 
	zipItFolder($copyTo)
	
}


Function Get-VdirsLDAP {

$authTypeEnum = @" 
namespace AuthMethods  
{
	using System;
	[Flags]
    public enum AuthenticationMethodFlags
    {
        None = 0,
        Basic = 1,
        Ntlm = 2,
        Fba = 4,
        Digest = 8,
        WindowsIntegrated = 16,
        LiveIdFba = 32,
        LiveIdBasic = 64,
        WSSecurity = 128,
        Certificate = 256,
        NegoEx = 512,
		// Exchange 2013
        OAuth = 1024,
        Adfs = 2048,
        Kerberos = 4096,
        Negotiate = 8192,
        LiveIdNegotiate = 16384,
    }
}
"@

Add-Type -TypeDefinition $authTypeEnum -Language CSharp

$objRootDSE = [ADSI]"LDAP://rootDSE"
$strConfigurationNC = $objRootDSE.configurationNamingContext
$objConfigurationNC = New-object System.DirectoryServices.DirectoryEntry("LDAP://$strConfigurationNC")
$searcher = new-object DirectoryServices.DirectorySearcher
$searcher.filter = "(&(objectClass=msExchVirtualDirectory)(!objectClass=container))" 
$searcher.SearchRoot = $objConfigurationNC
$Searcher.CacheResults = $false  
$Searcher.SearchScope = "Subtree"
$Searcher.PageSize = 1000  

# Get all the results
$colResults  = $searcher.FindAll()

$objects = @()

# Loop through the results and
foreach ($objResult in $colResults)
{
	$objItem = $objResult.getDirectoryEntry()
	$objProps = $objItem.Properties
	
	$place = $objResult.Path.IndexOf("CN=Protocols,CN=")
	$ServerDN = [ADSI]("LDAP://" + $objResult.Path.SubString($place,($objResult.Path.Length - $place)).Replace("CN=Protocols,",""))
	[string]$Site = $serverDN.Properties.msExchServerSite.ToString().Split(",")[0].Replace("CN=","")
	[string]$server = $serverDN.Properties.adminDisplayName.ToString()
    [string]$version = $serverDN.Properties.serialNumber.ToString()
    

    $obj = New-Object PSObject 
    $obj | Add-Member -MemberType NoteProperty -name Server -value $server
	$obj | Add-Member -MemberType NoteProperty -name Version -value $version
	$obj | Add-Member -MemberType NoteProperty -name Site -value $Site
	[string]$var = $objProps.DistinguishedName.ToString().Split(",")[0].Replace("CN=","")
    $obj | Add-Member -MemberType NoteProperty -name VirtualDirectory -value $var
	[string]$var = $objProps.msExchInternalHostName
	$obj | Add-Member -MemberType NoteProperty -name InternalURL -value $var
	
	if (-not [string]::IsNullOrEmpty($objProps.msExchInternalAuthenticationMethods))
	{
		$obj | Add-Member -MemberType NoteProperty -name InternalAuthenticationMethods -value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchInternalAuthenticationMethods)
	}
	else
	{
		$obj | Add-Member -MemberType NoteProperty -name InternalAuthenticationMethods -value $null
	}
	
	[string]$var = $objProps.msExchExternalHostName
	$obj | Add-Member -MemberType NoteProperty -name ExternalURL -value $var 

	if (-not [string]::IsNullOrEmpty($objProps.msExchExternalAuthenticationMethods))
	{
		$obj | Add-Member -MemberType NoteProperty -name ExternalAuthenticationMethods -value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchExternalAuthenticationMethods)
	}
	else
	{
		$obj | Add-Member -MemberType NoteProperty -name ExternalAuthenticationMethods -value $null
	}
	
	if (-not [string]::IsNullOrEmpty($objProps.msExch2003Url))
	{
		[string]$var = $objProps.msExch2003Url
		$obj | Add-Member -MemberType NoteProperty -name Exchange2003URL  -value $var
	}
	else
	{
		$obj | Add-Member -MemberType NoteProperty -name Exchange2003URL -value $null
	}
	
	[Array]$objects += $obj
}

$vdirfile = $targetDir + "\ConfigNC_msExchVirtualDirectory_All.CSV"
$objects | Sort-Object -Property Server | Export-Csv $vdirfile -NoTypeInformation

}

Function Write-MSInfo($targetDirectory){
    msinfo32.exe /nfo $targetDirectory\msinfo.nfo
    Write-Warning "Waiting for msinfo32.exe process to end before moving on..."
    while ((Get-Process | ?{$_.ProcessName -eq "msinfo32"}).ProcessName -eq "msinfo32") {
        sleep 5; 
    }
}

#Add Logging and Adjust this function 
Function Get-ServerInfo {
    $Folder = "General_Server_Info" 
    $tDir = "$targetDir\$Folder"
    create-Folder $tDir
    Write-MSInfo $tDir 
    Gcm exsetup | %{$_.FileversionInfo} > "$tDir\GCM.txt"
    fltmc > "$tDir\FilterDrivers.txt"
    Get-HotFix | Select Source, Description, HotFixID, InstalledBy, InstalledOn | Export-Clixml "$tDir\HotfixInfo.xml"
    Get-ExchangeServer $serverName -Status | Export-Clixml "$tDir\ExchangeServerInfo_$serverName.xml"
    zipItFolder $tDir
}


Function checkMyDiskSpace {

	$driveLetter = $FilePath.split("\")
	$freeSpace = gwmi win32_volume -Filter 'drivetype = 3' | ?{$_.DriveLetter -eq $driveLetter[0]} |  select DriveLetter, label, @{LABEL='GBfreespace';EXPRESSION={$_.freespace/1GB} }
	
	#Check to see if the drive is above 15GB default 
	if ($freeSpace.GBfreespace -gt $checkSize) {
	
		Write-Host "We have more than $checkSize GB of free space at $FilePath"
		Write-Host "Moving on...."
        Write-Host " "
			
	}
	
	elseif ($freeSpace.GBfreespace -lt $checkSize) {
	
		Write-Warning "We have less than $checkSize GB of free space on $FilePath"
		Write-Warning "Please use the DiskCheckOverride switch if this is a mistake or if you would like to proceed any ways" 
		exit
	
	}

}

#check to see if the base folder is already created or not if it is add a -1 to the name 
Function BaseFolderCheck ($ThisFolder) {

    if((Test-Path $ThisFolder) -eq $True){

        #add onto the root 
        [int]$i = 1
        $ThisFolderAdded = "$ThisFolder" + "-" + "$i"

        while((Test-Path $ThisFolderAdded) -eq $True) {

            $ThisFolderAdded = "$ThisFolder" + "-" + "$i"

            $i++

        }

        #set added folder to ThisFolder 
        $ThisFolder = $ThisFolderAdded
    }

    #in the end we still want to create the folder 
    $Script:targetDir = $ThisFolder

}

Function Test-CommandExists {

 Param ($command)

 $oldPreference = $ErrorActionPreference

 $ErrorActionPreference = 'stop'

 try {if(Get-Command $command){RETURN $true}}

 Catch {Write-Host "$command does not exist"; RETURN $false}

 Finally {$ErrorActionPreference=$oldPreference}

} 

<#

    DAG Information Functions 

#>

Function Export-FileAndXMLData($dataIn, $FolderPath, $FileName) {

    $xmlOut = $FolderPath + "\" + $FileName + ".xml"
    $txtOut = $FolderPath + "\" + $FileName + ".txt" 
    if($dataIn -ne $null){
        $dataIn | Export-Clixml $xmlOut -Encoding UTF8
        $dataIn | fl | Out-File $txtOut 
    }
}

Function Get-FolderwithFullPath ($FolderName) {
    $fullpath = $targetDir + "\" + $FolderName
    return $fullpath
}

Function Get-DatabaseAvailabilityGroupInfo ($dagName) {
    $data = Get-DatabaseAvailabilityGroup $dagName -Status
    return $data
}

Function Get-DatabaseAvailabilityGroupNetworkInfo ($dagName) {
    $data = Get-DatabaseAvailabilityGroupNetwork $dagName
    return $data
}

Function Get-MailboxDatabaseCopyStatusPerDatabase ($mbxDB_name) {
    $data = Get-MailboxDatabaseCopyStatus $mbxDB_name\*
    return $data
}

Function Get-DatabaseInformationOnServer ($serverName) {

    $dbs = Get-MailboxDatabase -Server $serverName
    $FolderName = $serverName + "_Databases_Info"
    $FolderPath = Get-FolderwithFullPath $FolderName
    create-Folder $FolderPath
    foreach($db in $dbs) {
        $FileName = $db.Name + "_CopyStatus"
        $dbcopyinfo = Get-MailboxDatabaseCopyStatusPerDatabase $db.name 
        Export-FileAndXMLData $dbcopyinfo $FolderPath $FileName
    }

}

Function Get-DagInformation {

    $FolderName = "DAG_Information"
    if(Bool-CheckServerIsDAGMember $serverName){
        $DAGName = (Get-MailboxServer $serverName).DatabaseAvailabilityGroup.Name
        $DAGInfo = Get-DatabaseAvailabilityGroupInfo $DAGName
        $folderPath = Get-FolderwithFullPath $FolderName 
        create-Folder $folderPath
        $fileName = $DAGName + "_DAG_Info"
        Export-FileAndXMLData $DAGInfo $folderPath $fileName
        $DAGNetInfo = Get-DatabaseAvailabilityGroupNetworkInfo $DAGName
        $fileName = $DAGName + "_DAG_Network_Info"
        Export-FileAndXMLData $DAGNetInfo $folderPath $fileName 
        Get-DatabaseInformationOnServer $serverName 
    }

}


<#

   IIS Logging Directory Finding information 

#>


#updated version of us loading the IIS vars information 
Function Load-IISVars {

#Going to check to see if we have the Get-WebConfigurationProperty cmdlet 
if((Test-CommandExists Get-WebConfigurationProperty)) {
	[string]$IisLogPath = ((Get-WebConfigurationProperty "system.applicationHost/sites/siteDefaults" -Name logFile).directory).Replace("%SystemDrive%",$env:SystemDrive) 
	$script:IISLogDirectory = $IisLogPath
}

elseif ($IISLogDirectory -eq ""){

#IIS Information 
$IISLogDirectory = "C:\inetpub\logs\LogFiles\"
$testPath = "$IISLogDirectory\W3SVC1" #we should always be seeing the W3SVC1 directory 
if(Test-Path $testPath){ $script:IISLogDirectory = $IISLogDirectory }

}

else {
	    $testPath = "$IISLogDirectory\W3SVC1"
	    if(Test-Path $testPath){$script:IISLogDirectory = ""}
    }
    
}

#This function will just test to see if we have multiple sites and multiple w3svc directories depending on the version of Exchange 
Function Bool-IISMultiW3SVCDirectories  {

if($ServerObject.Version -eq 15){
	    $test = "$IISLogDirectory\W3SVC3"
	    if(Test-Path $test){return $true }
	    else {return $false}
    }

else {
	    $test = "$IISLogDirectory\W3SVC2"
	    if(Test-Path $test){return $true}
	    else {return $false}
    }

}


<#

   End - IIS Logging Directory Finding information - End 

#>



<#

    Logman functions 

#>


Function Start-Logman ($logmanName, $serverName) {

    Write-Host "Starting Data Collection $logmanName"
    logman start -s $serverName $logmanName

}

Function Stop-Logman ($logmanName, $serverName) {
    
    Write-Host "Stopping Data Collection $logmanName" 
    logman stop -s $serverName $logmanName

}

Function Get-LogmanStatus ($rawLogData) {

    $status = "Status:" 
    $stop = "Stopped"
    $run = "Running" 
    $currentStatus = "unknown"

    if($rawLogData[2].Contains($status) -ne $true) {
        $i = 0 
        $end = $rawLogData.Count 
        if($rawLogData[$i].Contains($status) -ne $true){
            do{
            $i++
            }while(($rawLogData[$i].Contains($status) -eq $false) -and ($i -lt ($end-1)))
        }
        
    }
    else{
        $i = 2
    }

    $sLine = $rawLogData[$i]
    
    
    if($sLine.Contains($stop)){
        $currentStatus = $stop
    }
    elseif($sLine.Contains($run)){
        $currentStatus = $run 
    }

    return $currentStatus 

}

Function Strip-RootPathFromString([string]$inString){

	$replace = $inString.Replace("Root Path:", "")
	[int]$IndexOf = $replace.IndexOf(":")
	$IndexOf-- 
	
	$sReturn = $replace.Substring($IndexOf)
	return $sReturn
}

Function Strip-StartDate([string]$inString) {

    [int]$index = $inString.LastIndexOf(" ")
    $rString = $inString.Substring($index+1)
    return $rString

}

Function Extract-ExtFromString([string]$inString) {
    
    $extString = "null"
    $testIndex = $inString.LastIndexOf(".")
    if($testIndex -ne -1) {
        $extString = $inString.Substring($testIndex)
    }
    return $extString 
}

Function Get-LogmanRootPath($rawLogmanData) {

    $rPath = "Root Path:" 

    if($rawLogmanData[3].Contains($rPath) -ne $true) {
        $i = 0
        $end = $rawLogmanData.Count 
        if($rawLogmanData[$i].Contains($rPath) -ne $true) {
            do{
               $i++
            }while(($rawLogmanData[$i].Contains($rPath) -eq $false) -and ($i -lt ($end-1)))

        }
    }

    else{
        $i = 3
    }

    $rLine = $rawLogmanData[$i]
    $sReturn = Strip-RootPathFromString $rLine
    return $sReturn
}

Function Get-LogmanStartDate($rawLogData) {

    $sStartDate = "Start Date:" 
    if($rawLogData[11].Contains($sStartDate) -ne $true) {
            $i = 0
            $end = $rawLogData.count 
            if($rawLogData[$i].Contains($sStartDate) -ne $true) {
                do{
                $i++
                }while(($rawLogData[$i].Contains($sStartDate) -eq $false) -and ($i -lt ($end - 1)))
            }

    }

    else{
        $i = 11 
    }

    $rLine = $rawLogData[$i]
    $sStart_Date = Strip-StartDate $rLine 
    return $sStart_Date
}


Function Get-LogmanExt($rawData) {

    $outLocation = "Output Location:" 
    if($rawData[15].Contains($outLocation) -ne $true) {
        $i = 0
        $end = $rawData.count 
        if($rawData[$i].Contains($outLocation) -ne $true) {
            do{
                $i++
            }while(($rawData[$i].Contains($outLocation) -eq $false) -and ($i -lt ($end - 1)))

        }
    }
    else{
        $i = 15
    }

    $raw_OutLocation = $rawData[$i]
    $ext = Extract-ExtFromString $raw_OutLocation

    return $ext
}

Function Build-LogmanObject($logmanName, $serverName) {

    $rawDataResults = logman -s $serverName $logmanName 
    $iTst = $rawDataResults.Count -1 
    if($rawDataResults[$iTst].Contains("Set was not found.")){
        $snull = "null"
        return $snull
    }
    else{
    $logManStatus = Get-LogmanStatus $rawDataResults 
    $logPath = Get-LogmanRootPath $rawDataResults
    $startDate = Get-LogmanStartDate $rawDataResults
    $ext = Get-LogmanExt $rawDataResults
    
    $objLogman = New-Object -TypeName PSObject 
    $objLogman | Add-Member -Name LogmanName -MemberType NoteProperty -Value $logmanName 
    $objLogman | Add-Member -Name Status -MemberType NoteProperty -Value $logManStatus
    $objLogman | Add-Member -Name RootPath -MemberType NoteProperty -Value $logPath 
    $objLogman | Add-Member -Name StartDate -MemberType NoteProperty -Value $startDate 
    $objLogman | Add-Member -Name Ext -MemberType NoteProperty -Value $ext
    $objLogman | Add-Member -Name StartLogman -MemberType NoteProperty -Value $false 

    return $objLogman 
    }
}

Function Copy-LogmanFilesBasedOnStartTime($objLogman) {
    
    $dir = $objLogman.RootPath 
    if(Test-Path $dir) {
        $wildExt = "*" + $objLogman.Ext 
        $date = $objLogman.StartDate
        $files = Get-ChildItem $dir | ?{($_.Name -like $wildExt) -and ($_.CreationTime -ge $date)}
        return $files
    }

    else {
        Write-Warning "Doesn't look like this Directory is valid"
        Write-Warning $dir 
        return $null
    }

}

Function Copy-LogmanData($objLogman, $logmanName) {

    Switch ($logmanName) 
    {
        $Experf_Logman_Name {$FolderName = "ExPerfWiz_Data"; break} #end Experf_Logman_Name
        $Exmon_Logman_Name { $FolderName = "ExmonTrace_Data"; break} #end of Exmon_Logman_Name
        default { $FolderName = $logmanName }

    }
    $copyTo = $targetDir + "\" + $FolderName 
    create-Folder $copyTo 
    $files = Copy-LogmanFilesBasedOnStartTime $objLogman
    if($files -ne $null) {
        foreach($file in $files){
        copy $file.VersionInfo.FileName $copyTo
        }
        zipItFolder $copyTo
    }
    else {
        Write-Warning "Failed to collect files from that directory..."

    }

}

Function Get-LogmanData($logmanName, $serverName) {
    
    $objLogman = Build-LogmanObject $logmanName $serverName 
    if($objLogman -ne "null") {

        Switch ($objLogman.Status)
        {

            "Running" {
                 Write-Host "Looks like Logman $logmanName is running...."
                 Write-Host "Going to stop $logmanName to prevent corruption...." 
                 $objLogman.StartLogman = $true 
                 Stop-Logman $logmanName $serverName
                 Copy-LogmanData $objLogman $logmanName
                 Write-Host "Starting Logman again...."
                 Start-Logman $logmanName $serverName
                 Write-Host "Done..."
                 break; 
                 }#end running 
            "Stopped"  {
                   Write-Host "Doesn't look like Logman $logmanName is running..."
                   Write-Host "Not going to stop it"
                   Copy-LogmanData $objLogman $logmanName
                   break; 
                  } #end stopped 
            default {
                    Write-Host "Don't know what status the Logman $logmanName is in"
                    Write-Host "This is the status:" 
                    $st = $objLogman.Status
                    Write-Host $st
                    Write-Host "Going to try to stop it just in case.."
                    Stop-Logman $logmanName $serverName
                    Copy-LogmanData $objLogman $logmanName
                    Write-Warning "Not going to start it however...." 
                    Write-Warning "Please start this if you need to..."
                    break; 
                    } #end default 

        }

    }

    else {

        Write-Host "Can't find $logmanName on $serverName .... Moving on." 
    }

}

Function Collect-LogmanExperfWiz {

    Get-LogmanData $Experf_Logman_Name $serverName 
}

Function Collect-LogmanExmon {

    Get-LogmanData $Exmon_Logman_Name $serverName
}

<#

   End - Logman functions - End

#>



<#

    Transport Related Functions 

#>

Function Get-HubTransportLogLocations([string]$serverName,[int]$version) {

    $hubObject = New-Object TransportServiceLogPathClass

    switch($version) {
    15{ 
        $data = Get-TransportService -Identity $serverName 
        $hubObject.ConnectivityLogPath = $data.ConnectivityLogPath.PathName
        $hubObject.MessageTrackingLogPath = $data.MessageTrackingLogPath.PathName
        $hubObject.PipelineTracingPath = $data.PipelineTracingPath.PathName
        $hubObject.ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.PathName
        $hubObject.SendProtocolLogPath = $data.SendProtocolLogPath.PathName
        $hubObject.QueueLogPath = $data.QueueLogPath.PathName
        $hubObject.WlmLogPath = $data.WlmLogPath.PathName
        break;
    }
    14{
        $data = Get-TransportServer -Identity $serverName
        $hubObject.ConnectivityLogPath = $data.ConnectivityLogPath.PathName
        $hubObject.MessageTrackingLogPath = $data.MessageTrackingLogPath.PathName
        $hubObject.PipelineTracingPath = $data.PipelineTracingPath.PathName
        $hubObject.ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.PathName
        $hubObject.SendProtocolLogPath = $data.SendProtocolLogPath.PathName
        break;
    }
    default{Write-Warning "Error! Don't know this version of Exchange" Write-Warning "Failing to collect data..."; $hubObject = $null }
    }

    return $hubObject
}

Function Get-FrontEndTransportLogsLocations([string]$serverName) {

    $feObject = New-Object FrontendTransportServiceLogPathClass
    $data = Get-FrontendTransportService -Identity $serverName
    $feObject.ConnectivityLogPath = $data.ConnectivityLogPath.PathName
    $feObject.ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.PathName
    $feObject.SendProtocolLogPath = $data.SendProtocolLogPath.PathName
    $feObject.AgentLogPath = $data.AgentLogPath.PathName
    return $feObject
}

Function Get-MailboxTransportLogsLocation([string]$serverName) {
    
    Build-TransportClasses
    $mbxObject = New-Object MailboxTransportServiceLogPathClass
    $data = Get-MailboxTransportService -Identity $serverName
    $mbxObject.ConnectivityLogPath = $data.ConnectivityLogPath.PathName
    $mbxObject.ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.PathName
    $mbxObject.SendProtocolLogPath = $data.SendProtocolLogPath.PathName
    $mbxObject.PipelineTracingPath = $data.PipelineTracingPath.PathName
    $mbxObject.MailboxDeliveryThrottlingLogPath = $data.MailboxDeliveryThrottlingLogPath.PathName
    return $mbxObject
}

Function Get-ReceiveConnectorInformation([string]$serverName) {
    $data = Get-ReceiveConnector -Server $serverName
    return $data 
}


Function Get-SendConnectorInformation {
    $data = Get-SendConnector 
    return $data
}

Function Get-QueueInformation([string]$serverName) {
    $data = Get-Queue -Server $serverName
    return $data
}

#Local only 
Function Get-TransportConfigFilesLocation([int]$version) {
    switch($version){
    15{
        $itemsToCopy = @()
        $itemsToCopy += $exbin + "\EdgeTransport.exe.config" 
        $itemsToCopy += $exbin + "\MSExchangeFrontEndTransport.exe.config" 
        $itemsToCopy += $exbin + "\MSExchangeDelivery.exe.config" 
        $itemsToCopy += $exbin + "\MSExchangeSubmission.exe.config"
        return $itemsToCopy
    }
    14{
        $copyThis = $exbin + "\EdgeTransport.exe.config" 
        return $copyThis
    }
    default{return $null}
    }

}


Function Collect-TransportLogInformationManager {

    if($ServerObject.Hub -eq $true -or $ServerObject.Version -eq 15) {

        switch($ServerObject.Version)
        {
            15{
                [MailboxTransportServiceLogPathClass]$mbxObject = Get-MailboxTransportLogsLocation $ServerObject.ServerName
                [FrontendTransportServiceLogPathClass]$feObject = Get-FrontEndTransportLogsLocations $ServerObject.ServerName
                [TransportServiceLogPathClass]$hubObject = Get-HubTransportLogLocations $ServerObject.ServerName $ServerObject.Version 
                break
              }
            14{ 
                [TransportServiceLogPathClass]$hubObject = Get-HubTransportLogLocations $ServerObject.ServerName $ServerObject.Version; break
            }
            default {Write-Error "Major Error occurred....Failed to collect Transport Log information";return}
        }

        

        if($MessageTrackingLogs){
            $Folder = "MessageTrackingLogs" 
            Collect-LogsBasedOnTime $Folder $hubObject.MessageTrackingLogPath
        }
        if($HubProtocolLogs){
            $Folder = "Hub_Send_Protocol_Logs"
            Collect-LogsBasedOnTime $Folder $hubObject.SendProtocolLogPath
            $Folder = "Hub_Receive_Protocol_Logs"
            Collect-LogsBasedOnTime $Folder $hubObject.ReceiveProtocolLogPath
        }
        if($HubConnectivityLogs){
            $Folder = "Hub_Connectivity_Logs"
            Collect-LogsBasedOnTime $Folder $hubObject.ConnectivityLogPath
        }

        if($QueueInformationThisServer){
            $Folder = "Queue_Data" 
            $pFolder = $targetDir + "\" + $Folder 
            $CurrentQueue = Get-QueueInformation $ServerObject.ServerName 
            create-Folder $pFolder
            $copyTo = $pFolder + "\" + "Current_Queue_Info.txt"
            $CurrentQueue | fl > $copyTo
            $copyTo = $pFolder + "\" + "Current_Queue_Info.xml"
            $CurrentQueue | Export-Clixml $copyTo
            if($ServerObject.Version -eq 15){
                $Folder = "Queue_V15_Logging"
                Collect-LogsBasedOnTime $Folder $hubObject.QueueLogPath
            }
        }
        if($ReceiveConnectors) {
           $Folder = "Connectors" 
           $pFolder = $targetDir + "\" + $Folder
           create-Folder $pFolder
           $data = Get-ReceiveConnectorInformation $ServerObject.ServerName 
           $copyTo = $pFolder + "\" + "Receive_Connectors.txt" 
           $data | fl | Out-File $copyTo 
           $copyTo = $pFolder + "\" + "Receive_Connectors.xml" 
           $data | Export-Clixml $copyTo 
        }
        if($SendConnectors) {
            $Folder = "Connectors"
            $pFolder = $targetDir + "\" + $Folder
            create-Folder $pFolder 
            $data = Get-SendConnectorInformation
            $copyTo = $pFolder + "\" + "Send_Connectors.txt" 
            $data | fl | Out-File $copyTo 
            $copyTo = $pFolder + "\" + "Send_Connectors.xml" 
            $data | Export-Clixml $copyTo 
        }
        if($TransportConfig) {

            $files = Get-TransportConfigFilesLocation $ServerObject.Version
            $copyTo = $targetDir + "\Transport_Configuration"
            if($files.count -gt 1){
                $copyTo = $targetDir + "\Transport_Configuration"
                Bulk-CopyItems $copyTo $files 
            }
            else{
                create-Folder $copyTo
                copy $files $copyTo    
            }
            $file = $copyTo + "\TransportConfig.xml" 
            $data = Get-TransportConfig 
            $data | fl * | Export-Clixml $file 
            $file = $copyTo + "\TransportConfig.txt" 
            $data | fl * | Out-File $file 
            $file = $copyTo + "\TransportAgent.xml" 
            $data = Get-TransportAgent 
            $data | fl * | Export-Clixml $file
            $file = $copyTo + "\TransportAgent.txt" 
            $data | fl * | Out-File $file
        }

        if($ServerObject.Version -eq 15){
           if($FrontEndConnectivityLogs){
                $Folder = "FE_Connectivity_Logs"
                Collect-LogsBasedOnTime $Folder $feObject.ConnectivityLogPath
            }

            if($FrontEndProtocolLogs){
                $Folder = "FE_Send_Protocol_Logs"
                Collect-LogsBasedOnTime $Folder $feObject.SendProtocolLogPath
                $Folder = "FE_Receive_Protocol_Logs"
                Collect-LogsBasedOnTime $Folder $feObject.ReceiveProtocolLogPath
            }

            if($MailboxConnectivityLogs){
                $Folder = "MBX_Delivery_Connectivity_Logs"
                $DeliveryPath = $mbxObject.ConnectivityLogPath + "\Delivery"
                $SubmissionPath = $mbxObject.ConnectivityLogPath + "\Submission"
                Collect-LogsBasedOnTime $Folder $DeliveryPath
                $Folder = "MBX_Submission_Connectivity_Logs"
                Collect-LogsBasedOnTime $Folder $SubmissionPath
            }

            if($MailboxProtocolLogs){
                $Folder = "MBX_Receive_Protocol_Logs"
                Collect-LogsBasedOnTime $Folder $mbxObject.ReceiveProtocolLogPath
                $Folder = "MBX_Send_Protocol_Logs"
                Collect-LogsBasedOnTime $Folder $mbxObject.SendProtocolLogPath
            }

        }
    }

    else{
        Write-Host "Doesn't look like you are a HUB role server.... Moving on...."
    }
}

<#

 End - Transport Related Functions - End

#>


Function Check-SevenZip {
    
    if((Test-Path $scriptLocation\7za.exe) -eq $false) {
        Write-Warning "It doesn't look like you have 7za available in the script location. Here is what i am looking for: "
        $wData = $scriptLocation + "\7za.exe"
        Write-Warning $wData
        Write-Host " "
        Write-Host "I am not going to be able to zip up anything for you, would you like to continue?" 
        do{
            [string]$sAnswer = Read-Host "Please enter 'y' or 'n': " 
        }while ([string]$sAnswer -ne 'y' -and [string]$sAnswer -ne 'n')

        if($sAnswer -eq "y") {
            $Script:NOZIP = $True 
            Write-Host "Changing the Free Space to 25 GB requirement" 
            $Script:checkSize = 25 
        }
        else{
            Write-Host "You selected 'n', so i am going to exit out of the script"
            Write-Host "Bye!" 
            exit 
        }
    }

}

Function Load-IOCompression {

    if($ServerObject.Version -eq 15) {
        Add-Type -AssemblyName System.IO.Compression.Filesystem 
    }
    else{
        #Check for .NET Framework 4.5
        Write-Host "Checking .NET Framework version....."
        if(Bool-CheckNETFrameVersion45GT){
            Write-Host "You have .NET Framework 4.5 or greater, I will be able to zip up your data for you" 
            Add-Type -AssemblyName System.IO.Compression.Filesystem 
        }
        else{

        Write-Warning "Hey, I don't know how to zip up data without .NET Framework 4.5"
        Write-Warning ".NET Framework is not needed for Exchange 2010, so you are not required to have it" 
        Write-Warning "In order to zip up data automatically for you, I need 7za.exe located in my script directory, or i will just not zip"
        Write-Host " " 
        Write-Host "Would you like to continue and not zip up the files?" 
        do{
            [string]$sAnswer = Read-Host "Please enter 'y' or 'n': "
        }while([string]$sAnswer -ne 'y' -and [string]$sAnswer -ne 'n') 
        if($sAnswer -eq "y") {
            $Script:NOZIP = $true
            Write-Host "Changing the Free Space to 25 GB requirement"
            $Script:checkSize = 25
        }
        else{
            Write-Host "You selected 'n', so i am going to exit out of the script"
            Write-Host "Bye!" 
            exit 
        }
        }
    }

}




###############################################
#                                             #
#              Main Function                  #
#                                             #
###############################################

Function Main {
    
    if((Is-Admin) -eq $false) {
        Write-Warning "Hey! The script needs to be executed in elevated mode. Start the Exchange Mangement Shell as an Administrator." 
        exit
    }
    Load-ExShell
    Load-VarScripts
    Build-ServerObject
    #Note: IIS Vars need to be loaded 

    if($SevenZipIt -eq $true -and $ServerObject.Version -ne 15){
        Check-SevenZip 
    }
    else {
        Load-IOCompression
    }
    create-Folder $FilePath 
    BaseFolderCheck $targetDir 
    create-Folder $targetDir
    if($DiskCheckOverride -ne $true) {
        checkMyDiskSpace
    }

}

Function Read-ExecuteCmds {

    $cmdsToRun = @()
    #########################
    #                       #
    #     Exchange 2013     #
    #                       #
    #########################

    if($ServerObject.Version -eq 15) {
        
        if($EWSLogs) {
            if($ServerObject.Mailbox) {
                $Folder = "EWS_BE_Logs"
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else{$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$EWSBELogFilePath'"}
            }
            if($ServerObject.CAS) {
                $Folder = "EWS_Proxy_Logs"
                if($CollectAllLogsBasedOnDaysWorth){  } #Add
                else{$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$EWSProxyLogFilePath'"}
            }
        } #End EWS

        if($DailyPerformanceLogs){
            $Folder = "Daily_Performance_Logs"
            $cmdsToRun += "Collect-LogsBasedOnTime $Folder '$DailyPerformanceDirectory'"
        }#End Daily Performance Logs 

        if($IISLogs) {
            Load-IISVars
            if($IISLogDirectory -ne ""){
                if((Bool-IISMultiW3SVCDirectories) -eq $false){
                    if($ServerObject.Cas){
                        $Folder = "IIS_FE_Logs"
                        $IISBEDirectory = "$IISLogDirectory\W3SVC1"
                        $cmdsToRun = $cmdsToRun + "Collect-LogsBasedOnTime $Folder '$IISBEDirectory'"
                    }
                    if($ServerObject.Mailbox){
                        $Folder = "IIS_BE_Logs"
                        $IISBEDirectory = "$IISLogDirectory\W3SVC2"
                        $cmdsToRun = $cmdsToRun + "Collect-LogsBasedOnTime $Folder '$IISBEDirectory'"
                    }
                }
                else{
                    $Folders = Get-ChildItem $IISLogDirectory
                    foreach($folder in $Folders.Name) {
                        if($folder -like "W3SVC*"){
                        	$sFolder = "IIS_" + $folder + "_Logs"
				            $IISCopyDirectory = $IISLogDirectory + "\" + $folder 
				            $cmdsToRun = $cmdsToRun + "Collect-LogsBasedOnTime $sFolder '$IISCopyDirectory'"
				        }
                    }
                }
                $folder = "HTTPERR_Logs" 
                $cmdsToRun = $cmdsToRun + "Collect-LogsBasedOnTime $folder '$HttpErrDirectory'"
            }
        }

        if($ManagedAvailability) {
            $cmdsToRun += "Collect-ManagedAvailabilityLogs"
        }#End Managed Availability 

        if($RPCLogs) {
            if($ServerObject.CAS) {
                $Folder = "RCA_Proxy_Logs" 
                if($CollectAllLogsBasedOnDaysWorth){ } #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$RPCProxyLogFilePath'"}
            }
            if($ServerObject.Mailbox){
                $Folder = "RCA_Logs"
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else{$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$RCALogFilePath'"}
            }
            $Folder = "RPC_Http_Logs"
            if($CollectAllLogsBasedOnDaysWorth) { } #Add
            else{$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$RPCHttpLogFilePath'"}
        } #End PRC Logs 

        if($EASLogs -and $ServerObject.CAS) {
            $Folder = "EAS_Proxy_Logs"
            if($CollectAllLogsBasedOnDaysWorth) { } #Add 
            else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$EASProxyLogFilePath'"}
        } #End EAS 

        if($AutoDLogs) {
            if($ServerObject.CAS) {
                $Folder = "AutoD_Proxy_Logs" 
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$AutoDProxyLogFilePath'"}
            }
            if($ServerObject.Mailbox){
                $Folder = "AutoD_Logs" 
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$AutoDLogFilePath'"}
            }
        } #End AutoD 

        if($OWALogs) {
            if($ServerObject.CAS) {
                $Folder = "OWA_Proxy_Calendar_Logs"
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$OWACalendarProxyLogFilePath'"}
                $Folder = "OWA_Proxy_Logs" 
                if($CollectAllLogsBasedOnDaysWorth) { } #add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$OWAProxyLogFilePath'"}
            }
            if($ServerObject.Mailbox) {
                $Folder = "OWA_Logs"
                if($CollectAllLogsBasedOnDaysWorth) { } # Add 
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$OWALogFilePath'"}
            } 

        }#End OWA Logs 

        if($ADDriverLogs) {
            $Folder = "AD_Driver_Logs" 
            if($CollectAllLogsBasedOnDaysWorth) { } #Add
            else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$ADDriverLogFilePath'"}
        } #End AD Driver 

        if($MapiLogs) {
            if($ServerObject.CAS) {
                $Folder = "MAPI_Proxy_Logs"
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$MAPIProxyFilePath'"}
            }
            if($ServerObject.Mailbox) {
                $Folder = "MAPI_Logs" 
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$MapiLogsFilePath'"}
            }

        } #End Mapi Logs 

        if($ECPLogs) {
            if($ServerObject.CAS) {
                $Folder = "ECP_Proxy_Logs"
                if($CollectAllLogsBasedOnDaysWorth) {} #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$ECPProxyLogFilePath'"}
            }
            if($ServerObject.Mailbox) {
                $Folder = "ECP_Logs"
                if($CollectAllLogsBasedOnDaysWorth) { } #Add
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$ECPLogFilePath'"}
            }
        }

        if($SearchLogs) {
            if($ServerObject.Mailbox) {
                $Folder = "Search_Diag_Logs"
                $cmdsToRun += "Collect-LogsBasedOnTime $Folder '$SearchDiagnosticLogs'"
                $Folder = "Search_Diag_ETLs"
                $cmdsToRun += "Collect-LogsBasedOnTime $Folder '$SearchDiagnosticETLTraces'"
            }
        }

    } #end Exchange 2013 

    ###############################
    #
    #     Exchange 2010 
    #
    ###############################
    if($ServerObject.Version -eq 14) {
        
        if($ServerObject.CAS) {
            if($RPCLogs) {
                $Folder = "RCA_Logs" 
                if($CollectAllLogsBasedOnDaysWorth) { } 
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$RCALogFilePath'"}
            }
            if($EWSLogs) {
                $Folder = "EWS_Logs" 
                if($CollectAllLogsBasedOnDaysWorth) { } 
                else {$cmdsToRun += "Copy-FullLogFolderPathRecurse $Folder '$EWSBELogFilePath'"}
            }
        } #End CAS Role 

        if($IISLogs) {
            Load-IISVars
            if($IISLogDirectory -ne ""){
            if((Bool-IISMultiW3SVCDirectories) -eq $false) {
                $Folder = "IIS_FE_Logs"
                $IISBEDirectory = "$IISLogDirectory\W3SVC1"
                $cmdsToRun = $cmdsToRun + "Collect-LogsBasedOnTime $Folder '$IISBEDirectory'"
            }
            else{
                $Folders = Get-ChildItem $IISLogDirectory
                foreach($folder in $Folders){
				    if($folder.name -like "W3SVC*"){
				        $sFolder = "IIS_" + $folder + "_Logs"
				        $IISCopyDirectory = $IISLogDirectory + "\" + $folder.name 
				        $cmdsToRun = $cmdsToRun + "Collect-LogsBasedOnTime $sFolder '$IISCopyDirectory'"
				        }
                    }
                }
                $folder = "HTTPERR_Logs" 
                $cmdsToRun = $cmdsToRun + "Collect-LogsBasedOnTime $folder '$HttpErrDirectory'"
            }
        }
    }#End Exchange 2010 

    ##############################
    #
    #    All Versions 
    #
    ##############################

    if($Experfwiz) {$cmdsToRun += "Collect-LogmanExperfWiz"}
    if($Exmon) {$cmdsToRun += "Collect-LogmanExmon"}
    if($TransportSwitchesEnabled){$cmdsToRun += "Collect-TransportLogInformationManager"}
    if($DAGInformation) {$cmdsToRun += "Get-DagInformation"} 
    if($CustomData) {
        if($CustomDataDirectory -eq ""){Write-Warning "Custom Data wasn't collected as the directory wasn't provided. Please run the script again to get this information"}
        else{$cmdsToRun += "Collect-CustomData"}
    }
    if($HighAvailabilityLogs) {$cmdsToRun += "Collect-HighAvailabilityLogs"}
    if($ServerInfo) {$cmdsToRun += "Get-ServerInfo"}
    if($GetVdirs) {$cmdsToRun += "Get-VdirsLDAP"} 
    if($AppSysLogs) {$cmdsToRun += "Collect-AppSysLogs"}

    ###### Now Do the Work ################
    $i = 0
    foreach($cmd in $cmdsToRun){
        $temp = $cmd.Split(" ")
        $showME = $temp[1]
        if($showME -eq $null) {$showME = $temp[0]}
        Write-Progress -Activity "Total Progress Report for the Log Collection" -Status "Working on $showME" -PercentComplete ((++$i/$cmdsToRun.count)*100)
        Invoke-Expression $cmd
    }
}

#Set Script location 
$scriptLocation = Get-Location 
CommonScenarios
Dectect-IfNoSwitchesProvided
Main
Read-ExecuteCmds
zipAllIt