<#
.NOTES
	Name: HealthChecker.ps1
	Original Author: Marc Nivens
    Author: David Paulson
    Contributor: Jason Shinbaum, Michael Schatte, Lukas Sassl
	Requires: Exchange Management Shell and administrator rights on the target Exchange
	server as well as the local machine.
    Major Release History:
        1/18/2017 - Initial Public Release of version 2. - rewritten by David Paulson.
        3/30/2015 - Initial Public Release.
    
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
	Checks the target Exchange server for various configuration recommendations from the Exchange product group.
.DESCRIPTION
	This script checks the Exchange server for various configuration recommendations outlined in the 
	"Exchange 2013 Performance Recommendations" section on Microsoft Docs, found here:

	https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help

	Informational items are reported in Grey.  Settings found to match the recommendations are
	reported in Green.  Warnings are reported in yellow.  Settings that can cause performance
	problems are reported in red.  Please note that most of these recommendations only apply to Exchange
	2013/2016.  The script will run against Exchange 2010/2007 but the output is more limited.
.PARAMETER Server
	This optional parameter allows the target Exchange server to be specified.  If it is not the 		
	local server is assumed.
.PARAMETER OutputFilePath
	This optional parameter allows an output directory to be specified.  If it is not the local 		
	directory is assumed.  This parameter must not end in a \.  To specify the folder "logs" on 		
	the root of the E: drive you would use "-OutputFilePath E:\logs", not "-OutputFilePath E:\logs\".
.PARAMETER MailboxReport
	This optional parameter gives a report of the number of active and passive databases and
	mailboxes on the server.
.PARAMETER LoadBalancingReport
    This optional parameter will check the connection count of the Default Web Site for every server
    running Exchange 2013/2016 with the Client Access role in the org.  It then breaks down servers by percentage to 
    give you an idea of how well the load is being balanced.
.PARAMETER CasServerList
    Used with -LoadBalancingReport.  A comma separated list of CAS servers to operate against.  Without 
    this switch the report will use all 2013/2016 Client Access servers in the organization.
.PARAMETER SiteName
	Used with -LoadBalancingReport.  Specifies a site to pull CAS servers from instead of querying every server
    in the organization.
.PARAMETER XMLDirectoryPath
    Used in combination with BuildHtmlServersReport switch for the location of the HealthChecker XML files for servers 
    which you want to be included in the report. Default location is the current directory.
.PARAMETER BuildHtmlServersReport 
    Switch to enable the script to build the HTML report for all the servers XML results in the XMLDirectoryPath location.
.PARAMETER HtmlReportFile 
    Name of the HTML output file from the BuildHtmlServersReport. Default is ExchangeAllServersReport.html
.PARAMETER DCCoreRatio 
    Gathers the Exchange to DC/GC Core ratio and displays the results in the current site that the script is running in.
.PARAMETER Verbose	
	This optional parameter enables verbose logging.
.EXAMPLE
	.\HealthChecker.ps1 -Server SERVERNAME
	Run against a single remote Exchange server
.EXAMPLE
	.\HealthChecker.ps1 -Server SERVERNAME -MailboxReport -Verbose
	Run against a single remote Exchange server with verbose logging and mailbox report enabled.
.EXAMPLE
    Get-ExchangeServer | ?{$_.AdminDisplayVersion -Match "^Version 15"} | %{.\HealthChecker.ps1 -Server $_.Name}
    Run against all Exchange 2013/2016 servers in the Organization.
.EXAMPLE
    .\HealthChecker.ps1 -LoadBalancingReport
    Run a load balancing report comparing all Exchange 2013/2016 CAS servers in the Organization.
.EXAMPLE
    .\HealthChecker.ps1 -LoadBalancingReport -CasServerList CAS01,CAS02,CAS03
    Run a load balancing report comparing servers named CAS01, CAS02, and CAS03.
.LINK
    https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help
    https://docs.microsoft.com/en-us/exchange/exchange-2013-virtualization-exchange-2013-help#requirements-for-hardware-virtualization
    https://docs.microsoft.com/en-us/exchange/plan-and-deploy/virtualization?view=exchserver-2019#requirements-for-hardware-virtualization
#>
[CmdletBinding(DefaultParameterSetName="HealthChecker")]
param(
[Parameter(Mandatory=$false,ParameterSetName="HealthChecker")]
[Parameter(Mandatory=$false,ParameterSetName="MailboxReport")]
    [string]$Server=($env:COMPUTERNAME),
[Parameter(Mandatory=$false)]
    [ValidateScript({-not $_.ToString().EndsWith('\')})][string]$OutputFilePath = ".",
[Parameter(Mandatory=$false,ParameterSetName="MailboxReport")]
    [switch]$MailboxReport,
[Parameter(Mandatory=$false,ParameterSetName="LoadBalancingReport")]
    [switch]$LoadBalancingReport,
[Parameter(Mandatory=$false,ParameterSetName="LoadBalancingReport")]
    [array]$CasServerList = $null,
[Parameter(Mandatory=$false,ParameterSetName="LoadBalancingReport")]
    [string]$SiteName = ([string]::Empty),
[Parameter(Mandatory=$false,ParameterSetName="HTMLReport")]
    [ValidateScript({-not $_.ToString().EndsWith('\')})][string]$XMLDirectoryPath = ".",
[Parameter(Mandatory=$false,ParameterSetName="HTMLReport")]
    [switch]$BuildHtmlServersReport,
[Parameter(Mandatory=$false,ParameterSetName="HTMLReport")]
    [string]$HtmlReportFile="ExchangeAllServersReport.html",
[Parameter(Mandatory=$false,ParameterSetName="DCCoreReport")]
    [switch]$DCCoreRatio
)

<#
Note to self. "New Release Update" are functions that i need to update when a new release of Exchange is published
#>

$healthCheckerVersion = "2.34"
$VirtualizationWarning = @"
Virtual Machine detected.  Certain settings about the host hardware cannot be detected from the virtual machine.  Verify on the VM Host that: 

    - There is no more than a 1:1 Physical Core to Virtual CPU ratio (no oversubscribing)
    - If Hyper-Threading is enabled do NOT count Hyper-Threaded cores as physical cores
    - Do not oversubscribe memory or use dynamic memory allocation
    
Although Exchange technically supports up to a 2:1 physical core to vCPU ratio, a 1:1 ratio is strongly recommended for performance reasons.  Certain third party Hyper-Visors such as VMWare have their own guidance.  

VMWare recommends a 1:1 ratio.  Their guidance can be found at https://www.vmware.com/files/pdf/Exchange_2013_on_VMware_Best_Practices_Guide.pdf.  
Related specifically to VMWare, if you notice you are experiencing packet loss on your VMXNET3 adapter, you may want to review the following article from VMWare:  http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2039495. 

For further details, please review the virtualization recommendations on TechNet at the following locations: 
Exchange 2013: https://docs.microsoft.com/en-us/exchange/exchange-2013-virtualization-exchange-2013-help#requirements-for-hardware-virtualization.  
Exchange 2016/2019: https://docs.microsoft.com/en-us/exchange/plan-and-deploy/virtualization?view=exchserver-2019. 

"@

#this is to set the verbose information to a different color 
if($PSBoundParameters["Verbose"]){
    #Write verose output in cyan since we already use yellow for warnings 
    $Script:VerboseEnabled = $true
    $VerboseForeground = $Host.PrivateData.VerboseForegroundColor 
    $Host.PrivateData.VerboseForegroundColor = "Cyan"
}

$oldErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Stop"

try{

#Enums and custom data types 
Add-Type -TypeDefinition @"
using System.Collections;
    namespace HealthChecker
    {
        public class HealthExchangeServerObject
        {
            public string ServerName;        //String of the server that we are working with 
            public HardwareObject HardwareInfo;  // Hardware Object Information 
            public OperatingSystemObject  OSVersion; // OS Version Object Information 
            public NetVersionObject NetVersionInfo; //.net Framework object information 
            public ExchangeInformationObject ExchangeInformation; //Detailed Exchange Information 
            public double HealthCheckerVersion; //To determine the version of the script on the object.
        }

        public class ExchangeInformationObject 
        {
            public ServerRole ExServerRole;          // Roles that are currently installed - Exchange 2013 makes a note if both roles aren't installed 
            public ExchangeVersion ExchangeVersion;  //Exchange Version (Exchange 2010/2013/2016)
            public string ExchangeFriendlyName;       // Friendly Name is provided 
            public string ExchangeBuildNumber;       //Exchange Build number 
            public string BuildReleaseDate;           //Provides the release date for which the CU they are currently on 
            public object ExchangeServerObject;      //Stores the Get-ExchangeServer Object 
            public bool SupportedExchangeBuild;      //Deteremines if we are within the correct build of Exchange 
            public bool InbetweenCUs;                //bool to provide if we are between main releases of CUs. Hotfixes/IUs. 
            public bool RecommendedNetVersion; //RecommendNetVersion Info includes all the factors. Windows Version & CU. 
            public ExchangeBuildObject ExchangeBuildObject; //Store the build object
            public System.Array KBsInstalled;         //Stored object for IU or Security KB fixes 
            public bool MapiHttpEnabled; //Stored from ogranzation config 
            public string MapiFEAppGCEnabled; //to determine if we were able to get information regarding GC mode being enabled or not
            public string ExchangeServicesNotRunning; //Contains the Exchange services not running by Test-ServiceHealth 
            public Hashtable ExchangeAppPools; 
            public object ExchangeSetup;                  //Stores the Get-Command ExSetup object 
           
        }

        public class ExchangeInformationTempObject 
        {
            public string FriendlyName;    //String of the friendly name of the Exchange version 
            public bool Error;             //To report back an error and address how to handle it
            public string ExchangeBuildNumber;  //Exchange full build number 
            public string ReleaseDate;        // The release date of that version of Exchange 
            public bool SupportedCU;          //bool to determine if we are on a supported build of Exchange 
            public bool InbetweenCUs;         //Bool to determine if we are inbetween CUs. FIU/Hotfixes 
            public ExchangeBuildObject ExchangeBuildObject; //Holds the Exchange Build Object for debugging and function use reasons 
        }

        public class ExchangeBuildObject
        {
            public ExchangeVersion ExchangeVersion;  //enum for Exchange 2010/2013/2016 
            public ExchangeCULevel CU;               //enum for the CU value 
            public bool InbetweenCUs;                //bool for if we are between CUs 
        }

        //enum for CU levels of Exchange
        //New Release Update 
        public enum ExchangeCULevel
        {
            Unknown,
            Preview,
            RTM,
            CU1,
            CU2,
            CU3,
            CU4,
            CU5,
            CU6,
            CU7,
            CU8,
            CU9,
            CU10,
            CU11,
            CU12,
            CU13,
            CU14,
            CU15,
            CU16,
            CU17,
            CU18,
            CU19,
            CU20,
            CU21,
            CU22

        }

        //enum for the server roles that the computer is 
        public enum ServerRole
        {
            MultiRole,
            Mailbox,
            ClientAccess,
            Hub,
            Edge,
            None
        }
        
        public class NetVersionObject 
        {
            public NetVersion NetVersion; //NetVersion value 
            public string FriendlyName;  //string of the friendly name 
            public bool SupportedVersion; //bool to determine if the .net framework is on a supported build for the version of Exchange that we are running 
            public string DisplayWording; //used to display what is going on
            public int NetRegValue; //store the registry value 
        }

        public class NetVersionCheckObject
        {
            public bool Error;         //bool for error handling 
            public bool Supported;     //to provide if we are supported or not. This should throw a red warning if false 
            public bool RecommendedNetVersion;  //Bool to determine if there is a recommended version that we should be on instead of the supported version 
            public string DisplayWording;   //string value to display what is wrong with the .NET version that we are on. 
        }

        //enum for the dword value of the .NET frame 4 that we are on 
        public enum NetVersion 
        {

            Unknown = 0,
            Net4d5 = 378389,
			Net4d5d1 = 378675,
			Net4d5d2 = 379893,
			Net4d5d2wFix = 380035,
			Net4d6 = 393297,
			Net4d6d1 = 394271,
            Net4d6d1wFix = 394294,
			Net4d6d2 = 394806,
            Net4d7 = 460805,
            Net4d7d1 = 461310,
            Net4d7d2 = 461814
        }

        //enum for the dword values of the latest supported VC++ redistributable releases
	//https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads
        public enum VCRedistVersion
        {
            Unknown = 0,
            VCRedist2012 = 184610406,
            VCRedist2013 = 201367256
        }

        public class VCRedistObject
        {
            public string DisplayName;
            public string DisplayVersion;
            public string InstallDate;
            public int VersionIdentifier;
        }

        public class HardwareObject
        {
            public string Manufacturer; //String to display the hardware information 
            public ServerType ServerType; //Enum to determine if the hardware is VMware, HyperV, Physical, or Unknown 
            public double TotalMemory; //Stores the total memory available 
            public object System;   //object to store the system information that we have collected 
            public ProcessorInformationObject Processor;   //Detailed processor Information 
            public bool AutoPageFile; //True/False if we are using a page file that is being automatically set 
            public string Model; //string to display Model 
            
        }

        //enum for the type of computer that we are
        public enum ServerType
        {
            VMWare,
            HyperV,
            Physical,
            Unknown
        }

        public class ProcessorInformationObject 
        {
            public int NumberOfPhysicalCores;    //Number of Physical cores that we have 
            public int NumberOfLogicalProcessors;  //Number of Logical cores that we have presented to the os 
            public int NumberOfProcessors; //Total number of processors that we have in the system 
            public int MaxMegacyclesPerCore; //Max speed that we can get out of the cores 
            public int CurrentMegacyclesPerCore; //Current speed that we are using the cores at 
            public bool ProcessorIsThrottled;  //True/False if we are throttling our processor 
            public string ProcessorName;    //String of the processor name 
            public object Processor;        // object to store the processor information 
            public bool DifferentProcessorsDetected; //true/false to detect if we have different processor types detected 
			public int EnvProcessorCount; //[system.environment]::processorcount 
            
        }

        public class OperatingSystemObject 
        {
            public OSVersionName  OSVersion; //enum for the version name 
            public string OSVersionBuild;    //string to hold the build number 
            public string OperatingSystemName; //string for the OS version friendly name
            public object OperatingSystem;   //object to store the OS information that we pulled 
            public bool HighPerformanceSet;  //True/False for the power plan setting being set correctly 
            public string PowerPlanSetting; //string value for the power plan setting being set correctly 
            public object PowerPlan;       // object to store the power plan information 
            public System.Array NetworkAdaptersConfiguration; // Stores the Win32_NetworkAdapterConfiguration for the server. 
            public System.Array NetworkAdapters; //array to keep all the nics on the servers 
            public double TCPKeepAlive;       //value used for the TCP/IP keep alive setting 
            public double MinimumConnectionTimeout; //value used for the RPC minimum connection timeout. 
            public System.Array HotFixes; //array to keep all the hotfixes of the server
            public System.Array HotFixInfo;     //object to store hotfix information
			public string HttpProxy;
            public PageFileObject PageFile;
            public ServerLmCompatibilityLevel LmCompat;
            public bool ServerPendingReboot; //bool to determine if a server is pending a reboot to properly apply fixes
            public object PacketsReceivedDiscarded; //object to hold all packets received discarded on the server
            public double DisabledComponents; //value stored in the registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents 
            public bool IPv6DisabledOnNICs; //value that determines if we have IPv6 disabled on some NICs or not. 
            public string TimeZone; //value to stores the current timezone of the server. 
            public System.Array TLSSettings;
            public NetDefaultTlsVersionObject NetDefaultTlsVersion;
	    public string BootUpTimeInDays;
            public string BootUpTimeInHours;
            public string BootUpTimeInMinutes;
            public string BootUpTimeInSeconds;
        }

        public enum TLSVersion
        {
            TLS10,
            TLS11,
            TLS12
        }

        public class TLSObject
        {
            public string TLSName; 
            public bool ClientEnabled;
            public bool ClientDisabledByDefault; 
            public bool ServerEnabled;
            public bool ServerDisabledByDefault; 
        }

        public class NetDefaultTlsVersionObject 
        {
            public bool SystemDefaultTlsVersions;
            public bool WowSystemDefaultTlsVersions; 
        }

        public class HotfixObject
        {
            public string KBName; //KB that we are using to check against 
            public System.Array FileInformation; //store FileVersion information
            public bool ValidFileLevelCheck;  
        }

        public class FileVersionCheckObject 
        {
            public string FriendlyFileName;
            public string FullPath; 
            public string BuildVersion;
        }

        public class NICInformationObject 
        {
            public string Description;  //Friendly name of the adapter 
            public string LinkSpeed;    //speed of the adapter 
            public string DriverDate;   // date of the driver that is currently installed on the server 
            public string DriverVersion; // version of the driver that we are on 
            public string RSSEnabled;  //bool to determine if RSS is enabled 
            public string Name;        //name of the adapter 
            public object NICObject; //object to store the adapter info 
            public bool IPv6Enabled; //Checks to see if we have an IPv6 address on the NIC 
            public int MTUSize; //Size of the MTU on the network card. 
             
        }

        //enum for the Exchange version 
        public enum ExchangeVersion
        {
            Unknown,
            Exchange2010,
            Exchange2013,
            Exchange2016,
            Exchange2019
        }

        //enum for the OSVersion that we are
        public enum OSVersionName
        {
            Unknown,
            Windows2008, 
            Windows2008R2,
            Windows2012,
            Windows2012R2,
            Windows2016,
            Windows2019
        }

        public class PageFileObject 
        {
            public object PageFile;  //object to store the information that we got for the page file 
            public double MaxPageSize; //value to hold the information of what our page file is set to 
        }

        public class ServerLmCompatibilityLevel
        {
            public int LmCompatibilityLevel;  //The LmCompatibilityLevel for the server (INT 1 - 5)
            public string LmCompatibilityLevelDescription; //The description of the lmcompat that the server is set too
            public string LmCompatibilityLevelRef; //The URL for the LmCompatibilityLevel technet (https://technet.microsoft.com/en-us/library/cc960646.aspx or https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960646(v=technet.10) )
        }
    }

"@

}

catch {
    Write-Warning "There was an error trying to add custom classes to the current PowerShell session. You need to close this session and open a new one to have the script properly work."
    exit 
}

finally {
    $ErrorActionPreference = $oldErrorAction
}

##################
#Helper Functions#
##################

#Output functions
function Write-Red($message)
{
    Write-Host $message -ForegroundColor Red
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Yellow($message)
{
    Write-Host $message -ForegroundColor Yellow
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Green($message)
{
    Write-Host $message -ForegroundColor Green
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Grey($message)
{
    Write-Host $message
    $message | Out-File ($OutputFullPath) -Append
}

function Write-VerboseOutput($message)
{
    Write-Verbose $message
    if($Script:VerboseEnabled)
    {
        $message | Out-File ($OutputFullPath) -Append
    }
}

Function Write-Break {
    Write-Host ""
}


############################################################
############################################################

Function Invoke-CatchActions{

    Write-VerboseOutput("Calling: Invoke-Actions")
    $Script:ErrorsExcludedCount++
    $Script:ErrorsExcluded += $Error[0]

}

Function Test-ScriptVersion {
param(
[Parameter(Mandatory=$true)][string]$ApiUri, 
[Parameter(Mandatory=$true)][string]$RepoOwner,
[Parameter(Mandatory=$true)][string]$RepoName,
[Parameter(Mandatory=$true)][double]$CurrentVersion,
[Parameter(Mandatory=$true)][int]$DaysOldLimit
)
    Write-VerboseOutput("Calling: Test-ScriptVersion")

    $isCurrent = $false 
    
    if(Test-Connection -ComputerName $ApiUri -Count 1 -Quiet)
    {
        try 
        {
            $currentSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $releaseInformation = (ConvertFrom-Json(Invoke-WebRequest -Uri ($uri = "https://$apiUri/repos/$RepoOwner/$RepoName/releases/latest")))
        }
        catch 
        {
            Invoke-CatchActions
            Write-VerboseOutput("Failed to run Invoke-WebRequest")
        }
        finally 
        {
            [Net.ServicePointManager]::SecurityProtocol = $currentSecurityProtocol
        }
        if($releaseInformation -ne $null)
        {
            Write-VerboseOutput("We're online: {0} connected successfully." -f $uri)
            if($CurrentVersion -ge ($latestVersion = [double](($releaseInformation.tag_name).Split("v")[1])))
            {
                Write-VerboseOutput("Version '{0}' is the latest version." -f $latestVersion)
                $isCurrent = $true 
            }
            else 
            {
                Write-VerboseOutput("Version '{0}' is outdated. Lastest version is '{1}'" -f $CurrentVersion, $latestVersion)
            }
        }
    }
    else 
    {
        Write-VerboseOutput("We're offline: Unable to connect to '{0}" -f $ApiUri)
        Write-VerboseOutput("Unable to determine if this version '{0}' is current. Checking to see if the file is older than {1} days." -f $CurrentVersion, $DaysOldLimit)
        $writeTime = (Get-ChildItem ($MyInvocation.ScriptName)).LastWriteTime
        if($writeTime -gt ($testDate = ([datetime]::Now).AddDays(-$DaysOldLimit)))
        {
            Write-VerboseOutput("Determined that the script write time '{0}' is new than our our test date '{1}'." -f $writeTime, $testDate)
            $isCurrent = $true 
        }
        else 
        {
            Write-VerboseOutput("Script doesn't appear to be on the latest possible version. Script write time '{0}' vs out test date '{1}'" -f $writeTime, $testDate)
        }

    }

    return $isCurrent
}

Function Invoke-RegistryHandler {
param(
[Parameter(Mandatory=$false)][string]$RegistryHive = "LocalMachine",
[Parameter(Mandatory=$true)][string]$MachineName,
[Parameter(Mandatory=$true)][string]$SubKey,
[Parameter(Mandatory=$true)][string]$GetValue,
[Parameter(Mandatory=$false)][bool]$ErrorExpected
)
    Write-VerboseOutput("Calling: Invoke-RegistryHandler")
    try 
    {
        Write-VerboseOutput("Attempting to open the Base Key '{0}' on Server '{1}'" -f $RegistryHive, $MachineName)
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $MachineName)
        Write-VerboseOutput("Attempting to open the Sub Key '{0}'" -f $SubKey)
        $RegKey= $Reg.OpenSubKey($SubKey)
        Write-VerboseOutput("Attempting to get the value '{0}'" -f $GetValue)
        $returnGetValue = $RegKey.GetValue($GetValue)
    }
    catch 
    {
        Invoke-CatchActions
        Write-VerboseOutput("Failed to open the registry")
    }
    return $returnGetValue
}

Function Load-ExShell {
	#Verify that we are on Exchange 2010 or newer 
	if((Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'))
	{
		#If we are on Exchange Server, we need to make sure that Exchange Management Snapin is loaded 
		try
		{
			Get-ExchangeServer | Out-Null
		}
		catch
		{
            Invoke-CatchActions
			Write-Host "Loading Exchange PowerShell Module..."
			Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010
		}
	}
	else
	{
		Write-Host "Not on Exchange 2010 or newer. Going to exit."
		sleep 2
		exit
	}
}

Function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    If( $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    }
    else {
        return $false
    }
}

Function Get-InstalledSoftware {
param(
[Parameter(Mandatory=$true)][string]$MachineName
)
    Write-VerboseOutput("Calling: Get-InstalledSoftware")
    try
    {
        if($MachineName -match $env:COMPUTERNAME)
        {
            Write-VerboseOutput("Query software for local machine: {0}" -f $env:COMPUTERNAME)
            $InstalledSoftware = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
        }
        else
        {
            Write-VerboseOutput("Query software for remote machine: {0}" -f $MachineName)
            $InstalledSoftware = Invoke-Command -ComputerName $MachineName -ScriptBlock {Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*}
        }
    }
    catch
    {
        Invoke-CatchActions
        Write-VerboseOutput("Failed to query installed software")
    }
    return $InstalledSoftware
}

Function Get-CounterSamples {
param(
[Parameter(Mandatory=$true)][array]$MachineNames,
[Parameter(Mandatory=$true)][array]$Counters
)
    Write-VerboseOutput("Calling: Get-CounterSamples")
    try 
    {
        $counterSamples = (Get-Counter -ComputerName $MachineNames -Counter $Counters -ErrorAction Stop).CounterSamples
    }
    catch 
    {
        Invoke-CatchActions
        Write-VerboseOutput("Failed to get counter samples")
    }
    return $counterSamples 
}

Function Get-OperatingSystemVersion {
param(
[Parameter(Mandatory=$true)][string]$OS_Version
)

    Write-VerboseOutput("Calling: Get-OperatingSystemVersion")
    Write-VerboseOutput("Passed: $OS_Version")
    
    switch($OS_Version)
    {
        "6.0.6000" {Write-VerboseOutput("Returned: Windows2008"); return [HealthChecker.OSVersionName]::Windows2008}
        "6.1.7600" {Write-VerboseOutput("Returned: Windows2008R2"); return [HealthChecker.OSVersionName]::Windows2008R2}
        "6.1.7601" {Write-VerboseOutput("Returned: Windows2008R2"); return [HealthChecker.OSVersionName]::Windows2008R2}
        "6.2.9200" {Write-VerboseOutput("Returned: Windows2012"); return [HealthChecker.OSVersionName]::Windows2012}
        "6.3.9600" {Write-VerboseOutput("Returned: Windows2012R2"); return [HealthChecker.OSVersionName]::Windows2012R2}
        "10.0.14393" {Write-VerboseOutput("Returned: Windows2016"); return [HealthChecker.OSVersionName]::Windows2016}
        "10.0.17713" {Write-VerboseOutput("Returned: Windows2019"); return [HealthChecker.OSVersionName]::Windows2019}
        default{Write-VerboseOutput("Returned: Unknown"); return [HealthChecker.OSVersionName]::Unknown}
    }

}

Function Get-PageFileObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-PageFileObject")
    Write-Verbose("Passed: $Machine_Name")
    [HealthChecker.PageFileObject]$page_obj = New-Object HealthChecker.PageFileObject
    $pagefile = Get-WmiObject -ComputerName $Machine_Name -Class Win32_PageFileSetting
    if($pagefile -ne $null) 
    { 
        if($pagefile.GetType().Name -eq "ManagementObject")
        {
            $page_obj.MaxPageSize = $pagefile.MaximumSize
        }
        $page_obj.PageFile = $pagefile
    }
    else
    {
        Write-VerboseOutput("Return Null value")
    }

    return $page_obj
}


Function Build-NICInformationObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OSVersion
)

    Write-VerboseOutput("Calling: Build-NICInformationObject")
    Write-VerboseOutput("Passed: $Machine_Name")
    Write-VerboseOutput("Passed: $OSVersion")

    [array]$aNICObjects = @() 
    if($OSVersion -ge [HealthChecker.OSVersionName]::Windows2012R2)
    {
        Write-VerboseOutput("Detected OS Version greater than or equal to Windows 2012R2")
        try 
        {
            try 
            {
                $cimSession = New-CimSession -ComputerName $Machine_Name -ErrorAction Stop 
                $NetworkCards = Get-NetAdapter -CimSession $cimSession | ?{$_.MediaConnectionState -eq "Connected"} -ErrorAction Stop 
            }
            catch 
            {
                Invoke-CatchActions
                Write-VerboseOutput("Failed first attempt to get Windows2012R2 or greater advanced NIC settings. Error {0}." -f $Error[0].Exception)
                Write-VerboseOutput("Going to attempt to get the FQDN from Get-ExchangeServer")
                $fqdn = (Get-ExchangeServer $Machine_Name).FQDN 
                $cimSession = New-CimSession -ComputerName $fqdn -ErrorAction Stop
                $NetworkCards = Get-NetAdapter -CimSession $cimSession | ?{$_.MediaConnectionState -eq "Connected"} -ErrorAction Stop 
            }
        }
        catch 
        {
            Invoke-CatchActions
            Write-VerboseOutput("Failed to get Windows2012R2 or greater advanced NIC settings. Error {0}." -f $Error[0].Exception)
            Write-VerboseOutput("Going to attempt to get WMI Object Win32_NetworkAdapter on this machine instead")
            Write-VerboseOutput("NOTE: this means we aren't able to provide the driver date")
            $NetworkCards2008 = Get-WmiObject -ComputerName $Machine_Name -Class Win32_NetworkAdapter | ?{$_.NetConnectionStatus -eq 2}
            foreach($adapter in $NetworkCards2008)
            {
                [HealthChecker.NICInformationObject]$nicObject = New-Object -TypeName HealthChecker.NICInformationObject 
                $nicObject.Description = $adapter.Description
                $nicObject.Name = $adapter.Name
                $nicObject.LinkSpeed = $adapter.Speed
                $nicObject.NICObject = $adapter 
                $nicObject.DriverDate = [DateTime]::MaxValue;
                $aNICObjects += $nicObject
            }
        }
        foreach($adapter in $NetworkCards)
        {
            Write-VerboseOutput("Working on getting netAdapeterRSS information for adapter: " + $adapter.InterfaceDescription)
            [HealthChecker.NICInformationObject]$nicObject = New-Object -TypeName HealthChecker.NICInformationObject 
            try
            {
                $RSS_Settings = $adapter | Get-netAdapterRss -ErrorAction Stop
                $nicObject.RSSEnabled = $RSS_Settings.Enabled
            }
            catch 
            {
                Invoke-CatchActions
                Write-Yellow("Warning: Unable to get the netAdapterRSS Information for adapter: {0}" -f $adapter.InterfaceDescription)
                $nicObject.RSSEnabled = "NoRSS"
            }
            $nicObject.Description = $adapter.InterfaceDescription
            $nicObject.DriverDate = $adapter.DriverDate
            $nicObject.DriverVersion = $adapter.DriverVersionString
            $nicObject.LinkSpeed = (($adapter.Speed)/1000000).ToString() + " Mbps"
            $nicObject.Name = $adapter.Name
            $nicObject.NICObject = $adapter 
            $nicObject.MTUSize = $adapter.MtuSize
            $aNICObjects += $nicObject
        }

    }
    
    #Else we don't have all the correct powershell options to get more detailed information remotely 
    else
    {
        Write-VerboseOutput("Detected OS Version less than Windows 2012R2")
        $NetworkCards2008 = Get-WmiObject -ComputerName $Machine_Name -Class Win32_NetworkAdapter | ?{$_.NetConnectionStatus -eq 2}
        foreach($adapter in $NetworkCards2008)
        {
            [HealthChecker.NICInformationObject]$nicObject = New-Object -TypeName HealthChecker.NICInformationObject 
            $nicObject.Description = $adapter.Description
            $nicObject.Name = $adapter.Name
            $nicObject.LinkSpeed = $adapter.Speed
            $nicObject.NICObject = $adapter 
            $aNICObjects += $nicObject
        }

    }

    return $aNICObjects 

}

Function Get-HttpProxySetting {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
	$httpProxy32 = [String]::Empty
	$httpProxy64 = [String]::Empty
	Write-VerboseOutput("Calling  Get-HttpProxySetting")
	Write-VerboseOutput("Passed: {0}" -f $Machine_Name)
	$orgErrorPref = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    
    Function Get-WinHttpSettings {
    param(
        [Parameter(Mandatory=$true)][string]$RegistryLocation
    )
        $connections = Get-ItemProperty -Path $RegistryLocation
        $Proxy = [string]::Empty
        if(($connections -ne $null) -and ($Connections | gm).Name -contains "WinHttpSettings")
        {
            foreach($Byte in $Connections.WinHttpSettings)
            {
                if($Byte -ge 48)
                {
                    $Proxy += [CHAR]$Byte
                }
            }
        }
        return $(if($Proxy -eq [string]::Empty){"<None>"} else {$Proxy})
    }

	try
	{
        $httpProxyPath32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
        $httpProxyPath64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
        
        if($Machine_Name -ne $env:COMPUTERNAME) 
        {
            Write-VerboseOutput("Calling Get-WinHttpSettings via Invoke-Command")
            $httpProxy32 = Invoke-Command -ComputerName $Machine_Name -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList $httpProxyPath32
            $httpProxy64 = Invoke-Command -ComputerName $Machine_Name -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList $httpProxyPath64
        }
        else 
        {
            Write-VerboseOutput("Calling Get-WinHttpSettings via local session")
            $httpProxy32 = Get-WinHttpSettings -RegistryLocation $httpProxyPath32
            $httpProxy64 = Get-WinHttpSettings -RegistryLocation $httpProxyPath64
        }
		
		
        Write-VerboseOutput("Http Proxy 32: {0}" -f $httpProxy32)
		Write-VerboseOutput("Http Proxy 64: {0}" -f $httpProxy64)
	}

	catch
	{
        Invoke-CatchActions
		Write-Yellow("Warning: Unable to get the Http Proxy Settings for server {0}" -f $Machine_Name)
	}
	finally
	{
		$ErrorActionPreference = $orgErrorPref
	}

	if($httpProxy32 -ne "<None>")
	{
		return $httpProxy32
	}
	else
	{
		return $httpProxy64
	}

}

Function Get-VisualCRedistributableVersion {
param(
[Parameter(Mandatory=$true)][string]$MachineName
)
    Write-VerboseOutput("Calling Function: Get-VisualCRedistributableVersion")
    $Software_objs = @()
    $InstalledSoftware = Get-InstalledSoftware -MachineName $MachineName

    ForEach($Software in $InstalledSoftware)
    {
        if($Software.DisplayName -like "Microsoft Visual C++ *")
        {
            Write-VerboseOutput("Microsoft Visual C++ Redistributable found: {0}" -f $Software.DisplayName)
            [HealthChecker.VCRedistObject]$Software_obj = New-Object Healthchecker.VCRedistObject
            $Software_obj.DisplayName = $Software.DisplayName
            $Software_obj.DisplayVersion = $Software.DisplayVersion
            $Software_obj.InstallDate = $Software.InstallDate
            $Software_obj.VersionIdentifier = $Software.Version
            $Software_objs += $Software_obj
        }
    }
    return $Software_objs
}

Function Confirm-VisualCRedistributableVersion {
param(
[Parameter(Mandatory=$true)][object]$ExchangeServerObj
)
    Write-VerboseOutput("Calling Function: Confirm-VisualCRedistributableVersion")

    [hashtable]$Return = @{}
    $Return.VC2012Required = $false
    $Return.vc2013Required = $false
    $Return.VC2012Current = $false
    $Return.vc2013Current = $false

    $DetectedVisualCRedistVersions = Get-VisualCRedistributableVersion -MachineName $ExchangeServerObj.ServerName
    
    if($DetectedVisualCRedistVersions -ne $null)
    {
        if(($ExchangeServerObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::Edge))
        {
            Write-VerboseOutput("We need to check for Visual C++ Redistributable Version 2013")
            $Return.VC2013Required = $true
        }
            
        Write-VerboseOutput("We need to check for Visual C++ Redistributable Version 2012")
        $Return.VC2012Required = $true
        Write-VerboseOutput("VCRedist2012 Testing value: {0}" -f [HealthChecker.VCRedistVersion]::VCRedist2012.value__)
        Write-VerboseOutput("VCRedist2013 Testing value: {0}" -f [HealthChecker.VCRedistVersion]::VCRedist2013.value__)
        ForEach($DetectedVisualCRedistVersion in $DetectedVisualCRedistVersions)
        {
            Write-VerboseOutput("Testing {0} version id '{1}'" -f $DetectedVisualCRedistVersion.DisplayName, $DetectedVisualCRedistVersion.VersionIdentifier)
            if($DetectedVisualCRedistVersion.VersionIdentifier -eq [HealthChecker.VCRedistVersion]::VCRedist2012)
            {
                $Return.VC2012Current = $true
                $Return.VC2012Version = $DetectedVisualCRedistVersion.DisplayVersion
            }
            elseif($Return.VC2013Required -eq $true -and $DetectedVisualCRedistVersion.VersionIdentifier -eq [HealthChecker.VCRedistVersion]::VCRedist2013)
            {
                $Return.VC2013Current = $true
                $Return.VC2013Version = $DetectedVisualCRedistVersion.DisplayVersion
            }  
        }
    }
    else
    {
        Write-VerboseOutput("We can't determin required Visual C++ Redistributable Version")
    }
    return $Return
}

Function New-FileLevelHotfixObject {
param(
[parameter(Mandatory=$true)][string]$FriendlyName,
[parameter(Mandatory=$true)][string]$FullFilePath, 
[Parameter(Mandatory=$true)][string]$BuildVersion
)
    #Write-VerboseOutput("Calling Function: New-FileLevelHotfixObject")
    #Write-VerboseOutput("Passed - FriendlyName: {0} FullFilePath: {1} BuldVersion: {2}" -f $FriendlyName, $FullFilePath, $BuildVersion)
    [HealthChecker.FileVersionCheckObject]$FileVersion_obj = New-Object HealthChecker.FileVersionCheckObject
    $FileVersion_obj.FriendlyFileName = $FriendlyName
    $FileVersion_obj.FullPath = $FullFilePath
    $FileVersion_obj.BuildVersion = $BuildVersion
    return $FileVersion_obj
}

Function Get-HotFixListInfo{
param(
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OS_Version
)
    $hotfix_objs = @()
    switch ($OS_Version)
    {
        ([HealthChecker.OSVersionName]::Windows2008R2)
        {
            [HealthChecker.HotfixObject]$hotfix_obj = New-Object HealthChecker.HotfixObject
            $hotfix_obj.KBName = "KB3004383"
            $hotfix_obj.ValidFileLevelCheck = $true
            $hotfix_obj.FileInformation += (New-FileLevelHotfixObject -FriendlyName "Appidapi.dll" -FullFilePath "C:\Windows\SysWOW64\Appidapi.dll" -BuildVersion "6.1.7601.22823")
            #For this check, we are only going to check for one file, because there are a ridiculous amount in this KB. Hopefully we don't see many false positives 
            $hotfix_objs += $hotfix_obj
            return $hotfix_objs
        }
        ([HealthChecker.OSVersionName]::Windows2012R2)
        {
            [HealthChecker.HotfixObject]$hotfix_obj = New-Object HealthChecker.HotfixObject
            $hotfix_obj.KBName = "KB3041832"
            $hotfix_obj.ValidFileLevelCheck = $true
            $hotfix_obj.FileInformation += (New-FileLevelHotfixObject -FriendlyName "Hwebcore.dll" -FullFilePath "C:\Windows\SysWOW64\inetsrv\Hwebcore.dll" -BuildVersion "8.5.9600.17708")
            $hotfix_obj.FileInformation += (New-FileLevelHotfixObject -FriendlyName "Iiscore.dll" -FullFilePath "C:\Windows\SysWOW64\inetsrv\Iiscore.dll" -BuildVersion "8.5.9600.17708")
            $hotfix_obj.FileInformation += (New-FileLevelHotfixObject -FriendlyName "W3dt.dll" -FullFilePath "C:\Windows\SysWOW64\inetsrv\W3dt.dll" -BuildVersion "8.5.9600.17708")
            $hotfix_objs += $hotfix_obj
            
            return $hotfix_objs
        }
        ([HealthChecker.OSVersionName]::Windows2016)
        {
            [HealthChecker.HotfixObject]$hotfix_obj = New-Object HealthChecker.HotfixObject
            $hotfix_obj.KBName = "KB3206632"
            $hotfix_obj.ValidFileLevelCheck = $false
            $hotfix_obj.FileInformation += (New-FileLevelHotfixObject -FriendlyName "clusport.sys" -FullFilePath "C:\Windows\System32\drivers\clusport.sys" -BuildVersion "10.0.14393.576")
            $hotfix_objs += $hotfix_obj
            return $hotfix_objs
        }
    }

    return $null
}

Function Remote-GetFileVersionInfo {
param(
[Parameter(Mandatory=$true)][object]$PassedObject 
)
    $KBsInfo = $PassedObject.KBCheckList
    $ReturnList = @()
    foreach($KBInfo in $KBsInfo)
    {
        $main_obj = New-Object PSCustomObject
        $main_obj | Add-Member -MemberType NoteProperty -Name KBName -Value $KBInfo.KBName 
        $kb_info_List = @()
        foreach($FilePath in $KBInfo.KBInfo)
        {
            $obj = New-Object PSCustomObject
            $obj | Add-Member -MemberType NoteProperty -Name FriendlyName -Value $FilePath.FriendlyName
            $obj | Add-Member -MemberType NoteProperty -Name FilePath -Value $FilePath.FilePath
            $obj | Add-Member -MemberType NoteProperty -Name Error -Value $false
            if(Test-Path -Path $FilePath.FilePath)
            {
            $info = Get-childItem $FilePath.FilePath
            $obj | Add-Member -MemberType NoteProperty -Name ChildItemInfo -Value $info 
            $buildVersion = "{0}.{1}.{2}.{3}" -f $info.VersionInfo.FileMajorPart, $info.VersionInfo.FileMinorPart, $info.VersionInfo.FileBuildPart, $info.VersionInfo.FilePrivatePart
            $obj | Add-Member -MemberType NoteProperty -Name BuildVersion -Value $buildVersion
            
            }
            else 
            {
                $obj.Error = $true
            }
            $kb_info_List += $obj
        }
        $main_obj | Add-Member -MemberType NoteProperty -Name KBInfo -Value $kb_info_List
        $ReturnList += $main_obj
    }

    return $ReturnList
}

Function Get-RemoteHotFixInformation {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OS_Version
)
    $HotfixListObjs = Get-HotFixListInfo -OS_Version $OS_Version
    if($HotfixListObjs -ne $null)    
    {
        $oldErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "stop"
        try 
        {
            $kbList = @() 
            $results = @()
            foreach($HotfixListObj in $HotfixListObjs)
            {
                #HotfixListObj contains all files that we should check for that particular KB to make sure we are on the correct build 
                $kb_obj = New-Object PSCustomObject
                $kb_obj | Add-Member -MemberType NoteProperty -Name KBName -Value $HotfixListObj.KBName
                $list = @()
                foreach($FileCheck in $HotfixListObj.FileInformation)
                {
                    $obj = New-Object PSCustomObject
                    $obj | Add-Member -MemberType NoteProperty -Name FilePath -Value $FileCheck.FullPath
                    $obj | Add-Member -MemberType NoteProperty -Name FriendlyName -Value $FileCheck.FriendlyFileName
                    $list += $obj
                    #$results += Invoke-Command -ComputerName $Machine_Name -ScriptBlock $script_block -ArgumentList $FileCheck.FullPath
                }
                $kb_obj | Add-Member -MemberType NoteProperty -Name KBInfo -Value $list   
                $kbList += $kb_obj             
            }
            $argList = New-Object PSCustomObject
            $argList | Add-Member -MemberType NoteProperty -Name "KBCheckList" -Value $kbList
            
            if($Machine_Name -ne $env:COMPUTERNAME)
            {
                Write-VerboseOutput("Calling Remote-GetFileVersionInfo via Invoke-Command")
                $results = Invoke-Command -ComputerName $Machine_Name -ScriptBlock ${Function:Remote-GetFileVersionInfo} -ArgumentList $argList
            }
            else 
            {
                Write-VerboseOutput("Calling Remote-GetFileVersionInfo via local session")
                $results = Remote-GetFileVersionInfo -PassedObject $argList 
            }
            
            
            return $results
        }
        catch 
        {
            Invoke-CatchActions
        }
        finally
        {
            $ErrorActionPreference = $oldErrorAction
        }
        
    }
}

Function Get-ServerRebootPending {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-ServerRebootPending")
    Write-VerboseOutput("Passed: {0}" -f $Machine_Name)

    $PendingFileReboot = $false
    $PendingAutoUpdateReboot = $false
    $PendingCBSReboot = $false #Component-Based Servicing Reboot 
    $PendingSCCMReboot = $false
    $ServerPendingReboot = $false

    #Pending File Rename operations 
    Function Get-PendingFileReboot {

        $PendingFileKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
        $file = Get-ItemProperty -Path $PendingFileKeyPath -Name PendingFileRenameOperations
        if($file)
        {
            return $true
        }
        return $false
    }

    Function Get-PendingAutoUpdateReboot {

        if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
        {
            return $true
        }
        return $false
    }

    Function Get-PendingCBSReboot {

        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
        {
            return $true
        }
        return $false
    }

    Function Get-PendingSCCMReboot {

        $SCCMReboot = Invoke-CimMethod -Namespace 'Root\ccm\clientSDK' -ClassName 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending'

        if($SCCMReboot)
        {
            If($SCCMReboot.RebootPending -or $SCCMReboot.IsHardRebootPending)
            {
                return $true
            }
        }
        return $false
    }

    Function Execute-ScriptBlock{
    param(
    [Parameter(Mandatory=$true)][string]$Machine_Name,
    [Parameter(Mandatory=$true)][scriptblock]$Script_Block,
    [Parameter(Mandatory=$true)][string]$Script_Block_Name
    )
        Write-VerboseOutput("Calling Script Block {0} for server {1}." -f $Script_Block_Name, $Machine_Name)
        $oldErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        $returnValue = $false
        try 
        {
            $returnValue = Invoke-Command -ComputerName $Machine_Name -ScriptBlock $Script_Block
        }
        catch 
        {
            Write-VerboseOutput("Failed to run Invoke-Command for Script Block {0} on Server {1} --- Note: This could be normal" -f $Script_Block_Name, $Machine_Name)
            Invoke-CatchActions
        }
        finally 
        {
            $ErrorActionPreference = $oldErrorAction
        }
        return $returnValue
    }

    Function Execute-LocalMethods {
    param(
    [Parameter(Mandatory=$true)][string]$Machine_Name,
    [Parameter(Mandatory=$true)][ScriptBlock]$Script_Block,
    [Parameter(Mandatory=$true)][string]$Script_Block_Name
    )
        $oldErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        $returnValue = $false
        Write-VerboseOutput("Calling Local Script Block {0} for server {1}." -f $Script_Block_Name, $Machine_Name)
        try 
        {
            $returnValue = & $Script_Block
        }
        catch 
        {
            Write-VerboseOutput("Failed to run local for Script Block {0} on Server {1} --- Note: This could be normal" -f $Script_Block_Name, $Machine_Name)
            Invoke-CatchActions
        }
        finally 
        {
            $ErrorActionPreference = $oldErrorAction
        }
        return $returnValue
    }

    if($Machine_Name -eq $env:COMPUTERNAME)
    {
        Write-VerboseOutput("Calling Server Reboot Pending options via local session")
        $PendingFileReboot = Execute-LocalMethods -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingFileReboot} -Script_Block_Name "Get-PendingFileReboot"
        $PendingAutoUpdateReboot = Execute-LocalMethods -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingAutoUpdateReboot} -Script_Block_Name "Get-PendingAutoUpdateReboot"
        $PendingCBSReboot = Execute-LocalMethods -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingCBSReboot} -Script_Block_Name "Get-PendingCBSReboot"
        $PendingSCCMReboot = Execute-LocalMethods -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingSCCMReboot} -Script_Block_Name "Get-PendingSCCMReboot"
    }
    else 
    {
        Write-VerboseOutput("Calling Server Reboot Pending options via Invoke-Command")
        $PendingFileReboot = Execute-ScriptBlock -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingFileReboot} -Script_Block_Name "Get-PendingFileReboot"
        $PendingAutoUpdateReboot = Execute-ScriptBlock -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingAutoUpdateReboot} -Script_Block_Name "Get-PendingAutoUpdateReboot"
        $PendingCBSReboot = Execute-ScriptBlock -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingCBSReboot} -Script_Block_Name "Get-PendingCBSReboot"
        $PendingSCCMReboot = Execute-ScriptBlock -Machine_Name $Machine_Name -Script_Block ${Function:Get-PendingSCCMReboot} -Script_Block_Name "Get-PendingSCCMReboot"
    }

    Write-VerboseOutput("Results - PendingFileReboot: {0} PendingAutoUpdateReboot: {1} PendingCBSReboot: {2} PendingSCCMReboot: {3}" -f $PendingFileReboot, $PendingAutoUpdateReboot, $PendingCBSReboot, $PendingSCCMReboot)
    if($PendingFileReboot -or $PendingAutoUpdateReboot -or $PendingCBSReboot -or $PendingSCCMReboot)
    {
        $ServerPendingReboot = $true
    }

    Write-VerboseOutput("Exit: Get-ServerRebootPending")
    return $ServerPendingReboot
}

Function Get-TLSSettingsFromRegistry {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name,
[Parameter(Mandatory=$true)][HealthChecker.TLSVersion]$TLSVersion
)
    $regBase = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS {0}\{1}"
    switch($TLSVersion)
    {
        ([HealthChecker.TLSVersion]::TLS10)
        {
            $version = "1.0"
        }
        ([HealthChecker.TLSVersion]::TLS11)
        {
            $version = "1.1"
        }
        ([HealthChecker.TLSVersion]::TLS12)
        {
            $version = "1.2"
        }
    }

    $regServer = $regBase -f $version, "Server"
    $regClient = $regBase -f $version, "Client"
    $serverEnabled = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey $regServer -GetValue "Enabled"
    $serverDisabledByDefault = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name $regServer -GetValue "DisabledByDefault"
    $clientEnabled = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey $regClient -GetValue "Enabled"
    $clientDisabledByDefault = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey $regClient -GetValue "DisabledByDefault"
    
    if($serverEnabled -eq $null)
    {
        Write-Red("Failed to get TLS {0} Server Enabled Key on Server {1}. We are assuming that it is enabled." -f $version, $Machine_Name)
        Write-Yellow("This can be normal on Windows Server 2008 R2.")
        $serverEnabled = $true 
    }
    else 
    {
        Write-VerboseOutput("Server Enabled Value {0}" -f $serverEnabled)
        if($serverEnabled -eq 1)
        {
            $serverEnabled = $true 
        }
        else 
        {
            $serverEnabled = $false 
        }
    }
    if($serverDisabledByDefault -eq $null)
    {
        Write-VerboseOutput("Failed to get Server Disabled By Default value from registry. Setting to false")
        $serverDisabledByDefault = $false 
    }
    else 
    {
        Write-VerboseOutput("Server Disabled By Default value {0}" -f $serverDisabledByDefault)
        if($serverDisabledByDefault -eq 1)
        {
            $serverDisabledByDefault = $true 
        }
        else 
        {
            $serverDisabledByDefault = $false 
        }
    }
    if($clientEnabled -eq $null)
    {
        Write-VerboseOutput("Failed to get Client Enabled Key on Server. Setting to true (Enabled) by default.")
        $clientEnabled = $true 
    }
    else 
    {
        Write-VerboseOutput("Client Enabled value {0}" -f $clientEnabled)
        if($clientEnabled -eq 1)
        {
            $clientEnabled = $true
        }
        else 
        {
            $clientEnabled = $false 
        }
    }
    if($clientDisabledByDefault -eq $null)
    {
        Write-VerboseOutput("Failed to get Client Disabled By Default Key on Server. Setting to false.")
        $clientDisabledByDefault = $false 
    }
    else 
    {
        Write-VerboseOutput("Client Disabled By Default value {0}" -f $clientDisabledByDefault)
        if($clientDisabledByDefault -eq 1)
        {
            $clientDisabledByDefault = $true 
        }
        else 
        {
            $clientDisabledByDefault = $false 
        }
    }

    $returnObj = New-Object pscustomobject 
    $returnObj | Add-Member -MemberType NoteProperty -Name "ServerEnabled" -Value $serverEnabled
    $returnObj | Add-Member -MemberType NoteProperty -Name "ServerDisabledByDefault" -Value $serverDisabledByDefault
    $returnObj | Add-Member -MemberType NoteProperty -Name "ClientEnabled" -Value $clientEnabled 
    $returnObj | Add-Member -MemberType NoteProperty -Name "ClientDisabledByDefault" -Value $clientDisabledByDefault

    return $returnObj
}

Function Get-TLSSettings{
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    $tlsSettings = @() 
    $tlsObj = New-Object HealthChecker.TLSObject
    $tlsObj.TLSName = "1.0"
    $tlsResults = Get-TLSSettingsFromRegistry -Machine_Name $Machine_Name -TLSVersion ([HealthChecker.TLSVersion]::TLS10)
    $tlsObj.ClientEnabled = $tlsResults.ClientEnabled
    $tlsObj.ClientDisabledByDefault = $tlsResults.ClientDisabledByDefault
    $tlsObj.ServerEnabled = $tlsResults.ServerEnabled
    $tlsObj.ServerDisabledByDefault = $tlsResults.ServerDisabledByDefault
    $tlsSettings += $tlsObj

    $tlsObj = New-Object HealthChecker.TLSObject
    $tlsObj.TLSName = "1.1"
    $tlsResults = Get-TLSSettingsFromRegistry -Machine_Name $Machine_Name -TLSVersion ([HealthChecker.TLSVersion]::TLS11)
    $tlsObj.ClientEnabled = $tlsResults.ClientEnabled
    $tlsObj.ClientDisabledByDefault = $tlsResults.ClientDisabledByDefault
    $tlsObj.ServerEnabled = $tlsResults.ServerEnabled
    $tlsObj.ServerDisabledByDefault = $tlsResults.ServerDisabledByDefault
    $tlsSettings += $tlsObj

    $tlsObj = New-Object HealthChecker.TLSObject
    $tlsObj.TLSName = "1.2"
    $tlsResults = Get-TLSSettingsFromRegistry -Machine_Name $Machine_Name -TLSVersion ([HealthChecker.TLSVersion]::TLS12)
    $tlsObj.ClientEnabled = $tlsResults.ClientEnabled
    $tlsObj.ClientDisabledByDefault = $tlsResults.ClientDisabledByDefault
    $tlsObj.ServerEnabled = $tlsResults.ServerEnabled
    $tlsObj.ServerDisabledByDefault = $tlsResults.ServerDisabledByDefault
    $tlsSettings += $tlsObj

    return $tlsSettings
}

Function Set-NetTLSDefaultVersions2010 {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExchangeServerObject
)
    Write-VerboseOutput("Calling: Set-NetTLSDefaultVersions2010")
    $regBase = "SOFTWARE\{0}\.NETFramework\v2.0.50727"
    $HealthExchangeServerObject.OSVersion.NetDefaultTlsVersion.SystemDefaultTlsVersions = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $HealthExchangeServerObject.ServerName -SubKey ($regBase -f "Microsoft") -GetValue "SystemDefaultTlsVersions"
    $HealthExchangeServerObject.OSVersion.NetDefaultTlsVersion.WowSystemDefaultTlsVersions = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $HealthExchangeServerObject.ServerName -SubKey ($regBase -f "Wow6432Node\Microsoft") -GetValue "SystemDefaultTlsVersions"
    return $HealthExchangeServerObject
}

Function Get-NetTLSDefaultVersions {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-NetTLSDefaultVersions")
    Write-VerboseOutput("Passed: {0}" -f $Machine_Name)

    $netTlsVersion = New-Object HealthChecker.NetDefaultTlsVersionObject
    $regBase = "SOFTWARE\{0}\.NETFramework\v4.0.30319"
    $netTlsVersion.SystemDefaultTlsVersions = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey ($regBase -f "Microsoft") -GetValue "SystemDefaultTlsVersions"
    $netTlsVersion.WowSystemDefaultTlsVersions = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey ($regBase -f "Wow6432Node\Microsoft") -GetValue "SystemDefaultTlsVersions"
    return $netTlsVersion
}

Function Build-OperatingSystemObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
 
    Write-VerboseOutput("Calling: Build-OperatingSystemObject")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.OperatingSystemObject]$os_obj = New-Object HealthChecker.OperatingSystemObject
    $os = Get-WmiObject -ComputerName $Machine_Name -Class Win32_OperatingSystem
    try
    {
        $plan = Get-WmiObject -ComputerName $Machine_Name -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "isActive='true'" -ErrorAction Stop
    }
    catch
    {
        Write-VerboseOutput("Unable to get power plan from the server")
        Invoke-CatchActions
        $plan = $null
    }
    $temp_currentdate = Get-Date
    $temp_uptime = [Management.ManagementDateTimeConverter]::ToDateTime($os.lastbootuptime)
    $os_obj.OSVersionBuild = $os.Version
    $os_obj.OSVersion = (Get-OperatingSystemVersion -OS_Version $os_obj.OSVersionBuild)
    $os_obj.OperatingSystemName = $os.Caption
    $os_obj.OperatingSystem = $os
    $os_obj.BootUpTimeInDays = ($temp_currentdate - $temp_uptime).Days
    $os_obj.BootUpTimeInHours = ($temp_currentdate - $temp_uptime).Hours
    $os_obj.BootUpTimeInMinutes = ($temp_currentdate - $temp_uptime).Minutes
    $os_obj.BootUpTimeInSeconds = ($temp_currentdate - $temp_uptime).Seconds
    
    if($plan -ne $null)
    {
        if($plan.InstanceID -eq "Microsoft:PowerPlan\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}")
        {
            Write-VerboseOutput("High Performance Power Plan is set to true")
            $os_obj.HighPerformanceSet = $true
        }
        $os_obj.PowerPlanSetting = $plan.ElementName
        
    }
    else
    {
        Write-VerboseOutput("Power Plan Information could not be read")
        $os_obj.HighPerformanceSet = $false
        $os_obj.PowerPlanSetting = "N/A"
    }
    $os_obj.PowerPlan = $plan 
    $os_obj.PageFile = (Get-PageFileObject -Machine_Name $Machine_Name)
    $os_obj.NetworkAdaptersConfiguration = Get-WmiObject -ComputerName $Machine_Name -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
    $os_obj.NetworkAdapters = (Build-NICInformationObject -Machine_Name $Machine_Name -OSVersion $os_obj.OSVersion)
    foreach($adapter in $os_obj.NetworkAdaptersConfiguration)
    {
        Write-VerboseOutput("Working on {0}" -f $adapter.Description)
        $settingID = $adapter.SettingID
        Write-VerboseOutput("SettingID: {0}" -f $settingID)
        $IPv6Enabled = $false 
        foreach($address in $adapter.IPAddress)
        {
            if($address.Contains(":"))
            {
                Write-VerboseOutput("Determined IPv6 enabled")
                $IPv6Enabled = $true 
            }
        }
        Write-VerboseOutput("Going to try to find the Network Adapter that goes with this adapter configuration")
        foreach($nicAdapter in $os_obj.NetworkAdapters)
        {
            $nicObject = $nicAdapter.NICObject
            Write-VerboseOutput("Checking against '{0}'" -f $nicAdapter.Description)
            Write-VerboseOutput("GUID: '{0}' InterfaceGUID: '{1}'" -f $nicObject.GUID, $nicObject.InterfaceGUID)
            if($settingID -eq $nicObject.GUID -or $settingID -eq $nicObject.InterfaceGuid)
            {
                Write-VerboseOutput("Found setting the ipv6enabled: {0}" -f $IPv6Enabled)
                $nicAdapter.IPv6Enabled = $IPv6Enabled 
            }
        }
        if(!$IPv6Enabled)
        {
            $os_obj.IPv6DisabledOnNICs = $true 
        }
    }

    $os_obj.DisabledComponents = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -GetValue "DisabledComponents"
    $os_obj.TCPKeepAlive = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -GetValue "KeepAliveTime"
    $os_obj.MinimumConnectionTimeout = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "Software\Policies\Microsoft\Windows NT\RPC\" -GetValue "MinimumConnectionTimeout"
	$os_obj.HttpProxy = Get-HttpProxySetting -Machine_Name $Machine_Name
    $os_obj.HotFixes = (Get-HotFix -ComputerName $Machine_Name -ErrorAction SilentlyContinue) #old school check still valid and faster and a failsafe 
    $os_obj.HotFixInfo = Get-RemoteHotFixInformation -Machine_Name $Machine_Name -OS_Version $os_obj.OSVersion 
    $os_obj.LmCompat = (Build-LmCompatibilityLevel -Machine_Name $Machine_Name)
    $counterSamples = (Get-CounterSamples -MachineNames $Machine_Name -Counters "\Network Interface(*)\Packets Received Discarded")
    if($counterSamples -ne $null)
    {
        $os_obj.PacketsReceivedDiscarded = $counterSamples
    }
    $os_obj.ServerPendingReboot = (Get-ServerRebootPending -Machine_Name $Machine_Name)
    $os_obj.TimeZone = ([System.TimeZone]::CurrentTimeZone).StandardName
    $os_obj.TLSSettings = Get-TLSSettings -Machine_Name $Machine_Name
    $os_obj.NetDefaultTlsVersion = Get-NetTLSDefaultVersions -Machine_Name $Machine_Name

    return $os_obj
}

Function Get-ServerType {
param(
[Parameter(Mandatory=$true)][string]$ServerType
)
    Write-VerboseOutput("Calling: Get-ServerType")
    Write-VerboseOutput("Passed: $serverType")



    if($ServerType -like "VMware*"){Write-VerboseOutput("Returned: VMware"); return [HealthChecker.ServerType]::VMWare}
    elseif($ServerType -like "*Microsoft Corporation*"){Write-VerboseOutput("Returned: HyperV"); return [HealthChecker.ServerType]::HyperV}
    elseif($ServerType.Length -gt 0) {Write-VerboseOutput("Returned: Physical"); return [HealthChecker.ServerType]::Physical}
    else{Write-VerboseOutput("Returned: unknown") ;return [HealthChecker.ServerType]::Unknown}
    
}


Function Get-ProcessorInformationObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-ProcessorInformationObject")
    Write-VerboseOutput("Passed: $Machine_Name")
    [HealthChecker.ProcessorInformationObject]$processor_info_object = New-Object HealthChecker.ProcessorInformationObject
    $wmi_obj_processor = Get-WmiObject -ComputerName $Machine_Name -Class Win32_Processor
    $object_Type = $wmi_obj_processor.Gettype().Name 
    Write-VerboseOutput("Processor object type: $object_Type")
    
    #if it is a single processor 
    if($object_Type -eq "ManagementObject") {
        Write-VerboseOutput("single processor detected")
        $processor_info_object.ProcessorName = $wmi_obj_processor.Name
        $processor_info_object.MaxMegacyclesPerCore = $wmi_obj_processor.MaxClockSpeed
    }
    else{
        Write-VerboseOutput("multiple processor detected")
        $processor_info_object.ProcessorName = $wmi_obj_processor[0].Name
        $processor_info_object.MaxMegacyclesPerCore = $wmi_obj_processor[0].MaxClockSpeed
    }

    #Get the total number of cores in the processors 
    Write-VerboseOutput("getting the total number of cores in the processor(s)")
    foreach($processor in $wmi_obj_processor) 
    {
        $processor_info_object.NumberOfPhysicalCores += $processor.NumberOfCores 
        $processor_info_object.NumberOfLogicalProcessors += $processor.NumberOfLogicalProcessors
        $processor_info_object.NumberOfProcessors += 1 #may want to call Win32_ComputerSystem and use NumberOfProcessors for this instead.. but this should get the same results. 

        #Test to see if we are throttling the processor 
        if($processor.CurrentClockSpeed -lt $processor.MaxClockSpeed) 
        {
            Write-VerboseOutput("We see the processor being throttled")
            $processor_info_object.CurrentMegacyclesPerCore = $processor.CurrentClockSpeed
            $processor_info_object.ProcessorIsThrottled = $true 
        }

        if($processor.Name -ne $processor_info_object.ProcessorName -or $processor.MaxClockSpeed -ne $processor_info_object.MaxMegacyclesPerCore){$processor_info_object.DifferentProcessorsDetected = $true; Write-VerboseOutput("Different Processors are detected"); Write-Yellow("Warning: Different Processors are detected. This shouldn't occur")}
    }

	Write-VerboseOutput("Trying to get the System.Environment ProcessorCount")
	$oldError = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    Function Get-ProcessorCount {
        [System.Environment]::ProcessorCount
    }
	try
	{
        if($Machine_Name -ne $env:COMPUTERNAME)
        {
            Write-VerboseOutput("Getting System.Environment ProcessorCount from Invoke-Command")
            $processor_info_object.EnvProcessorCount = (
                Invoke-Command -ComputerName $Machine_Name -ScriptBlock ${Function:Get-ProcessorCount}
            )
        }
        else 
        {
            Write-VerboseOutput("Getting System.Environment ProcessorCount from local session")
            $processor_info_object.EnvProcessorCount = Get-ProcessorCount
        }

	}
	catch
	{
        Invoke-CatchActions
		Write-Red("Error: Unable to get Environment Processor Count on server {0}" -f $Machine_Name)
		$processor_info_object.EnvProcessorCount = -1 
	}
	finally
	{
		$ErrorActionPreference = $oldError
	}

    $processor_info_object.Processor = $wmi_obj_processor
    return $processor_info_object

}

Function Build-HardwareObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Build-HardwareObject")
    Write-VerboseOutput("Passed: $Machine_Name")
    [HealthChecker.HardwareObject]$hardware_obj = New-Object HealthChecker.HardwareObject
    $system = Get-WmiObject -ComputerName $Machine_Name -Class Win32_ComputerSystem
    $hardware_obj.Manufacturer = $system.Manufacturer
    $hardware_obj.System = $system
    $hardware_obj.AutoPageFile = $system.AutomaticManagedPagefile
    $hardware_obj.TotalMemory = $system.TotalPhysicalMemory
    $hardware_obj.ServerType = (Get-ServerType -ServerType $system.Manufacturer)
    $hardware_obj.Processor = Get-ProcessorInformationObject -Machine_Name $Machine_Name 
    $hardware_obj.Model = $system.Model 

    return $hardware_obj
}


Function Get-NetFrameworkVersionFriendlyInfo{
param(
[Parameter(Mandatory=$true)][int]$NetVersionKey,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OSVersionName 
)
    Write-VerboseOutput("Calling: Get-NetFrameworkVersionFriendlyInfo")
    Write-VerboseOutput("Passed: " + $NetVersionKey.ToString())
    Write-VerboseOutput("Passed: " + $OSVersionName.ToString())
    [HealthChecker.NetVersionObject]$versionObject = New-Object -TypeName HealthChecker.NetVersionObject
        if(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d5) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d5d1))
    {
        $versionObject.FriendlyName = "4.5"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d5
    }
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d5d1) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d5d2))
    {
        $versionObject.FriendlyName = "4.5.1"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d5d1
    }
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d5d2) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d5d2wFix))
    {
        $versionObject.FriendlyName = "4.5.2"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d5d2
    }
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d5d2wFix) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d6))
    {
        $versionObject.FriendlyName = "4.5.2 with Hotfix 3146718"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d5d2wFix
    }
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d6) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d6d1))
    {
        $versionObject.FriendlyName = "4.6"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d6
    }
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d6d1) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d6d1wFix))
    {
        $versionObject.FriendlyName = "4.6.1"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d6d1
    }
    elseif($NetVersionKey -eq 394802 -and $OSVersionName -eq [HealthChecker.OSVersionName]::Windows2016)
    {
        $versionObject.FriendlyName = "Windows Server 2016 .NET 4.6.2"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d6d2
    }
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d6d1wFix) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d6d2))
    {
        $versionObject.FriendlyName = "4.6.1 with Hotfix 3146716/3146714/3146715"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d6d1wFix
    }
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d6d2) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d7))
    {
        $versionObject.FriendlyName = "4.6.2"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d6d2
    }
	elseif($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d7 -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d7d1))
	{
		$versionObject.FriendlyName = "4.7"
		$versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d7
    }
    elseif($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d7d1 -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d7d2))
    {
        $versionObject.FriendlyName = "4.7.1"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d7d1
    }
    elseif($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d7d2)
    {
        $versionObject.FriendlyName = "4.7.2"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d7d2
    }
    else
    {
        $versionObject.FriendlyName = "Unknown" 
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Unknown
    }
    $versionObject.NetRegValue = $NetVersionKey


    Write-VerboseOutput("Returned: " + $versionObject.FriendlyName)
    return $versionObject
    
}


#Uses registry build numbers from https://msdn.microsoft.com/en-us/library/hh925568(v=vs.110).aspx
Function Build-NetFrameWorkVersionObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OSVersionName
)
    Write-VerboseOutput("Calling: Build-NetFrameWorkVersionObject")
    Write-VerboseOutput("Passed: $Machine_Name")
    Write-VerboseOutput("Passed: $OSVersionName")
    [int]$NetVersionKey = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -GetValue "Release"
    Write-VerboseOutput("Got {0} from the registry" -f $NetVersionKey)
    [HealthChecker.NetVersionObject]$versionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $NetVersionKey -OSVersionName $OSVersionName
    return $versionObject
}

Function Get-ExchangeVersion {
param(
[Parameter(Mandatory=$true)][object]$AdminDisplayVersion
)
    Write-VerboseOutput("Calling: Get-ExchangeVersion")
    Write-VerboseOutput("Passed: " + $AdminDisplayVersion.ToString())
    $iBuild = $AdminDisplayVersion.Major + ($AdminDisplayVersion.Minor / 10)
    Write-VerboseOutput("Determing build based of of: " + $iBuild) 
    switch($iBuild)
    {
        14.3 {Write-VerboseOutput("Returned: Exchange2010"); return [HealthChecker.ExchangeVersion]::Exchange2010}
        15 {Write-VerboseOutput("Returned: Exchange2013"); return [HealthChecker.ExchangeVersion]::Exchange2013}
        15.1{Write-VerboseOutput("Returned: Exchange2016"); return [HealthChecker.ExchangeVersion]::Exchange2016}
        15.2{Write-VerboseOutput("Returned: Exchange2019"); return [HealthChecker.ExchangeVersion]::Exchange2019}
        default {Write-VerboseOutput("Returned: Unknown"); return [HealthChecker.ExchangeVersion]::Unknown}
    }

}

Function Get-BuildNumberToString {
param(
[Parameter(Mandatory=$true)][object]$AdminDisplayVersion
)
    $sAdminDisplayVersion = $AdminDisplayVersion.Major.ToString() + "." + $AdminDisplayVersion.Minor.ToString() + "."  + $AdminDisplayVersion.Build.ToString() + "."  + $AdminDisplayVersion.Revision.ToString()
    Write-VerboseOutput("Called: Get-BuildNumberToString")
    Write-VerboseOutput("Returned: " + $sAdminDisplayVersion)
    return $sAdminDisplayVersion
}

<#
New Release Update 
#>
Function Get-ExchangeBuildObject {
param(
[Parameter(Mandatory=$true)][object]$AdminDisplayVersion
)
    Write-VerboseOutput("Calling: Get-ExchangeBuildObject")
    Write-VerboseOutput("Passed: " + $AdminDisplayVersion.ToString())
    [HealthChecker.ExchangeBuildObject]$exBuildObj = New-Object -TypeName HealthChecker.ExchangeBuildObject
    $iRevision = if($AdminDisplayVersion.Revision -lt 10) {$AdminDisplayVersion.Revision /10} else{$AdminDisplayVersion.Revision /100}
    $buildRevision = $AdminDisplayVersion.Build + $iRevision
    Write-VerboseOutput("Revision Value: " + $iRevision)
    Write-VerboseOutput("Build Plus Revision Value: " + $buildRevision)
    #https://technet.microsoft.com/en-us/library/hh135098(v=exchg.150).aspx
    #https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019

    if($AdminDisplayVersion.Major -eq 15 -and $AdminDisplayVersion.Minor -eq 2)
    {
        Write-VerboseOutput("Determined that we are on Exchange 2019")
        $exBuildObj.ExchangeVersion = [HealthChecker.ExchangeVersion]::Exchange2019
        if($buildRevision -ge 196.0 -and $buildRevision -lt 221.12){if($buildRevision -gt 196.9){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::Preview}
        elseif($buildRevision -lt 330.6){if($buildRevision -gt 221.12){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::RTM}
        elseif($buildRevision -ge 330.6){if($buildRevision -gt 330.6){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU1}
    }
    elseif($AdminDisplayVersion.Major -eq 15 -and $AdminDisplayVersion.Minor -eq 1)
    {
        Write-VerboseOutput("Determined that we are on Exchange 2016")
        $exBuildObj.ExchangeVersion = [HealthChecker.ExchangeVersion]::Exchange2016
        if($buildRevision -ge 225.16 -and $buildRevision -lt 225.42) {if($buildRevision -gt 225.16){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::Preview}
        elseif($buildRevision -lt 396.30) {if($buildRevision -gt 225.42){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::RTM}
        elseif($buildRevision -lt 466.34) {if($buildRevision -gt 396.30){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU1}
        elseif($buildRevision -lt 544.27) {if($buildRevision -gt 466.34){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU2}
        elseif($buildRevision -lt 669.32) {if($buildRevision -gt 544.27){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU3}
        elseif($buildRevision -lt 845.34) {if($buildRevision -gt 669.32){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU4}
        elseif($buildRevision -lt 1034.26) {if($buildRevision -gt 845.34){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU5}
        elseif($buildRevision -lt 1261.35) {if($buildRevision -gt 1034.26){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU6}
        elseif($buildRevision -lt 1415.2) {if($buildRevision -gt 1261.35){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU7}
        elseif($buildRevision -lt 1466.3) {if($buildRevision -gt 1415.2){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU8}
        elseif($buildRevision -lt 1531.3) {if($buildRevision -gt 1466.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU9}
        elseif($buildRevision -lt 1591.10) {if($buildRevision -gt 1531.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU10}
        elseif($buildRevision -lt 1713.5) {if($buildRevision -gt 1591.10){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU11}
        elseif($buildRevision -ge 1713.5) {if($buildRevision -gt 1713.5){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU12}

    }
    elseif($AdminDisplayVersion.Major -eq 15 -and $AdminDisplayVersion.Minor -eq 0)
    {
        Write-VerboseOutput("Determined that we are on Exchange 2013")
        $exBuildObj.ExchangeVersion = [HealthChecker.ExchangeVersion]::Exchange2013
        if($buildRevision -ge 516.32 -and $buildRevision -lt 620.29) {if($buildRevision -gt 516.32){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::RTM}
        elseif($buildRevision -lt 712.24) {if($buildRevision -gt 620.29){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU1}
        elseif($buildRevision -lt 775.38) {if($buildRevision -gt 712.24){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU2}
        elseif($buildRevision -lt 847.32) {if($buildRevision -gt 775.38){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU3}
        elseif($buildRevision -lt 913.22) {if($buildRevision -gt 847.32){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU4}
        elseif($buildRevision -lt 995.29) {if($buildRevision -gt 913.22){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU5}
        elseif($buildRevision -lt 1044.25) {if($buildRevision -gt 995.29){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU6}
        elseif($buildRevision -lt 1076.9) {if($buildRevision -gt 1044.25){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU7}
        elseif($buildRevision -lt 1104.5) {if($buildRevision -gt 1076.9){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU8}
        elseif($buildRevision -lt 1130.7) {if($buildRevision -gt 1104.5){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU9}
        elseif($buildRevision -lt 1156.6) {if($buildRevision -gt 1130.7){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU10}
        elseif($buildRevision -lt 1178.4) {if($buildRevision -gt 1156.6){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU11}
        elseif($buildRevision -lt 1210.3) {if($buildRevision -gt 1178.4){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU12}
        elseif($buildRevision -lt 1236.3) {if($buildRevision -gt 1210.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU13}
        elseif($buildRevision -lt 1263.5) {if($buildRevision -gt 1236.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU14}
        elseif($buildRevision -lt 1293.2) {if($buildRevision -gt 1263.5){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU15}
        elseif($buildRevision -lt 1320.4) {if($buildRevision -gt 1293.2){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU16}
        elseif($buildRevision -lt 1347.2) {if($buildRevision -gt 1320.4){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU17}
        elseif($buildRevision -lt 1365.1) {if($buildRevision -gt 1347.2){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU18}
        elseif($buildRevision -lt 1367.3) {if($buildRevision -gt 1365.1){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU19}
        elseif($buildRevision -lt 1395.4) {if($buildRevision -gt 1367.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU20}
        elseif($buildRevision -lt 1473.3) {if($buildRevision -gt 1395.4){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU21}
        elseif($buildRevision -ge 1473.3) {if($buildRevision -gt 1473.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU22}
    }
    else
    {
        Write-Red "Error: Didn't know how to process the Admin Display Version Provided"
        
    }

    return $exBuildObj

}

#New Release Update 
Function Get-ExchangeBuildInformation {
param(
[Parameter(Mandatory=$true)][object]$AdminDisplayVersion
)
    Write-VerboseOutput("Calling: Get-ExchangeBuildInformation")
    Write-VerboseOutput("Passed: " + $AdminDisplayVersion.ToString())
    [HealthChecker.ExchangeInformationTempObject]$tempObject = New-Object -TypeName HealthChecker.ExchangeInformationTempObject
    
    #going to remove the minor checks. Not sure I see a value in keeping them. 
    if($AdminDisplayVersion.Major -eq 15)
    {
       Write-VerboseOutput("Determined that we are working with Exchange 2013 or greater")
       [HealthChecker.ExchangeBuildObject]$exBuildObj = Get-ExchangeBuildObject -AdminDisplayVersion $AdminDisplayVersion 
       Write-VerboseOutput("Got the exBuildObj")
       Write-VerboseOutput("Exchange Version is set to: " + $exBuildObj.ExchangeVersion.ToString())
       Write-VerboseOutput("CU is set to: " + $exBuildObj.CU.ToString())
       Write-VerboseOutput("Inbetween CUs: " + $exBuildObj.InbetweenCUs.ToString())
       switch($exBuildObj.ExchangeVersion)
       {
        ([HealthChecker.ExchangeVersion]::Exchange2019)
            {
                Write-VerboseOutput("Working with Exchange 2019")
                switch($exBuildObj.CU)
                {
                    ([HealthChecker.ExchangeCULevel]::Preview) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2019 Preview"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "07/24/2018"; break}
                    ([HealthChecker.ExchangeCULevel]::RTM) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2019 RTM"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "10/22/2018"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU1) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2019 CU1"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "02/12/2019"; $tempObject.SupportedCU = $true; break}
                    default {Write-Red("Error: Unknown Exchange 2019 Build was detected"); $tempObject.Error = $true; break;}
                }
            }

        ([HealthChecker.ExchangeVersion]::Exchange2016)
            {
                Write-VerboseOutput("Working with Exchange 2016")
                switch($exBuildObj.CU)
                {
                    ([HealthChecker.ExchangeCULevel]::Preview) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 Preview"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "07/22/2015"; break}
                    ([HealthChecker.ExchangeCULevel]::RTM) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 RTM"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "10/01/2015"; break}
                    ([HealthChecker.ExchangeCULevel]::CU1) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU1"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "03/15/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU2) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU2"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "06/21/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU3) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU3"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "09/20/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU4) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU4"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "12/13/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU5) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU5"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "03/21/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU6) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU6"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "06/24/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU7) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU7"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "09/16/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU8) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU8"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "12/19/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU9) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU9"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "03/20/2018"; break}
                    ([HealthChecker.ExchangeCULevel]::CU10) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU10"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "06/19/2018"; break}
                    ([HealthChecker.ExchangeCULevel]::CU11) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU11"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "10/16/2018"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU12) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU12"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "02/12/2019"; $tempObject.SupportedCU = $true; break}
                    default {Write-Red "Error: Unknown Exchange 2016 build was detected"; $tempObject.Error = $true; break;}
                }
                break;
            }
        ([HealthChecker.ExchangeVersion]::Exchange2013)
            {
                Write-VerboseOutput("Working with Exchange 2013")
                switch($exBuildObj.CU)
                {
                    ([HealthChecker.ExchangeCULevel]::RTM) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 RTM"; $tempObject.ReleaseDate = "12/03/2012"; break}
                    ([HealthChecker.ExchangeCULevel]::CU1) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU1"; $tempObject.ReleaseDate = "04/02/2013"; break}
                    ([HealthChecker.ExchangeCULevel]::CU2) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU2"; $tempObject.ReleaseDate = "07/09/2013"; break}
                    ([HealthChecker.ExchangeCULevel]::CU3) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU3"; $tempObject.ReleaseDate = "11/25/2013"; break}
                    ([HealthChecker.ExchangeCULevel]::CU4) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU4"; $tempObject.ReleaseDate = "02/25/2014"; break}
                    ([HealthChecker.ExchangeCULevel]::CU5) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU5"; $tempObject.ReleaseDate = "05/27/2014"; break}
                    ([HealthChecker.ExchangeCULevel]::CU6) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU6"; $tempObject.ReleaseDate = "08/26/2014"; break}
                    ([HealthChecker.ExchangeCULevel]::CU7) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU7"; $tempObject.ReleaseDate = "12/09/2014"; break}
                    ([HealthChecker.ExchangeCULevel]::CU8) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU8"; $tempObject.ReleaseDate = "03/17/2015"; break}
                    ([HealthChecker.ExchangeCULevel]::CU9) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU9"; $tempObject.ReleaseDate = "06/17/2015"; break}
                    ([HealthChecker.ExchangeCULevel]::CU10) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU10"; $tempObject.ReleaseDate = "09/15/2015"; break}
                    ([HealthChecker.ExchangeCULevel]::CU11) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU11"; $tempObject.ReleaseDate = "12/15/2015"; break}
                    ([HealthChecker.ExchangeCULevel]::CU12) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU12"; $tempObject.ReleaseDate = "03/15/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU13) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU13"; $tempObject.ReleaseDate = "06/21/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU14) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU14"; $tempObject.ReleaseDate = "09/20/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU15) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU15"; $tempObject.ReleaseDate = "12/13/2016"; break}
                    ([HealthChecker.ExchangeCULevel]::CU16) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU16"; $tempObject.ReleaseDate = "03/21/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU17) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU17"; $tempObject.ReleaseDate = "06/24/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU18) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU18"; $tempObject.ReleaseDate = "09/16/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU19) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU19"; $tempObject.ReleaseDate = "12/19/2017"; break}
                    ([HealthChecker.ExchangeCULevel]::CU20) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU20"; $tempObject.ReleaseDate = "03/20/2018"; break}
                    ([HealthChecker.ExchangeCULevel]::CU21) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU21"; $tempObject.ReleaseDate = "06/19/2018"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU22) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU22"; $tempObject.ReleaseDate = "02/12/2019"; $tempObject.SupportedCU = $true; break}
                    default {Write-Red "Error: Unknown Exchange 2013 build was detected"; $tempObject.Error = $TRUE; break;}
                }
                break;
            }
            
        default {$tempObject.Error = $true; Write-Red "Error: Unknown error in Get-ExchangeBuildInformation"}   
       }
    }

    else
    {
        Write-VerboseOutput("Error occur because we weren't on Exchange 2013 or greater")
        $tempObject.Error = $true
    }

    return $tempObject
}

<#

Exchange 2013 Support 
https://technet.microsoft.com/en-us/library/aa996719(v=exchg.150).aspx
https://docs.microsoft.com/en-us/exchange/exchange-2013-system-requirements-exchange-2013-help

Exchange 2016 Support 
https://technet.microsoft.com/en-us/library/aa996719(v=exchg.160).aspx
https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/system-requirements?view=exchserver-2019

Team Blog Articles 

.NET Framework 4.7 and Exchange Server
https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/NET-Framework-4-7-and-Exchange-Server/ba-p/606871

Released: December 2016 Quarterly Exchange Updates
https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-December-2016-Quarterly-Exchange-Updates/ba-p/606193

Released: September 2016 Quarterly Exchange Updates
https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-September-2016-Quarterly-Exchange-Updates/ba-p/605402

Released: June 2016 Quarterly Exchange Updates
https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-June-2016-Quarterly-Exchange-Updates/ba-p/604877

Released: December 2017 Quarterly Exchange Updates
https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-December-2017-Quarterly-Exchange-Updates/ba-p/607541

Released: October 2018 Quarterly Exchange Updates
https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Released-October-2018-Quarterly-Exchange-Updates/ba-p/608455

Summary:
Exchange 2013 CU19 & 2016 CU8 .NET Framework 4.7.1 Supported on all OSs 
Exchange 2013 CU15 & 2016 CU4 .Net Framework 4.6.2 Supported on All OSs
Exchange 2016 CU3 .NET Framework 4.6.2 Supported on Windows 2016 OS - however, stuff is broke on this OS. 

Exchange 2016 CU11 Supports .NET 4.7.2

Exchange 2013 CU13 & Exchange 2016 CU2 .NET Framework 4.6.1 Supported on all OSs


Exchange 2013 CU12 & Exchange 2016 CU1 Supported on .NET Framework 4.5.2 

The upgrade to .Net 4.6.2, while strongly encouraged, is optional with these releases. As previously disclosed, the cumulative updates released in our March 2017 quarterly updates will require .Net 4.6.2.

#>
Function Check-DotNetFrameworkSupportedLevel {
param(
[Parameter(Mandatory=$true)][HealthChecker.ExchangeBuildObject]$exBuildObj,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OSVersionName,
[Parameter(Mandatory=$true)][HealthChecker.NetVersion]$NetVersion
)
    Write-VerboseOutput("Calling: Check-DotNetFrameworkSupportedLevel")


    Function Check-NetVersionToExchangeVersion {
    param(
    [Parameter(Mandatory=$true)][HealthChecker.NetVersion]$CurrentNetVersion,
    [Parameter(Mandatory=$true)][HealthChecker.NetVersion]$MinSupportNetVersion,
    [Parameter(Mandatory=$true)][HealthChecker.NetVersion]$RecommendedNetVersion
    
    )
        [HealthChecker.NetVersionCheckObject]$NetCheckObj = New-Object -TypeName HealthChecker.NetVersionCheckObject
        $NetCheckObj.RecommendedNetVersion = $true 
        Write-VerboseOutput("Calling: Check-NetVersionToExchangeVersion")
        Write-VerboseOutput("Passed: Current Net Version: " + $CurrentNetVersion.ToString())
        Write-VerboseOutput("Passed: Min Support Net Version: " + $MinSupportNetVersion.ToString())
        Write-VerboseOutput("Passed: Recommended/Max Net Version: " + $RecommendedNetVersion.ToString())

        #If we are on the recommended/supported version of .net then we should be okay 
        if($CurrentNetVersion -eq $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current Version of .NET equals the Recommended Version of .NET")
            $NetCheckObj.Supported = $true    
        }
        elseif($CurrentNetVersion -eq [HealthChecker.NetVersion]::Net4d6 -and $RecommendedNetVersion -ge [HealthChecker.NetVersion]::Net4d6d1wFix)
        {
            Write-VerboseOutput("Current version of .NET equals 4.6 while the recommended version of .NET is equal to or greater than 4.6.1 with hotfix. This means that we are on an unsupported version because we never supported just 4.6")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET 4.6 and this is an unsupported build of .NET for Exchange. Only .NET 4.6.1 with the hotfix and greater are supported. Please upgrade to " + $RecommendedNetVersionObject.FriendlyName + " as soon as possible to get into a supported state."
        }
		elseif($CurrentNetVersion -eq [HealthChecker.NetVersion]::Net4d6d1 -and $RecommendedNetVersion -ge [HealthChecker.NetVersion]::Net4d6d1wFix)
		{
			Write-VerboseOutput("Current version of .NET equals 4.6.1 while the recommended version of .NET is equal to or greater than 4.6.1 with hotfix. This means that we are on an unsupported version because we never supported just 4.6.1 without the hotfix")
			$NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false
			[HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
			$NetCheckObj.DisplayWording = "On .NET 4.6.1 and this is an unsupported build of .NET for Exchange. Only .NET 4.6.1 with the hotfix and greater are supported. Please upgrade to " + $RecommendedNetVersionObject.FriendlyName + " as soon as possible to get into a supported state."
		}

        #this catch is for when you are on a version of exchange where we can be on let's say 4.5.2 without fix, but there isn't a better option available.
        elseif($CurrentNetVersion -lt $MinSupportNetVersion -and $MinSupportNetVersion -eq $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version of .NET is less than Min Supported Version. Need to upgrade to this version as soon as possible")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionObject]$MinSupportNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $MinSupportNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the minimum supported version is " + $MinSupportNetVersionObject.FriendlyName + ". Upgrade to this version as soon as possible."
        }
        #here we are assuming that we are able to get to a much better version of .NET then the min 
        elseif($CurrentNetVersion -lt $MinSupportNetVersion)
        {
            Write-VerboseOutput("Current Version of .NET is less than Min Supported Version. However, the recommended version is the one we want to upgrade to")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionObject]$MinSupportNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $MinSupportNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the minimum supported version is " + $MinSupportNetVersionObject.FriendlyName + ", but the recommended version is " + $RecommendedNetVersionObject.FriendlyName + ". upgrade to this version as soon as possible." 
        }
        elseif($CurrentNetVersion -lt $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version is less than the recommended version, but we are at or higher than the Min Supported level. Should upgrade to the recommended version as soon as possible.")
            $NetCheckObj.Supported = $true
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the recommended version of .NET for this build of Exchange is " + $RecommendedNetVersionObject.FriendlyName + ". Upgrade to this version as soon as possible." 
        }
        elseif($CurrentNetVersion -gt $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version is greater than the recommended version. This is an unsupported state.")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the max recommended version of .NET for this build of Exchange is " + $RecommendedNetVersionObject.FriendlyName + ". Correctly remove the .NET version that you are on and reinstall the recommended max value. Generic catch message for current .NET version being greater than Max .NET version, so ask or lookup on the correct steps to address this issue."
        }
        else
        {
            $NetCheckObj.Error = $true
            Write-VerboseOutput("unknown version of .net detected or combination with Exchange build")
        }

        Return $NetCheckObj
    }

    switch($exBuildObj.ExchangeVersion)
    {
        ([HealthChecker.ExchangeVersion]::Exchange2013)
            {
                Write-VerboseOutput("Exchange 2013 Detected...checking .NET version")
				#change -lt to -le as we don't support CU12 with 4.6.1 
                if($exBuildObj.CU -le ([HealthChecker.ExchangeCULevel]::CU12))
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d5d2wFix
                }
                elseif($exBuildObj.CU -lt ([HealthChecker.ExchangeCULevel]::CU15))
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d1wFix
                }
                elseif($exBuildObj.CU -eq ([HealthChecker.ExchangeCULevel]::CU15))
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d2
                    $NetCheckObj.DisplayWording = $NetCheckObj.DisplayWording + " NOTE: Starting with CU16 we will require .NET 4.6.2 before you can install this version of Exchange." 
                }
                elseif($exBuildObj.CU -lt ([HealthChecker.ExchangeCULevel]::CU19))
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d6d2 -RecommendedNetVersion Net4d6d2
                }
                elseif($exBuildObj.CU -lt ([HealthChecker.ExchangeCULevel]::CU21))
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d6d2 -RecommendedNetVersion Net4d7d1
                }
                else
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d1 -RecommendedNetVersion Net4d7d2
                }


                break;
                
            }
        ([HealthChecker.ExchangeVersion]::Exchange2016)
            {
                Write-VerboseOutput("Exchange 2016 detected...checking .NET version")

                if($exBuildObj.CU -lt [HealthChecker.ExchangeCULevel]::CU2)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d5d2wFix
                }
                elseif($exBuildObj.CU -eq [HealthChecker.ExchangeCULevel]::CU2)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d1wFix 
                }
                elseif($exBuildObj.CU -eq [HealthChecker.ExchangeCULevel]::CU3)
                {
                    if($OSVersionName -eq [HealthChecker.OSVersionName]::Windows2016)
                    {
                        $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d2
                        $NetCheckObj.DisplayWording = $NetCheckObj.DisplayWording + " NOTE: Starting with CU16 we will require .NET 4.6.2 before you can install this version of Exchange."
                    }
                    else
                    {
                        $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d1wFix
                    }
                }
                elseif($exBuildObj.CU -eq [HealthChecker.ExchangeCULevel]::CU4)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d2 
                    $NetCheckObj.DisplayWording = $NetCheckObj.DisplayWording + " NOTE: Starting with CU5 we will require .NET 4.6.2 before you can install this version of Exchange."
                }
                elseif($exBuildObj.CU -lt [HealthChecker.ExchangeCULevel]::CU8)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d6d2 -RecommendedNetVersion Net4d6d2 
                }
                elseif($exBuildObj.CU -lt [HealthChecker.ExchangeCULevel]::CU11)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d6d2 -RecommendedNetVersion Net4d7d1
                }
                else
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d1 -RecommendedNetVersion Net4d7d2
                }
                

                break;
            }
        ([HealthChecker.ExchangeVersion]::Exchange2019)
            {
                Write-VerboseOutput("Exchange 2019 detected...checking .NET version")
                if($exBuildObj.CU -lt [HealthChecker.ExchangeCULevel]::CU2)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d1 -RecommendedNetVersion Net4d7d2
                }

            }
        default {$NetCheckObj.Error = $true; Write-VerboseOutput("Error trying to determine major version of Exchange for .NET fix level")}
    }

    return $NetCheckObj

}

Function Get-ExchangeAppPoolsInformation {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-ExchangeAppPoolsInformation")
    Write-VerboseOutput("Passed: {0}" -f $Machine_Name)
    Function Get-ExchangeAppPoolsScriptBlock 
    {
        $windir = $env:windir
        $Script:appCmd = "{0}\system32\inetsrv\appcmd.exe" -f $windir

        $appPools = &$Script:appCmd list apppool 
        $exchangeAppPools = @() 
        foreach($appPool in $appPools)
        {
            $startIndex = $appPool.IndexOf('"') + 1
            $appPoolName = $appPool.Substring($startIndex, ($appPool.Substring($startIndex).IndexOf('"')))
            if($appPoolName.StartsWith("MSExchange"))
            {
                $exchangeAppPools += $appPoolName
            }
        }

        $exchAppPools = @{}

        foreach($appPool in $exchangeAppPools)
        {
            $status = &$Script:appCmd list apppool $appPool /text:state
            $config = &$Script:appCmd list apppool $appPool /text:CLRConfigFile
            if(Test-Path $config)
            {
                $content = Get-Content $config 
            }
            else 
            {
                Write-VerboseOutput("Failed to find config file setting in app pool '{0}'" -f $appPool)
                $content = $null     
            }
            $statusObj = New-Object pscustomobject 
            $statusObj | Add-Member -MemberType NoteProperty -Name "Status" -Value $status
            $statusObj | Add-Member -MemberType NoteProperty -Name "ConfigPath" -Value $config
            $statusObj | Add-Member -MemberType NoteProperty -Name "Content" -Value $content 

            $exchAppPools.Add($appPool, $statusObj)
        }
        return $exchAppPools
    }
    $exchangeAppPoolsInfo = @{}
    if($Machine_Name -eq $env:COMPUTERNAME)
    {
        $exchangeAppPoolsInfo = Get-ExchangeAppPoolsScriptBlock
    }
    else 
    {
        try 
        {
            $exchangeAppPoolsInfo = Invoke-Command -ComputerName $Machine_Name -ScriptBlock ${Function:Get-ExchangeAppPoolsScriptBlock} -ErrorAction stop 
        }
        catch 
        {
            Write-VerboseOutput("Failed to execute invoke-commad for Get-ExchangeAppPoolsScriptBlock")
            Invoke-CatchActions
        }
    }
    return $exchangeAppPoolsInfo
}

Function Get-MapiFEAppPoolGCMode{
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-MapiFEAppPoolGCMode")
    Write-VerboseOutput("Passed: {0}" -f $Machine_Name)
    $installPath = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\ExchangeServer\v15\Setup\" -GetValue "MsiInstallPath"
    $MapiConfig = ("{0}bin\MSExchangeMapiFrontEndAppPool_CLRConfig.config" -f $installPath)
    Write-VerboseOutput("Mapi FE App Pool Config Location: {0}" -f $MapiConfig)
    $mapiGCMode = "Unknown"

    Function Get-MapiConfigGCSetting {
    param(
        [Parameter(Mandatory=$true)][string]$ConfigPath
    )
        if(Test-Path $ConfigPath)
        {
            $xml = [xml](Get-Content $ConfigPath)
            $rString =  $xml.configuration.runtime.gcServer.enabled
            return $rString
        }
        else 
        {
            Return "Unknown"    
        }
    }

    try 
    {
        if($Machine_Name -ne $env:COMPUTERNAME)
        {
            Write-VerboseOutput("Calling Get-MapiConfigGCSetting via Invoke-Command")
            $mapiGCMode = Invoke-Command -ComputerName $Machine_Name -ScriptBlock ${Function:Get-MapiConfigGCSetting} -ArgumentList $MapiConfig
        }
        else 
        {
            Write-VerboseOutput("Calling Get-MapiConfigGCSetting via local session")
            $mapiGCMode = Get-MapiConfigGCSetting -ConfigPath $MapiConfig    
        }
        
    }
    catch
    {
        Invoke-CatchActions
    }

    Write-VerboseOutput("Returning GC Mode: {0}" -f $mapiGCMode)
    return $mapiGCMode
}

Function Get-ExchangeUpdates {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name,
[Parameter(Mandatory=$true)][HealthChecker.ExchangeVersion]$ExchangeVersion
)
    Write-VerboseOutput("Calling: Get-ExchangeUpdates")
    Write-VerboseOutput("Passed: " + $Machine_Name)
    Write-VerboseOutput("Passed: {0}" -f $ExchangeVersion.ToString())
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Machine_Name)
    $RegLocation = $null 
    if([HealthChecker.ExchangeVersion]::Exchange2013 -eq $ExchangeVersion)
    {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2013"
    }
    else 
    {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2016"
    }
    $RegKey= $Reg.OpenSubKey($RegLocation)
    if($RegKey -ne $null)
    {
        $IU = $RegKey.GetSubKeyNames()
        if($IU -ne $null)
        {
            Write-VerboseOutput("Detected fixes installed on the server")
            $fixes = @()
            foreach($key in $IU)
            {
                $IUKey = $Reg.OpenSubKey($RegLocation + "\" + $key)
                $IUName = $IUKey.GetValue("PackageName")
                Write-VerboseOutput("Found: " + $IUName)
                $fixes += $IUName
            }
            return $fixes
        }
    }
    return $null
}

Function Get-ServerRole {
param(
[Parameter(Mandatory=$true)][object]$ExchangeServerObj
)
    Write-VerboseOutput("Calling: Get-ServerRole")
    $roles = $ExchangeServerObj.ServerRole.ToString()
    Write-VerboseOutput("Roll: " + $roles)
    #Need to change this to like because of Exchange 2010 with AIO with the hub role.
    if($roles -like "Mailbox, ClientAccess*")
    {
        return [HealthChecker.ServerRole]::MultiRole
    }
    elseif($roles -eq "Mailbox")
    {
        return [HealthChecker.ServerRole]::Mailbox
    }
    elseif($roles -eq "Edge")
    {
        return [HealthChecker.ServerRole]::Edge
    }
    elseif($roles -like "*ClientAccess*")
    {
        return [HealthChecker.ServerRole]::ClientAccess
    }
    else
    {
        return [HealthChecker.ServerRole]::None
    }
}

Function Get-ExSetupDetails {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-ExSetupDetails")
    $exSetupDetails = [string]::Empty
    Function Get-ExSetupDetailsScriptBlock {
        Get-Command ExSetup | ForEach-Object{$_.FileVersionInfo}
    }
    if($Machine_Name -ne $env:COMPUTERNAME)
    {
        Write-VerboseOutput("Getting ExSetup remotely")
        try 
        {
            $exSetupDetails = Invoke-Command -ComputerName $Machine_Name -ScriptBlock ${Function:Get-ExSetupDetailsScriptBlock} -ErrorAction Stop
        }
        catch 
        {
            Write-VerboseOutput("Failed to get ExSetupDetails from server {0}" -f $Machine_Name)
            Invoke-CatchActions
        }
    }
    else 
    {
        $exSetupDetails = Get-ExSetupDetailsScriptBlock 
    }
    return $exSetupDetails
}

Function Build-ExchangeInformationObject {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
)
    $Machine_Name = $HealthExSvrObj.ServerName
    $OSVersionName = $HealthExSvrObj.OSVersion.OSVersion
    Write-VerboseOutput("Calling: Build-ExchangeInformationObject")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.ExchangeInformationObject]$exchInfoObject = New-Object -TypeName HealthChecker.ExchangeInformationObject
    $exchInfoObject.ExchangeServerObject = (Get-ExchangeServer -Identity $Machine_Name)
    $exchInfoObject.ExchangeVersion = (Get-ExchangeVersion -AdminDisplayVersion $exchInfoObject.ExchangeServerObject.AdminDisplayVersion) 
    $exchInfoObject.ExServerRole = (Get-ServerRole -ExchangeServerObj $exchInfoObject.ExchangeServerObject)
    $exchInfoObject.ExchangeSetup = (Get-ExSetupDetails -Machine_Name $Machine_Name) 

    #Exchange 2013 and 2016 things to check 
    if($exchInfoObject.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013) 
    {
        Write-VerboseOutput("Exchange 2013 or greater detected")
        $HealthExSvrObj.NetVersionInfo = Build-NetFrameWorkVersionObject -Machine_Name $Machine_Name -OSVersionName $OSVersionName
        $versionObject =  $HealthExSvrObj.NetVersionInfo 
        [HealthChecker.ExchangeInformationTempObject]$tempObject = Get-ExchangeBuildInformation -AdminDisplayVersion $exchInfoObject.ExchangeServerObject.AdminDisplayVersion
        if($tempObject.Error -ne $true) 
        {
            Write-VerboseOutput("No error detected when getting temp information")
            $exchInfoObject.BuildReleaseDate = $tempObject.ReleaseDate
            $exchInfoObject.ExchangeBuildNumber = $tempObject.ExchangeBuildNumber
            $exchInfoObject.ExchangeFriendlyName = $tempObject.FriendlyName
            $exchInfoObject.InbetweenCUs = $tempObject.InbetweenCUs
            $exchInfoObject.SupportedExchangeBuild = $tempObject.SupportedCU
            $exchInfoObject.ExchangeBuildObject = $tempObject.ExchangeBuildObject 
            [HealthChecker.NetVersionCheckObject]$NetCheckObj = Check-DotNetFrameworkSupportedLevel -exBuildObj $exchInfoObject.ExchangeBuildObject -OSVersionName $OSVersionName -NetVersion $versionObject.NetVersion
            if($NetCheckObj.Error)
            {
                Write-Yellow "Warning: Unable to determine if .NET is supported"
            }
            else
            {
                $versionObject.SupportedVersion = $NetCheckObj.Supported
                $versionObject.DisplayWording = $NetCheckObj.DisplayWording
                $exchInfoObject.RecommendedNetVersion = $NetCheckObj.RecommendedNetVersion

            }
            
        }
        else
        {
            Write-Yellow "Warning: Couldn't get accurate information on server: $Machine_Name"
        }

        
        $exchInfoObject.MapiHttpEnabled = (Get-OrganizationConfig).MapiHttpEnabled
        if($exchInfoObject.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -and $exchInfoObject.MapiHttpEnabled)
        {
            $exchInfoObject.MapiFEAppGCEnabled = Get-MapiFEAppPoolGCMode -Machine_Name $Machine_Name
        }

        $exchInfoObject.ExchangeAppPools = Get-ExchangeAppPoolsInformation -Machine_Name $Machine_Name

        $exchInfoObject.KBsInstalled = Get-ExchangeUpdates -Machine_Name $Machine_Name -ExchangeVersion $exchInfoObject.ExchangeVersion
    }
    elseif($exchInfoObject.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        Write-VerboseOutput("Exchange 2010 detected")
        $exchInfoObject.ExchangeFriendlyName = "Exchange 2010"
        $exchInfoObject.ExchangeBuildNumber = $exchInfoObject.ExchangeServerObject.AdminDisplayVersion
    }
    else
    {
        Write-Red "Error: Unknown version of Exchange detected for server: $Machine_Name"
    }

    if($exchInfoObject.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -and $exchInfoObject.ExServerRole -eq [HealthChecker.ServerRole]::ClientAccess)
    {
        Write-VerboseOutput("Exchange 2013 CAS only detected. Not going to run Test-ServiceHealth against this server.")
    }
    else 
    {
        Write-VerboseOutput("Exchange 2013 CAS only not detected. Going to run Test-ServiceHealth against this server.")
        $exchInfoObject.ExchangeServicesNotRunning = Test-ServiceHealth -Server $Machine_Name | %{$_.ServicesNotRunning}
    }
	
    $HealthExSvrObj.ExchangeInformation = $exchInfoObject
    return $HealthExSvrObj

}


Function Build-HealthExchangeServerObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)

    Write-VerboseOutput("Calling: Build-HealthExchangeServerObject")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.HealthExchangeServerObject]$HealthExSvrObj = New-Object -TypeName HealthChecker.HealthExchangeServerObject 
    $HealthExSvrObj.ServerName = $Machine_Name 
    $HealthExSvrObj.HardwareInfo = Build-HardwareObject -Machine_Name $Machine_Name 
    $HealthExSvrObj.OSVersion = Build-OperatingSystemObject -Machine_Name $Machine_Name  
    $HealthExSvrObj = Build-ExchangeInformationObject -HealthExSvrObj $HealthExSvrObj
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        $HealthExSvrObj = Set-NetTLSDefaultVersions2010 -HealthExchangeServerObject $HealthExSvrObj
    }
    $HealthExSvrObj.HealthCheckerVersion = $healthCheckerVersion
    Write-VerboseOutput("Finished building health Exchange Server Object for server: " + $Machine_Name)
    return $HealthExSvrObj
}

Function Get-MailboxDatabaseAndMailboxStatistics {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-MailboxDatabaseAndMailboxStatistics")
    Write-VerboseOutput("Passed: " + $Machine_Name)

    $AllDBs = Get-MailboxDatabaseCopyStatus -server $Machine_Name -ErrorAction SilentlyContinue 
    $MountedDBs = $AllDBs | Where-Object{$_.ActiveCopy -eq $true}
    if($MountedDBs.Count -gt 0)
    {
        Write-Grey("`tActive Database:")
        foreach($db in $MountedDBs)
        {
            Write-Grey("`t`t" + $db.Name)
        }
        $MountedDBs.DatabaseName | ForEach-Object{Write-VerboseOutput("Calculating User Mailbox Total for Active Database: $_"); $TotalActiveUserMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited).Count}
        Write-Grey("`tTotal Active User Mailboxes on server: " + $TotalActiveUserMailboxCount)
        $MountedDBs.DatabaseName | ForEach-Object{Write-VerboseOutput("Calculating Public Mailbox Total for Active Database: $_"); $TotalActivePublicFolderMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited -PublicFolder).Count}
        Write-Grey("`tTotal Active Public Folder Mailboxes on server: " + $TotalActivePublicFolderMailboxCount)
        Write-Grey("`tTotal Active Mailboxes on server " + $Machine_Name + ": " + ($TotalActiveUserMailboxCount + $TotalActivePublicFolderMailboxCount).ToString())
    }
    else
    {
        Write-Grey("`tNo Active Mailbox Databases found on server " + $Machine_Name + ".")
    }
    
    $HealthyDbs = $AllDBs | Where-Object{$_.Status -match 'Healthy'}
    if($HealthyDbs.count -gt 0)
    {
        Write-Grey("`r`n`tPassive Databases:")
        foreach($db in $HealthyDbs)
        {
            Write-Grey("`t`t" + $db.Name)
        }
        $HealthyDbs.DatabaseName | ForEach-Object{Write-VerboseOutput("`tCalculating User Mailbox Total for Passive Healthy Databases: $_"); $TotalPassiveUserMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited).Count}
        Write-Grey("`tTotal Passive user Mailboxes on Server: " + $TotalPassiveUserMailboxCount)
        $HealthyDbs.DatabaseName | ForEach-Object{Write-VerboseOutput("`tCalculating Passive Mailbox Total for Passive Healthy Databases: $_"); $TotalPassivePublicFolderMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited -PublicFolder).Count}
        Write-Grey("`tTotal Passive Public Mailboxes on server: " + $TotalPassivePublicFolderMailboxCount)
        Write-Grey("`tTotal Passive Mailboxes on server: " + ($TotalPassiveUserMailboxCount + $TotalPassivePublicFolderMailboxCount).ToString()) 
    }
    else
    {
        Write-Grey("`tNo Passive Mailboxes found on server " + $Machine_Name + ".")
    }
}

#This function will return a true if the version level is the same or greater than the CheckVersionObject - keeping it simple so it can be done remotely as well 
Function Get-BuildLevelVersionCheck {
param(
[Parameter(Mandatory=$true)][object]$ActualVersionObject,
[Parameter(Mandatory=$true)][object]$CheckVersionObject,
[Parameter(Mandatory=$false)][bool]$DebugFunction = $false
)
Add-Type -TypeDefinition @"
public enum VersionDetection 
{
    Unknown,
    Lower,
    Equal,
    Greater
}
"@
    #unsure of how we do build numbers for all types of DLLs on the OS, but we are going to try to cover all bases here and it is up to the caller to make sure that we are passing the correct values to be checking 
    #FileMajorPart
    if($ActualVersionObject.FileMajorPart -lt $CheckVersionObject.FileMajorPart){$FileMajorPart = [VersionDetection]::Lower}
    elseif($ActualVersionObject.FileMajorPart -eq $CheckVersionObject.FileMajorPart){$FileMajorPart = [VersionDetection]::Equal}
    elseif($ActualVersionObject.FileMajorPart -gt $CheckVersionObject.FileMajorPart){$FileMajorPart = [VersionDetection]::Greater}
    else{$FileMajorPart =  [VersionDetection]::Unknown}

    if($ActualVersionObject.FileMinorPart -lt $CheckVersionObject.FileMinorPart){$FileMinorPart = [VersionDetection]::Lower}
    elseif($ActualVersionObject.FileMinorPart -eq $CheckVersionObject.FileMinorPart){$FileMinorPart = [VersionDetection]::Equal}
    elseif($ActualVersionObject.FileMinorPart -gt $CheckVersionObject.FileMinorPart){$FileMinorPart = [VersionDetection]::Greater}
    else{$FileMinorPart = [VersionDetection]::Unknown}

    if($ActualVersionObject.FileBuildPart -lt $CheckVersionObject.FileBuildPart){$FileBuildPart = [VersionDetection]::Lower}
    elseif($ActualVersionObject.FileBuildPart -eq $CheckVersionObject.FileBuildPart){$FileBuildPart = [VersionDetection]::Equal}
    elseif($ActualVersionObject.FileBuildPart -gt $CheckVersionObject.FileBuildPart){$FileBuildPart = [VersionDetection]::Greater}
    else{$FileBuildPart = [VersionDetection]::Unknown}

    
    if($ActualVersionObject.FilePrivatePart -lt $CheckVersionObject.FilePrivatePart){$FilePrivatePart = [VersionDetection]::Lower}
    elseif($ActualVersionObject.FilePrivatePart -eq $CheckVersionObject.FilePrivatePart){$FilePrivatePart = [VersionDetection]::Equal}
    elseif($ActualVersionObject.FilePrivatePart -gt $CheckVersionObject.FilePrivatePart){$FilePrivatePart = [VersionDetection]::Greater}
    else{$FilePrivatePart = [VersionDetection]::Unknown}

    if($DebugFunction)
    {
        Write-VerboseOutput("ActualVersionObject - FileMajorPart: {0} FileMinorPart: {1} FileBuildPart: {2} FilePrivatePart: {3}" -f $ActualVersionObject.FileMajorPart, 
        $ActualVersionObject.FileMinorPart, $ActualVersionObject.FileBuildPart, $ActualVersionObject.FilePrivatePart)
        Write-VerboseOutput("CheckVersionObject - FileMajorPart: {0} FileMinorPart: {1} FileBuildPart: {2} FilePrivatePart: {3}" -f $CheckVersionObject.FileMajorPart,
        $CheckVersionObject.FileMinorPart, $CheckVersionObject.FileBuildPart, $CheckVersionObject.FilePrivatePart)
        Write-VerboseOutput("Switch Detection - FileMajorPart: {0} FileMinorPart: {1} FileBuildPart: {2} FilePrivatePart: {3}" -f $FileMajorPart, $FileMinorPart, $FileBuildPart, $FilePrivatePart)
    }

    if($FileMajorPart -eq [VersionDetection]::Greater){return $true}
    if($FileMinorPart -eq [VersionDetection]::Greater){return $true}
    if($FileBuildPart -eq [VersionDetection]::Greater){return $true}
    if($FilePrivatePart -ge [VersionDetection]::Equal){return $true}

    return $false
}

Function Get-CASLoadBalancingReport {

    Write-VerboseOutput("Calling: Get-CASLoadBalancingReport")
    Write-Yellow("Note: CAS Load Balancing Report has known issues with attempting to get counter from servers. If you see errors regarding 'Get-Counter path not valid', please ignore for the time being. This is going to be addressed in later versions")
    #Connection and requests per server and client type values
    $CASConnectionStats = @{}
    $TotalCASConnectionCount = 0
    $AutoDStats = @{}
    $TotalAutoDRequests = 0
    $EWSStats = @{}
    $TotalEWSRequests = 0
    $MapiHttpStats = @{}
    $TotalMapiHttpRequests = 0
    $EASStats = @{}
    $TotalEASRequests = 0
    $OWAStats = @{}
    $TotalOWARequests = 0
    $RpcHttpStats = @{}
    $TotalRpcHttpRequests = 0
    $CASServers = @()

    if($CasServerList -ne $null)
    {
		Write-Grey("Custom CAS server list is being used.  Only servers specified after the -CasServerList parameter will be used in the report.")
        foreach($cas in $CasServerList)
        {
            $CASServers += (Get-ExchangeServer $cas)
        }
    }
	elseif($SiteName -ne [string]::Empty)
	{
		Write-Grey("Site filtering ON.  Only Exchange 2013/2016 CAS servers in " + $SiteName + " will be used in the report.")
		$CASServers = Get-ExchangeServer | ?{($_.IsClientAccessServer -eq $true) -and ($_.AdminDisplayVersion -Match "^Version 15") -and ($_.Site.Name -eq $SiteName)}
	}
    else
    {
		Write-Grey("Site filtering OFF.  All Exchange 2013/2016 CAS servers will be used in the report.")
        $CASServers = Get-ExchangeServer | ?{($_.IsClientAccessServer -eq $true) -and ($_.AdminDisplayVersion -Match "^Version 15")}
    }

	if($CASServers.Count -eq 0)
	{
		Write-Red("Error: No CAS servers found using the specified search criteria.")
		Exit
	}

    #Pull connection and request stats from perfmon for each CAS
    foreach($cas in $CASServers)
    {
        #Total connections
        $TotalConnectionCount = (Get-Counter ("\\" + $cas.Name + "\Web Service(Default Web Site)\Current Connections")).CounterSamples.CookedValue
        $CASConnectionStats.Add($cas.Name, $TotalConnectionCount)
        $TotalCASConnectionCount += $TotalConnectionCount

        #AutoD requests
        $AutoDRequestCount = (Get-Counter ("\\" + $cas.Name + "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Autodiscover)\Requests Executing")).CounterSamples.CookedValue
        $AutoDStats.Add($cas.Name, $AutoDRequestCount)
        $TotalAutoDRequests += $AutoDRequestCount

        #EWS requests
        $EWSRequestCount = (Get-Counter ("\\" + $cas.Name + "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_EWS)\Requests Executing")).CounterSamples.CookedValue
        $EWSStats.Add($cas.Name, $EWSRequestCount)
        $TotalEWSRequests += $EWSRequestCount

        #MapiHttp requests
        $MapiHttpRequestCount = (Get-Counter ("\\" + $cas.Name + "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_mapi)\Requests Executing")).CounterSamples.CookedValue
        $MapiHttpStats.Add($cas.Name, $MapiHttpRequestCount)
        $TotalMapiHttpRequests += $MapiHttpRequestCount

        #EAS requests
        $EASRequestCount = (Get-Counter ("\\" + $cas.Name + "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Microsoft-Server-ActiveSync)\Requests Executing")).CounterSamples.CookedValue
        $EASStats.Add($cas.Name, $EASRequestCount)
        $TotalEASRequests += $EASRequestCount

        #OWA requests
        $OWARequestCount = (Get-Counter ("\\" + $cas.Name + "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_owa)\Requests Executing")).CounterSamples.CookedValue
        $OWAStats.Add($cas.Name, $OWARequestCount)
        $TotalOWARequests += $OWARequestCount

        #RPCHTTP requests
        $RpcHttpRequestCount = (Get-Counter ("\\" + $cas.Name + "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Rpc)\Requests Executing")).CounterSamples.CookedValue
        $RpcHttpStats.Add($cas.Name, $RpcHttpRequestCount)
        $TotalRpcHttpRequests += $RpcHttpRequestCount
    }

    #Report the results for connection count
    Write-Grey("")
    Write-Grey("Connection Load Distribution Per Server")
    Write-Grey("Total Connections: " + $TotalCASConnectionCount)
    #Calculate percentage of connection load
    $CASConnectionStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
    Write-Grey($_.Key + ": " + $_.Value + " Connections = " + [math]::Round((([int]$_.Value/$TotalCASConnectionCount)*100)) + "% Distribution")
    }

    #Same for each client type.  These are request numbers not connection numbers.
    #AutoD
    if($TotalAutoDRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current AutoDiscover Requests Per Server")
        Write-Grey("Total Requests: " + $TotalAutoDRequests)
        $AutoDStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalAutoDRequests)*100)) + "% Distribution")
        }
    }

    #EWS
    if($TotalEWSRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current EWS Requests Per Server")
        Write-Grey("Total Requests: " + $TotalEWSRequests)
        $EWSStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalEWSRequests)*100)) + "% Distribution")
        }
    }

    #MapiHttp
    if($TotalMapiHttpRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current MapiHttp Requests Per Server")
        Write-Grey("Total Requests: " + $TotalMapiHttpRequests)
        $MapiHttpStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalMapiHttpRequests)*100)) + "% Distribution")
        }
    }

    #EAS
    if($TotalEASRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current EAS Requests Per Server")
        Write-Grey("Total Requests: " + $TotalEASRequests)
        $EASStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalEASRequests)*100)) + "% Distribution")
        }
    }

    #OWA
    if($TotalOWARequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current OWA Requests Per Server")
        Write-Grey("Total Requests: " + $TotalOWARequests)
        $OWAStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalOWARequests)*100)) + "% Distribution")
        }
    }

    #RpcHttp
    if($TotalRpcHttpRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current RpcHttp Requests Per Server")
        Write-Grey("Total Requests: " + $TotalRpcHttpRequests)
        $RpcHttpStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalRpcHttpRequests)*100)) + "% Distribution")
        }
    }

    Write-Grey("")

}

Function Verify-Pagefile25PercentOfTotalMemory {
param(
[Parameter(Mandatory=$true)][HealthChecker.PageFileObject]$PageFileObj,
[Parameter(Mandatory=$true)][HealthChecker.HardwareObject]$HardwareObj
)
    Write-VerboseOutput("Calling: Verify-Pagefile25PercentOfTotalMemory")
    Write-VerboseOutput("Passed: Total Memory: {0}" -f ($totalMemory = $HardwareObj.TotalMemory))
    Write-VerboseOutput("Passed: Max page file size: {0}" -f ($pageFileSize = $PageFileObj.MaxPageSize))
    $returnString = "Good"
    $pageFileSizeMB = [Math]::Truncate((($totalMemoryMB = ($totalMemory / 1MB)) / 4))
    if($pageFileSize -ne $pageFileSizeMB)
    {
        $returnString = "Page File size is set to {0} MB which does not equal 25% of the Total System Memory which is {1} MB. This is set incorrectly." -f $pageFileSizeMB, [Math]::Truncate($totalMemoryMB)
    }

    return $returnString
}

Function Verify-PagefileEqualMemoryPlus10{
param(
[Parameter(Mandatory=$true)][HealthChecker.PageFileObject]$page_obj,
[Parameter(Mandatory=$true)][HealthChecker.HardwareObject]$hardware_obj
)
    Write-VerboseOutput("Calling: Verify-PagefileEqualMemoryPlus10")
    Write-VerboseOutput("Passed: total memory: " + $hardware_obj.TotalMemory)
    Write-VerboseOutput("Passed: max page file size: " + $page_obj.MaxPageSize)
    $sReturnString = "Good"
    $iMemory = [System.Math]::Round(($hardware_obj.TotalMemory / 1048576) + 10)
    Write-VerboseOutput("Server Memory Plus 10 MB: " + $iMemory) 
    
    if($page_obj.MaxPageSize -lt $iMemory)
    {
        $sReturnString = "Page file is set to (" + $page_obj.MaxPageSize + ") which appears to be less than the Total System Memory plus 10 MB which is (" + $iMemory + ") this appears to be set incorrectly."
    }
    elseif($page_obj.MaxPageSize -gt $iMemory)
    {
        $sReturnString = "Page file is set to (" + $page_obj.MaxPageSize + ") which appears to be More than the Total System Memory plus 10 MB which is (" + $iMemory + ") this appears to be set incorrectly." 
    }

    return $sReturnString

}

Function Get-LmCompatibilityLevel {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    #LSA Reg Location "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    #Check if valuename LmCompatibilityLevel exists, if not, then value is 3
    $RegValue = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Control\Lsa" -GetValue "LmCompatibilityLevel"
    If ($RegValue)
    {
        Return $RegValue
    }
    Else
    {
        Return 3
    }

}

Function Build-LmCompatibilityLevel {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)

    Write-VerboseOutput("Calling: Build-LmCompatibilityLevel")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.ServerLmCompatibilityLevel]$ServerLmCompatObject = New-Object -TypeName HealthChecker.ServerLmCompatibilityLevel
    
    $ServerLmCompatObject.LmCompatibilityLevelRef = "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960646(v=technet.10)"
    $ServerLmCompatObject.LmCompatibilityLevel    = Get-LmCompatibilityLevel $Machine_Name
    Switch ($ServerLmCompatObject.LmCompatibilityLevel)
    {
        0 {$ServerLmCompatObject.LmCompatibilityLevelDescription = "Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        1 {$ServerLmCompatObject.LmCompatibilityLevelDescription = "Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        2 {$ServerLmCompatObject.LmCompatibilityLevelDescription = "Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication." }
        3 {$ServerLmCompatObject.LmCompatibilityLevelDescription = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        4 {$ServerLmCompatObject.LmCompatibilityLevelDescription = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2." }
        5 {$ServerLmCompatObject.LmCompatibilityLevelDescription = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2." }
    }

    Return $ServerLmCompatObject
}

Function Display-MSExchangeVulnerabilities {
param(
[Parameter(Mandatory=$true)][object]$HealthExSvrObj
)
    Write-VerboseOutput("Calling: Display-MSExchangeVulnerabilities")
    Write-VerboseOutput("For Server: {0}" -f ($Machine_Name = $HealthExSvrObj.ServerName))

    Function Test-VulnerabilitiesByBuildNumbersAndDisplay{
    param(
    [Parameter(Mandatory=$true)][double]$ExchangeBuildRevision,
    [Parameter(Mandatory=$true)][double]$SecurityFixedBuild,
    [Parameter(Mandatory=$true)][string]$CVEName
    )
        Write-VerboseOutput("Testing CVE: {0} | Security Fix Build: {1}" -f $CVEName, $SecurityFixedBuild)
        if($ExchangeBuildRevision -lt $SecurityFixedBuild)
        {
            Write-Red("System vulnerable to {0}.`r`n`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{1} for more information." -f $CVEName, $CVEName)
            $Script:AllVulnerabilitiesPassed = $false 
        }
        else 
        {
            Write-VerboseOutput("System NOT vulnerable to {0}. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{1}" -f $CVEName, $CVEName)
        }
    }
    
    $Script:AllVulnerabilitiesPassed = $true 
    Write-Grey("`r`nVulnerability Check:`r`n")

    #Check for CVE-2018-8581 vulnerability
    #LSA Reg Location "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    #Check if valuename DisableLoopbackCheck exists
    $RegValue = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Control\Lsa" -GetValue "DisableLoopbackCheck"
    If ($RegValue)
    {
        Write-Red("System vulnerable to CVE-2018-8581.  See: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8581 for more information.")  
        $Script:AllVulnerabilitiesPassed = $false 
    }
    Else
    {
        Write-VerboseOutput("System NOT vulnerable to CVE-2018-8581.")
    }

    #Check for CVE-2010-3190 vulnerability
    #If installed Exchange server release is prior to October 2018
    #KB2565063 should be installed to fix vulnerability
    
    $KB2565063_RegValue = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1D8E6291-B0D5-35EC-8441-6616F567A0F7}" -GetValue "DisplayVersion" 
    $KB2565063_RegValueInstallDate = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1D8E6291-B0D5-35EC-8441-6616F567A0F7}" -GetValue "InstallDate"

    If ($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        If ([System.Convert]::ToDateTime([DateTime]$HealthExSvrObj.ExchangeInformation.BuildReleaseDate) -lt ([System.Convert]::ToDateTime([DateTime]"1 Oct 2018")))
        {
            Write-VerboseOutput("Your Exchange server build is prior to October 2018")

            If (($KB2565063_RegValue -ne $null) -and ($KB2565063_RegValue -match "10.0.40219"))
            {

                $E15_RegValueInstallData = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{CD981244-E9B8-405A-9026-6AEB9DCEF1F1}" -GetValue "InstallDate"

                If ($E15_RegValueInstallData -ne $null -and $E15_RegValueInstallData -ne [string]::Empty)
                {
                    If ((([DateTime]::ParseExact($KB2565063_RegValueInstallDate,”yyyyMMdd”,$null))) -lt (([DateTime]::ParseExact($E15_RegValueInstallData,”yyyyMMdd”,$null))))
                    {
                        Write-Red("Vulnerable to CVE-2010-3190.")
                        Write-Red("See: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/MS11-025-required-on-Exchange-Server-versions-released-before/ba-p/608353 for more information.")
                    }
                    Else
                    {
                        Write-VerboseOutput("System NOT vulnerable to CVE-2010-3190.")
                    }
                }
                Else
                {
                    Write-Yellow("Unable to determine Exchange server install date!")
                    Write-Yellow("Potentially vulnerable to CVE-2010-3190.")
                    Write-Yellow("See: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/MS11-025-required-on-Exchange-Server-versions-released-before/ba-p/608353 for more information.")
                }
            }
            Else
            {
                Write-Red("Vulnerable to CVE-2010-3190.")
                Write-Red("See: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/MS11-025-required-on-Exchange-Server-versions-released-before/ba-p/608353 for more information.")
            }
        }
        Else
        {
            Write-VerboseOutput("System NOT vulnerable to CVE-2010-3190.")
        }
    }
    Else
    {
        Write-VerboseOutput("`nYour Exchange server version is $($HealthExSvrObj.ExchangeInformation.ExchangeFriendlyName):")
        
        If (($KB2565063_RegValue -ne $null) -and ($KB2565063_RegValue -match "10.0.40219"))
        {

            $E2010_RegValueInstallDate = Invoke-RegistryHandler -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{4934D1EA-BE46-48B1-8847-F1AF20E892C1}" -GetValue "InstallDate"

            If ($E2010_RegValueInstallDate -ne $null -and $E2010_RegValueInstallDate -ne [string]::Empty)
            {
                If ((([DateTime]::ParseExact($KB2565063_RegValueInstallDate,”yyyyMMdd”,$null))) -lt (([DateTime]::ParseExact($E2010_RegValueInstallDate,”yyyyMMdd”,$null))))
                {
                    Write-Red("Potentially Vulnerable to CVE-2010-3190.")
                    Write-Red("See: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/MS11-025-required-on-Exchange-Server-versions-released-before/ba-p/608353 for more information.")
                }
                Else
                {
                    Write-VerboseOutput("System NOT vulnerable to CVE-2010-3190.")
                }
            }
            Else
            {
                Write-Red("Unable to determine Exchange server install date!")
                Write-Red("Potentially vulnerable to CVE-2010-3190.")
            }
        }
        Else
        {
            Write-Red("`nPotentially vulnerable to CVE-2010-3190.")
            Write-Red("You should check if your build is prior October 2018 and if so, install KB2565063")
            Write-Red("See: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/MS11-025-required-on-Exchange-Server-versions-released-before/ba-p/608353 for more information.")
        }
    }

    #Check for different vulnerabilities
    #We run checks based on build revision only for Exchange 2013/2016/2019
    #We check only for year 2018+ vulnerabilities
    #https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-194/Microsoft-Exchange-Server.html 

    [double]$buildRevision = [System.Convert]::ToDouble(("{0}.{1}" -f $HealthExSvrObj.ExchangeInformation.ExchangeSetup.FileBuildPart, $HealthExSvrObj.ExchangeInformation.ExchangeSetup.FilePrivatePart), [System.Globalization.CultureInfo]::InvariantCulture)
    Write-VerboseOutput("Exchange Build Revision: {0}" -f $buildRevision) 
    Write-VerboseOutput("Exchange CU: {0}" -f ($exchangeCU = $HealthExSvrObj.ExchangeInformation.ExchangeBuildObject.CU))

    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        #CVE-2018-8302 affects E2010 but we cannot check for them
        #CVE-2018-8154 affects E2010 but we cannot check for them
        #CVE-2018-8151 affects E2010 but we cannot check for them
        #CVE-2018-0940 affects E2010 but we cannot check for them
        #CVE-2018-16793 affects E2010 but we cannot check for them
        #CVE-2018-0924 affects E2010 but we cannot check for them
	    #CVE-2019-0686 affects E2010 but we cannot check for them
        #CVE-2019-0724 affects E2010 but we cannot check for them
        #CVE-2019-0817 affects E2010 but we cannot check for them
        #could do get the build number of exsetup, but not really needed with Exchange 2010 as it is going out of support soon. 
        Write-Yellow("`nWe cannot check for more vulnerabilities for Exchange 2010.")
        Write-Yellow("You should make sure that your Exchange 2010 Servers are up to date with all security patches.")
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        #Need to know which CU we are on, as that would be the best to break up the security patches 
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU18)
        {
            #CVE-2018-0924
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1347.5 -CVEName "CVE-2018-0924" 
            #CVE-2018-0940
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1347.5 -CVEName "CVE-2018-0940" 
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU19)
        {
            #to avoid duplicates only do these ones if we are equal to the current CU as they would have been caught on the previous CU if we are at a less CU
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU19)
            {
                #CVE-2018-0924
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1365.3 -CVEName "CVE-2018-0924" 
                #CVE-2018-0940
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1365.3 -CVEName "CVE-2018-0940" 
            }
            #CVE-2018-8151 
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1365.7 -CVEName "CVE-2018-8151"
            #CVE-2018-8154
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1365.7 -CVEName "CVE-2018-8154"
            #CVE-2018-8159
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1365.7 -CVEName "CVE-2018-8159"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU20)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU20)
            {
                #CVE-2018-8151
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1367.6 -CVEName "CVE-2018-8151"
                #CVE-2018-8154
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1367.6 -CVEName "CVE-2018-8154"
                #CVE-2018-8159 
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1367.6 -CVEName "CVE-2018-8159"
            }
            #CVE-2018-8302
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1367.9 -CVEName "CVE-2018-8302"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU21)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU21)
            {
                #CVE-2018-8302
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1395.7 -CVEName "CVE-2018-8302"
            }
            #CVE-2018-8265
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1395.8 -CVEName "CVE-2018-8265"
            #CVE-2018-8448
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1395.8 -CVEName "CVE-2018-8448"
            #CVE-2019-0586
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1395.10 -CVEName "CVE-2019-0586"
            #CVE-2019-0588
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1395.10 -CVEName "CVE-2019-0588"
        }
	    if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU22)
	    {
            #Do to supportability changes, we don't have security updates for both CU22 and CU21 so there is no need to check for this version
	        #CVE-2019-0686
	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1473.3 -CVEName "CVE-2019-0686"
	        #CVE-2019-0724
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1473.3 -CVEName "CVE-2019-0724"
            #CVE-2019-0817
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1473.4 -CVEName "CVE-2019-0817"
            #CVE-2019-0858
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1473.4 -CVEName "CVE-2019-0858"
	    }
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2016)
    {
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU7)
        {
            #CVE-2018-0924
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1261.39 -CVEName "CVE-2018-0924"
            #CVE-2018-0940
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1261.39 -CVEName "CVE-2018-0940"
            #CVE-2018-0941
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1261.39 -CVEName "CVE-2018-0941"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU8)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU8)
            {
                #CVE-2018-0924
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.4 -CVEName "CVE-2018-0924"
                #CVE-2018-0940
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.4 -CVEName "CVE-2018-0940"
                #CVE-2018-0941
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.4 -CVEName "CVE-2018-0941"

            }
            #CVE-2018-8151
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.7 -CVEName "CVE-2018-8151"
            #CVE-2018-8152
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.7 -CVEName "CVE-2018-8152"
            #CVE-2018-8153
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.7 -CVEName "CVE-2018-8153"
            #CVE-2018-8154
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.7 -CVEName "CVE-2018-8154"
            #CVE-2018-8159
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.7 -CVEName "CVE-2018-8159"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU9)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU9)
            {
                #CVE-2018-8151
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.8 -CVEName "CVE-2018-8151"
                #CVE-2018-8152
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.8 -CVEName "CVE-2018-8152"
                #CVE-2018-8153
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.8 -CVEName "CVE-2018-8153"
                #CVE-2018-8154
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.8 -CVEName "CVE-2018-8154"
                #CVE-2018-8159
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.8 -CVEName "CVE-2018-8159"
            }
            #CVE-2018-8374
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.9 -CVEName "CVE-2018-8374"
            #CVE-2018-8302
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.9 -CVEName "CVE-2018-8302"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU10)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU10)
            {
                #CVE-2018-8374
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.6 -CVEName "CVE-2018-8374"
                #CVE-2018-8302
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.6 -CVEName "CVE-2018-8302"
            }
            #CVE-2018-8265
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.8 -CVEName "CVE-2018-8265"
            #CVE-2018-8448
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.8 -CVEName "CVE-2018-8448"
            #CVE-2018-8604
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.8 -CVEName "CVE-2018-8604"
            #CVE-2019-0586
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.10 -CVEName "CVE-2019-0586"
            #CVE-2019-0588
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.10 -CVEName "CVE-2019-0588"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU11)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU11)
            {
                #CVE-2018-8604
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.11 -CVEName "CVE-2018-8604"
                #CVE-2019-0586
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.13 -CVEName "CVE-2019-0586"
                #CVE-2019-0588
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.13 -CVEName "CVE-2019-0588"
                #CVE-2019-0817
        	    Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.16 -CVEName "CVE-2019-0817"
	            #CVE-2018-0858
    	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.16 -CVEName "CVE-2019-0858"                
            }
        }
	if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU12)
	{
	    if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU12)
	    {
	        #CVE-2019-0817
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.6 -CVEName "CVE-2019-0817"
            #CVE-2018-0858
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.6 -CVEName "CVE-2019-0858"
	    }
	    #CVE-2019-0686
	    Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.5 -CVEName "CVE-2019-0686"
	    #CVE-2019-0724
	    Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.5 -CVEName "CVE-2019-0724"
	}
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2019)
    {
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::RTM)
        {
            #CVE-2019-0586
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 221.14 -CVEName "CVE-2019-0586"
            #CVE-2019-0588
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 221.14 -CVEName "CVE-2019-0588"
            #CVE-2019-0817
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 221.16 -CVEName "CVE-2019-0817"
            #CVE-2018-0858
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 221.16 -CVEName "CVE-2019-0858"
        }
	if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU1)
	{
	    if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU1)
	    {
            #CVE-2019-0817
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.7 -CVEName "CVE-2019-0817"
            #CVE-2018-0858
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.7 -CVEName "CVE-2019-0858"
	    }
	    #CVE-2019-0686
	    Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.6 -CVEName "CVE-2019-0686"
	    #CVE-2019-0724
	    Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.6 -CVEName "CVE-2019-0724"
	}
    }
    else 
    {
        Write-Red("`nUnknown Exchange Server Version. Unable to check for vulnerabilities.")     
    }
    if($Script:AllVulnerabilitiesPassed)
    {
        Write-Grey("All known security issues in this version of the script passed.")
    }
}

Function Display-KBHotfixCheckFailSafe {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
)

    Write-Grey("`r`nHotfix Check:")
    $2008HotfixList = $null
  $2008R2HotfixList = @("KB3004383")
  $2012HotfixList = $null
  $2012R2HotfixList = @("KB3041832")
  $2016HotfixList = @("KB3206632")
  
  
  Function Check-Hotfix 
  {
      param(
      [Parameter(Mandatory=$true)][Array]$Hotfixes,
      [Parameter(Mandatory=$true)][Array]$CheckListHotFixes
      )
      $hotfixesneeded = $false
      foreach($check in $CheckListHotFixes)
      {
          if($Hotfixes.Contains($check) -eq $false)
          {
              $hotfixesneeded = $true
              Write-Yellow("Warning: Hotfix " + $check + " is recommended for this OS and was not detected.  Please consider installing it to prevent performance issues. --- Note that this KB update may be superseded by another KB update. To verify, check the file versions in the KB against your machine. This is a temporary workaround till the script gets properly updated for all KB checks.")
          }
      }
      if($hotfixesneeded -eq $false)
      {
          Write-Grey("Hotfix check complete.  No action required.")
      }
  }

  switch($HealthExSvrObj.OSVersion.OSVersion) 
  {
      ([HealthChecker.OSVersionName]::Windows2008)
      {
          if($2008HotfixList -ne $null) {Check-Hotfix -Hotfixes $HealthExSvrObj.OSVersion.HotFixes.Hotfixid -CheckListHotFixes $2008HotfixList}
      }
      ([HealthChecker.OSVersionName]::Windows2008R2)
      {
          if($2008R2HotfixList -ne $null) {Check-Hotfix -Hotfixes $HealthExSvrObj.OSVersion.HotFixes.Hotfixid -CheckListHotFixes $2008R2HotfixList}
      }
      ([HealthChecker.OSVersionName]::Windows2012)
      {
          if($2012HotfixList -ne $null) {Check-Hotfix -Hotfixes $HealthExSvrObj.OSVersion.HotFixes.Hotfixid -CheckListHotFixes $2012HotfixList}
      }
      ([HealthChecker.OSVersionName]::Windows2012R2)
      {
          if($2012R2HotfixList -ne $null) {Check-Hotfix -Hotfixes $HealthExSvrObj.OSVersion.HotFixes.Hotfixid -CheckListHotFixes $2012R2HotfixList}
      }
      ([HealthChecker.OSVersionName]::Windows2016)
      {
          if($2016HotfixList -ne $null) {Check-Hotfix -Hotfixes $HealthExSvrObj.OSVersion.HotFixes.Hotfixid -CheckListHotFixes $2016HotfixList}
      }

      default {}
  }
}

Function Get-BuildVersionObjectFromString {
param(
[Parameter(Mandatory=$true)][string]$BuildString 
)
    $aBuild = $BuildString.Split(".")
    if($aBuild.Count -ge 4)
    {
        $obj = New-Object PSCustomObject 
        $obj | Add-Member -MemberType NoteProperty -Name FileMajorPart -Value ([System.Convert]::ToInt32($aBuild[0]))
        $obj | Add-Member -MemberType NoteProperty -Name FileMinorPart -Value ([System.Convert]::ToInt32($aBuild[1]))
        $obj | Add-Member -MemberType NoteProperty -Name FileBuildPart -Value ([System.Convert]::ToInt32($aBuild[2]))
        $obj | Add-Member -MemberType NoteProperty -Name FilePrivatePart -Value ([System.Convert]::ToInt32($aBuild[3]))
        return $obj 
    }
    else 
    {
        Return "Error"    
    }
}

#Addressed issue 69
Function Display-KBHotFixCompareIssues{
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
)
    Write-VerboseOutput("Calling: Display-KBHotFixCompareIssues")
    Write-VerboseOutput("For Server: {0}" -f $HealthExSvrObj.ServerName)

    #$HotFixInfo = $HealthExSvrObj.OSVersion.HotFixes.Hotfixid
    $HotFixInfo = @() 
    foreach($Hotfix in $HealthExSvrObj.OSVersion.HotFixes)
    {
        $HotFixInfo += $Hotfix.HotfixId 
    }

    $serverOS = $HealthExSvrObj.OSVersion.OSVersion
    if($serverOS -eq ([HealthChecker.OSVersionName]::Windows2008))
    {
        Write-VerboseOutput("Windows 2008 detected")
        $KBHashTable = @{"KB4295656"="KB4345397"}
    }
    elseif($serverOS -eq ([HealthChecker.OSVersionName]::Windows2008R2))
    {
        Write-VerboseOutput("Windows 2008 R2 detected")
        $KBHashTable = @{"KB4338823"="KB4345459";"KB4338818"="KB4338821"}
    }
    elseif($serverOS -eq ([HealthChecker.OSVersionName]::Windows2012))
    {
        Write-VerboseOutput("Windows 2012 detected")
        $KBHashTable = @{"KB4338820"="KB4345425";"KB4338830"="KB4338816"}
    }
    elseif($serverOS -eq ([HealthChecker.OSVersionName]::Windows2012R2))
    {
        Write-VerboseOutput("Windows 2012 R2 detected")
        $KBHashTable = @{"KB4338824"="KB4345424";"KB4338815"="KB4338831"}
    }
    elseif($serverOS -eq ([HealthChecker.OSVersionName]::Windows2016))
    {
        Write-VerboseOutput("Windows 2016 detected")
        $KBHashTable = @{"KB4338814"="KB4345418"}
    }

    if($HotFixInfo -ne $null)
    {
        if($KBHashTable -ne $null)
        {
            foreach($key in $KBHashTable.Keys)
            {
                foreach($problemKB in $HotFixInfo)
                {
                    if($problemKB -eq $key)
                    {
                        Write-VerboseOutput("Found Impacted {0}" -f $key)
                        $foundFixKB = $false 
                        foreach($fixKB in $HotFixInfo)
                        {
                            if($fixKB -eq ($KBHashTable[$key]))
                            {
                                Write-VerboseOutput("Found {0} that fixes the issue" -f ($KBHashTable[$key]))
                                $foundFixKB = $true 
                            }

                        }
                        if(-not($foundFixKB))
                        {
                            Write-Break
                            Write-Break
                            Write-Red("July Update detected: Error --- Problem {0} detected without the fix {1}. This can cause odd issues to occur on the system. See https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Issue-with-July-Updates-for-Windows-on-an-Exchange-Server/ba-p/608057" -f $key, ($KBHashTable[$key]))
                        }
                    }
                }
            }
        }
        else
        {
            Write-VerboseOutput("KBHashTable was null. July Update issue not checked.")
        }
    }
    else 
    {
        Write-VerboseOutput("No hotfixes were detected on the server")    
    }

    
}

Function Display-KBHotfixCheck {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
)
    Write-VerboseOutput("Calling: Display-KBHotfixCheck")
    Write-VerboseOutput("For Server: {0}" -f $HealthExSvrObj.ServerName)
    
    $HotFixInfo = $HealthExSvrObj.OSVersion.HotFixInfo
    $KBsToCheckAgainst = Get-HotFixListInfo -OS_Version $HealthExSvrObj.OSVersion.OSVersion 
    $FailSafe = $false
    if($KBsToCheckAgainst -ne $null)
    {
        foreach($KB in $HotFixInfo)
        {
            $KBName = $KB.KBName 
            foreach($KBInfo in $KB.KBInfo)
            {
                if(-not ($KBInfo.Error))
                {
                    #First need to find the correct KB to compare against 
                    $i = 0 
                    $iMax = $KBsToCheckAgainst.Count 
                    while($i -lt $iMax)
                    {
                        if($KBsToCheckAgainst[$i].KBName -eq $KBName)
                        {
                            break; 
                        }
                        else 
                        {
                            $i++ 
                        }
                    }
                    $allPass = $true 
                    foreach($CheckFile in $KBInfo)
                    {
                        $ii = 0 
                        $iMax = $KBsToCheckAgainst[$i].FileInformation.Count 
                        while($ii -lt $iMax)
                        {
                            if($KBsToCheckAgainst[$i].FileInformation[$ii].FriendlyFileName -eq $CheckFile.FriendlyName)
                            {
                                break; 
                            }
                            else 
                            {
                                $ii++    
                            }
                        }
                        
                        $ServerBuild = Get-BuildVersionObjectFromString -BuildString $CheckFile.BuildVersion 
                        $CheckVersion = Get-BuildVersionObjectFromString -BuildString $KBsToCheckAgainst[$i].FileInformation[$ii].BuildVersion
                        if(-not (Get-BuildLevelVersionCheck -ActualVersionObject $ServerBuild -CheckVersionObject $CheckVersion -DebugFunction $false))
                        {
                            $allPass = $false
                        }

                    }
                    
                    $KBInfo | Add-Member -MemberType NoteProperty -Name Passed -Value $allPass   
                }
                else 
                {
                    #If an error has occurred, that means we failed to find the files 
                    $FailSafe = $true 
                    break;    
                }
            }
        }
        if($FailSafe)
        {
            Display-KBHotfixCheckFailSafe -HealthExSvrObj $HealthExSvrObj
        }
        else 
        {
            Write-Grey("`r`nHotfix Check:")
            foreach($KBInfo in $HotFixInfo)
            {
                
                $allPass = $true 
                foreach($KBs in $KBInfo.KBInfo)
                {
                    if(-not ($KBs.Passed))
                    {
                        $allPass = $false
                    }
                }
                $dString = if($allPass){"is Installed"}else{"is recommended for this OS and was not detected.  Please consider installing it to prevent performance issues."}
                if($allPass)
                {
                    Write-Grey("{0} {1}" -f $KBInfo.KBName, ($dString))
                }
                else 
                {
                    Write-Yellow("{0} {1}" -f $KBInfo.KBName, ($dString))    
                }
                
            }
        }
    }

}

Function Display-ResultsToScreen {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
)
    Write-VerboseOutput("Calling: Display-ResultsToScreen")
    Write-VerboseOutput("For Server: " + $HealthExSvrObj.ServerName)

    ####################
    #Header information#
    ####################

    Write-Green("System Information Report for " + $HealthExSvrObj.ServerName + " on " + $date) 
    Write-Break
    Write-Break
    ###############################
    #OS, System, and Exchange Info#
    ###############################

    if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::VMWare -or $HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::HyperV)
    {
        Write-Yellow($VirtualizationWarning) 
        Write-Break
        Write-Break
    }
    Write-Grey("Hardware/OS/Exchange Information:");
    Write-Grey("`tHardware Type: " + $HealthExSvrObj.HardwareInfo.ServerType.ToString())
    if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
    {
        Write-Grey("`tManufacturer: " + $HealthExSvrObj.HardwareInfo.Manufacturer)
        Write-Grey("`tModel: " + $HealthExSvrObj.HardwareInfo.Model) 
    }

    Write-Grey("`tOperating System: " + $HealthExSvrObj.OSVersion.OperatingSystemName)
    Write-Grey("`tSystem up since: {0} day(s), {1} hour(s), {2} minute(s), {3} second(s)" -f $HealthExSvrObj.OSVersion.BootUpTimeInDays, $HealthExSvrObj.OSVersion.BootUpTimeInHours, $HealthExSvrObj.OSVersion.BootUpTimeInMinutes, $HealthExSvrObj.OSVersion.BootUpTimeInSeconds)
    Write-Grey("`tTime Zone: {0}" -f $HealthExSvrObj.OSVersion.TimeZone)
    Write-Grey("`tExchange: " + $HealthExSvrObj.ExchangeInformation.ExchangeFriendlyName)
    Write-Grey("`tBuild Number: " + $HealthExSvrObj.ExchangeInformation.ExchangeBuildNumber)
    #If IU or Security Hotfix detected
    if($HealthExSvrObj.ExchangeInformation.KBsInstalled -ne $null)
    {
        Write-Grey("`tExchange IU or Security Hotfix Detected")
        foreach($kb in $HealthExSvrObj.ExchangeInformation.KBsInstalled)
        {
            Write-Yellow("`t`t{0}" -f $kb)
        }
    }

    if($HealthExSvrObj.ExchangeInformation.SupportedExchangeBuild -eq $false -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        $Dif_Days = ($date - ([System.Convert]::ToDateTime([DateTime]$HealthExSvrObj.ExchangeInformation.BuildReleaseDate))).Days
        Write-Red("`tError: Out of date Cumulative Update.  Please upgrade to one of the two most recently released Cumulative Updates. Currently running on a build that is " + $Dif_Days + " Days old")
    }
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -and ($HealthExSvrObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::Edge -and $HealthExSvrObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::MultiRole))
    {
        Write-Yellow("`tServer Role: " + $HealthExSvrObj.ExchangeInformation.ExServerRole.ToString() + " --- Warning: Multi-Role servers are recommended") 
    }
    else
    {
        Write-Grey("`tServer Role: " + $HealthExSvrObj.ExchangeInformation.ExServerRole.ToString())
    }

    #MAPI/HTTP 
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        Write-Grey("`tMAPI/HTTP Enabled: {0}" -f $HealthExSvrObj.ExchangeInformation.MapiHttpEnabled)
        if($HealthExSvrObj.ExchangeInformation.MapiHttpEnabled -eq $true -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013)
        {
            if($HealthExSvrObj.ExchangeInformation.MapiFEAppGCEnabled -eq "false" -and 
            $HealthExSvrObj.HardwareInfo.TotalMemory -ge 21474836480)
            {
                Write-Red("`t`tMAPI Front End App Pool GC Mode: Workstation --- Error")
                Write-Yellow("`t`tTo Fix this issue go into the file MSExchangeMapiFrontEndAppPool_CLRConfig.config in the Exchange Bin directory and change the GCServer to true and recycle the MAPI Front End App Pool")
            }
            elseif($HealthExSvrObj.ExchangeInformation.MapiFEAppGCEnabled -eq "false")
            {
                Write-Yellow("`t`tMapi Front End App Pool GC Mode: Workstation --- Warning")
                Write-Yellow("`t`tYou could be seeing some GC issues within the Mapi Front End App Pool. However, you don't have enough memory installed on the system to recommend switching the GC mode by default without consulting a support professional.")
            }
            elseif($HealthExSvrObj.ExchangeInformation.MapiFEAppGCEnabled -eq "true")
            {
                Write-Green("`t`tMapi Front End App Pool GC Mode: Server")
            }
            else 
            {
                Write-Yellow("Mapi Front End App Pool GC Mode: Unknown --- Warning")    
            }
        }
    }

    ###########
    #Page File#
    ###########

    Write-Grey("Pagefile Settings:")
    if($HealthExSvrObj.HardwareInfo.AutoPageFile) 
    {
        Write-Red("`tError: System is set to automatically manage the pagefile size. This is not recommended.") 
    }
    elseif($HealthExSvrObj.OSVersion.PageFile.PageFile.Count -gt 1)
    {
        Write-Red("`tError: Multiple page files detected. This has been known to cause performance issues please address this.")
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2010) 
    {
        #Exchange 2010, we still recommend that we have the page file set to RAM + 10 MB 
        #Page File Size is Less than Physical Memory Size Plus 10 MB 
        #https://technet.microsoft.com/en-us/library/cc431357(v=exchg.80).aspx
        $sDisplay = Verify-PagefileEqualMemoryPlus10 -page_obj $HealthExSvrObj.OSVersion.PageFile -hardware_obj $HealthExSvrObj.HardwareInfo
        if($sDisplay -eq "Good")
        {
            Write-Grey("`tPagefile Size: " + $HealthExSvrObj.OSVersion.PageFile.MaxPageSize)
        }
        else
        {
            Write-Yellow("`tPagefile Size: {0} --- Warning: Article: https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#pagefile" -f $sDisplay)
            Write-Yellow("`tNote: We are calculating the page file size based off the WMI Object Win32_ComputerSystem. This is what is available on the OS.") 
        }
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2019)
    {
        $displayString = Verify-Pagefile25PercentOfTotalMemory -PageFileObj $HealthExSvrObj.OSVersion.PageFile -HardwareObj $HealthExSvrObj.HardwareInfo
        if($displayString -eq "Good")
        {
            Write-Grey("`tPagefile Size: {0}" -f $HealthExSvrObj.OSVersion.PageFile.MaxPageSize)
        }
        else
        {
            Write-Yellow("`tPagefile Size: {0} --- Warning --- See article: https://docs.microsoft.com/en-us/exchange/plan-and-deploy/system-requirements?view=exchserver-2019#hardware" -f $displayString)
            Write-Yellow("`tNote: We are calculating the page file size based off the WMI Object Win32_ComputerSystem. This is what is available on the OS.")
        }
    }
    #Exchange 2013/2016 with memory greater than 32 GB. Should be set to 32 + 10 MB for a value 
    #32GB = 1024 * 1024 * 1024 * 32 = 34,359,738,368 
    elseif($HealthExSvrObj.HardwareInfo.TotalMemory -ge 34359738368)
    {
        if($HealthExSvrObj.OSVersion.PageFile.MaxPageSize -eq 32778)
        {
            Write-Grey("`tPagefile Size: " + $HealthExSvrObj.OSVersion.PageFile.MaxPageSize)
        }
        else
        {
            Write-Yellow("`tPagefile Size: " + $HealthExSvrObj.OSVersion.PageFile.MaxPageSize + " --- Warning: Pagefile should be capped at 32778 MB for 32 GB Plus 10 MB - Article: https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#pagefile")
        }
    }
    #Exchange 2013 with page file size that should match total memory plus 10 MB 
    else
    {
        $sDisplay = Verify-PagefileEqualMemoryPlus10 -page_obj $HealthExSvrObj.OSVersion.PageFile -hardware_obj $HealthExSvrObj.HardwareInfo
        if($sDisplay -eq "Good")
        {
            Write-Grey("`tPagefile Size: " + $HealthExSvrObj.OSVersion.PageFile.MaxPageSize)
        }
        else
        {
            Write-Yellow("`tPagefile Size: {0} --- Warning: Article: https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#pagefile" -f $sDisplay)
            Write-Yellow("`tNote: We are calculating the page file size based off the WMI Object Win32_ComputerSystem. This is what is available on the OS.") 
        }
    }

    ################
    #.NET FrameWork#
    ################

    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -gt [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        Write-Grey(".NET Framework:")
        
        if($HealthExSvrObj.NetVersionInfo.SupportedVersion)
        {
            if($HealthExSvrObj.ExchangeInformation.RecommendedNetVersion)
            {
                Write-Green("`tVersion: " + $HealthExSvrObj.NetVersionInfo.FriendlyName)
            }
            else
            {
                Write-Yellow("`tDetected Version: " + $HealthExSvrObj.NetVersionInfo.FriendlyName + " --- Warning: " + $HealthExSvrObj.NetVersionInfo.DisplayWording)
            }
        }
        else
        {
                Write-Red("`tDetected Version: " + $HealthExSvrObj.NetVersionInfo.FriendlyName + " --- Error: " + $HealthExSvrObj.NetVersionInfo.DisplayWording)
        }

    }

    ################
    #  Visual C++  #
    ################
    #Only going to do this for Exchange 2013+ after C++ was required.
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -gt [HealthChecker.ExchangeVersion]::Exchange2010 -and 
        ([System.Convert]::ToDateTime([DateTime]$HealthExSvrObj.ExchangeInformation.BuildReleaseDate)) -ge ([System.Convert]::ToDateTime("06/19/2018", [System.Globalization.DateTimeFormatInfo]::InvariantInfo)))
    {
        Write-Grey("Visual C++ Redistributable Version Check:")
        $VisualCInfo = Confirm-VisualCRedistributableVersion -ExchangeServerObj $HealthExSvrObj
        $displayNote = $false 
        if($VisualCInfo.VC2013Required -eq $true)
        {
            if($VisualCInfo.VC2013Current -eq $true)
            {
                Write-Green("`tVisual C++ 2013 Redistributable Version {0} is current" -f $VisualCInfo.VC2013Version)
            }
            else
            {
                Write-Yellow("`tVisual C++ 2013 Redistributable is outdated")
                $displayNote = $true 
            }
        }
        if($VisualCInfo.VC2012Required -eq $true)
        {
            if($VisualCInfo.VC2012Current -eq $true)
            {
                Write-Green("`tVisual C++ 2012 Redistributable Version {0} is current" -f $VisualCInfo.VC2012Version)
            }
            else
            {
                Write-Yellow("`tVisual C++ 2012 Redistributable is outdated")
                $displayNote = $true 
            }
        }
        else
        {
            Write-Yellow("`tUnable to determin required Visual C++ Redistributable Versions")
        }
        if($displayNote)
        {
            Write-Yellow("`tNote: For more information about the latest C++ Redistributeable please visit: https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads")
            Write-Yellow("`tThis is not a requirement to upgrade, only a notification to bring to your attention.")
        }
    }
    else 
    {
        Write-VerboseOutput("Not checking Visual C++ Redistributeable Version.")
    }
    ################
    #Power Settings#
    ################
    Write-Grey("Power Settings:")
    if($HealthExSvrObj.OSVersion.HighPerformanceSet)
    {
        Write-Green("`tPower Plan: " + $HealthExSvrObj.OSVersion.PowerPlanSetting)
    }
    elseif($HealthExSvrObj.OSVersion.PowerPlan -eq $null) 
    {
        Write-Red("`tPower Plan: Not Accessible --- Error")
    }
    else
    {
        Write-Red("`tPower Plan: " + $HealthExSvrObj.OSVersion.PowerPlanSetting + " --- Error: High Performance Power Plan is recommended")
    }

    ################
    #Pending Reboot#
    ################

    Write-Grey("Server Pending Reboot:")

    if($HealthExSvrObj.OSVersion.ServerPendingReboot)
    {
        Write-Red("`tTrue --- Error: This can cause issues if files haven't been properly updated.")
    }
    else 
    {
        Write-Green("`tFalse")    
    }

	#####################
	#Http Proxy Settings#
	#####################

	Write-Grey("Http Proxy Setting:")
	if($HealthExSvrObj.OSVersion.HttpProxy -eq "<None>")
	{
		Write-Green("`tSetting: {0}" -f $HealthExSvrObj.OSVersion.HttpProxy)
	}
	else
	{
		Write-Yellow("`tSetting: {0} --- Warning: This could cause connectivity issues." -f $HealthExSvrObj.OSVersion.HttpProxy)
	}

    ##################
    #Network Settings#
    ##################

    Function Write-NICPacketReceivedDiscarded{
    param(
    [Parameter(Mandatory=$true)]$NICInstance 
    )
        $cookedValue = 0
        $foundCounter = $false 
        if($HealthExSvrObj.OSVersion.PacketsReceivedDiscarded -eq $null)
        {
            Write-VerboseOutput("HealthExSvrObj.OSVersion.PacketsReceivedDiscarded is null")
            return
        }
        foreach($instance in $HealthExSvrObj.OSVersion.PacketsReceivedDiscarded)
        {
            $instancePath = $instance.Path 
            $startIndex = $instancePath.IndexOf("(") + 1
            $charLength = $instancePath.Substring($startIndex, ($instancePath.IndexOf(")") - $startIndex)).Length
            $instanceName = $instancePath.Substring($startIndex, $charLength)
            $possibleInstanceName = $NICInstance.Replace("#","_")
            if($instanceName -eq $NICInstance -or $instanceName -eq $possibleInstanceName)
            {
                $cookedValue = $instance.CookedValue
                $foundCounter = $true 
                break 
            }
        }
        if($foundCounter)
        {
            if($cookedValue -eq 0)
            {
                Write-Green("`t`tPackets Received Discarded: 0")
            }
            elseif($cookedValue -lt 1000)
            {
                Write-Yellow("`t`tPackets Received Discarded: {0} - Warning: This value should be at 0." -f $cookedValue)
            }
            else 
            {
                Write-Red("`t`tPackets Received Discarded: {0} - Error: This value should be at 0. We are also seeing this value being rather high so this can cause a performance impacted on a system." -f $cookedValue)    
            }
            if($NICInstance -like "*vmxnet3*" -and $cookedValue -gt 0)
            {
                Write-Yellow("`t`t`tKnown Issue with vmxnet3: 'Large packet loss at the guest operating system level on the VMXNET3 vNIC in ESXi (2039495)' - https://kb.vmware.com/s/article/2039495")
            }
        }
        else 
        {
            Write-VerboseOutput("Could not find counter data for '{0}'" -f $NICInstance)
        }
    }

    Write-Grey("NIC settings per active adapter:")
    if($HealthExSvrObj.OSVersion.OSVersion -ge [HealthChecker.OSVersionName]::Windows2012R2)
    {
        foreach($adapter in $HealthExSvrObj.OSVersion.NetworkAdapters)
        {
            Write-Grey(("`tInterface Description: {0} [{1}] " -f $adapter.Description, $adapter.Name))
            if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
            {
                if($adapter.DriverDate -ne $null -and (New-TimeSpan -Start $date -End $adapter.DriverDate).Days -lt [int]-365)
                {
                    Write-Yellow("`t`tWarning: NIC driver is over 1 year old. Verify you are at the latest version.")
                    Write-Grey("`t`tDriver Date: " + $adapter.DriverDate)
                }
                elseif($adapter.DriverDate -eq $null -or $adapter.DriverDate -eq [DateTime]::MaxValue)
                {
                    Write-Grey("`t`tDriver Date: Unknown")
                }
                else 
                {
                    Write-Grey("`t`tDriver Date: " + $adapter.DriverDate)
                }
                Write-Grey("`t`tDriver Version: " + $adapter.DriverVersion)
                Write-Grey("`t`tLink Speed: " + $adapter.LinkSpeed)
            }
            else
            {
                Write-Yellow("`t`tLink Speed: Cannot be accurately determined due to virtualized hardware")
            }
            Write-Grey("`t`tMTU Size: {0}" -f $adapter.MTUSize)
            if($adapter.RSSEnabled -eq "NoRSS")
            {
                Write-Yellow("`t`tRSS: No RSS Feature Detected.")
            }
            elseif($adapter.RSSEnabled -eq "True")
            {
                Write-Green("`t`tRSS: Enabled")
            }
            else
            {
                Write-Yellow("`t`tRSS: Disabled --- Warning: Enabling RSS is recommended.")
            }
            if($HealthExSvrObj.OSVersion.DisabledComponents -ne 255 -and $adapter.IPv6Enabled -eq $false )
            {
                Write-Yellow("`t`tIPv6Enabled: {0} --- Warning" -f $adapter.IPv6Enabled)
            }
            else 
            {
                Write-Grey("`t`tIPv6Enabled: {0}" -f $adapter.IPv6Enabled)
            }
            Write-NICPacketReceivedDiscarded -NICInstance $adapter.Description          

        }

    }
    else
    {
        Write-Yellow("`tMore detailed NIC settings can be detected if both the local and target server are running on Windows 2012 R2 or later.")
        
        foreach($adapter in $HealthExSvrObj.OSVersion.NetworkAdapters)
        {
            Write-Grey("`tInterface Description: {0} [{1}]" -f $adapter.Description, $adapter.Name)
            if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
            {
                Write-Grey("`t`tLink Speed: " + $adapter.LinkSpeed)
            }
            else 
            {
                Write-Yellow("`t`tLink Speed: Cannot be accurately determined due to virtualization hardware")    
            }
            if($HealthExSvrObj.OSVersion.DisabledComponents -ne 255 -and $adapter.IPv6Enabled -eq $false )
            {
                Write-Yellow("`t`tIPv6Enabled: {0} --- Warning" -f $adapter.IPv6Enabled)
            }
            else 
            {
                Write-Grey("`t`tIPv6Enabled: {0}" -f $adapter.IPv6Enabled)
            }
            Write-NICPacketReceivedDiscarded -NICInstance $adapter.Description
        }
        
    }
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        if($HealthExSvrObj.OSVersion.NetworkAdapters.Count -gt 1 -and ($HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::Mailbox -or $HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::MultiRole))
        {
            Write-Yellow("`t`tMultiple active network adapters detected. Exchange 2013 or greater may not need separate adapters for MAPI and replication traffic.  For details please refer to https://docs.microsoft.com/en-us/exchange/planning-for-high-availability-and-site-resilience-exchange-2013-help#NR")
        }
    }
    if($HealthExSvrObj.OSVersion.DisabledComponents -ne 255 -and $HealthExSvrObj.OSVersion.IPv6DisabledOnNICs)
    {
        Write-Break
        Write-Red("Error: IPv6 is disabled on some NIC level settings but not fully disabled. DisabledComponents registry key currently set to '{0}'. For details please refer to the following articles: `r`n`thttps://blogs.technet.microsoft.com/rmilne/2014/10/29/disabling-ipv6-and-exchange-going-all-the-way/ `r`n`thttps://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users" -f $HealthExSvrObj.OSVersion.DisabledComponents )
    }
    #######################
    #Processor Information#
    #######################
    Write-Grey("Processor/Memory Information")
    Write-Grey("`tProcessor Type: " + $HealthExSvrObj.HardwareInfo.Processor.ProcessorName)
    Function Check-MaxCoresCount {
    param(
    [Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
    )
        if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2019 -and 
        $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 48)
        {
            Write-Red("`tError: More than 48 cores detected, this goes against best practices. For details see `r`n`thttps://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-2019-Public-Preview/ba-p/608158")
        }
        elseif(($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -or 
        $HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2016) -and 
        $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 24)
        {
            Write-Red("`tError: More than 24 cores detected, this goes against best practices. For details see `r`n`thttps://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Ask-the-Perf-Guy-How-big-is-too-BIG/ba-p/603855")
        }
    }

    #First, see if we are hyperthreading
    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
    {
        #Hyperthreading enabled 
        Write-Red("`tHyper-Threading Enabled: Yes --- Error: Having Hyper-Threading enabled goes against best practices. Please disable as soon as possible.")
        #AMD might not have the correct logic here. Throwing warning about this. 
        if($HealthExSvrObj.HardwareInfo.Processor.ProcessorName.StartsWith("AMD"))
        {
            Write-Yellow("`tThis script may incorrectly report that Hyper-Threading is enabled on certain AMD processors.  Check with the manufacturer to see if your model supports SMT.")
        }
        Check-MaxCoresCount -HealthExSvrObj $HealthExSvrObj
    }
    else
    {
        Write-Green("`tHyper-Threading Enabled: No")
        Check-MaxCoresCount -HealthExSvrObj $HealthExSvrObj
    }
    #Number of Processors - Number of Processor Sockets. 
    if($HealthExSvrObj.HardwareInfo.ServerType -ne [HealthChecker.ServerType]::Physical)
    {
        Write-Grey("`tNumber of Processors: {0}" -f $HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors)
        if($HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors -gt 2 -and $HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::VMWare)
        {
            Write-Grey("`t`tNote: Please make sure you are following VMware's performance recommendation to get the most out of your guest machine. VMware blog 'Does corespersocket Affect Performance?' https://blogs.vmware.com/vsphere/2013/10/does-corespersocket-affect-performance.html")
        }
        if($HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors -gt 2)
        {
            Write-Grey("`t`tNote: If you are running into a CPU constraint and have a case open with Microsoft Premier Support, feel free to have the case owner reach out to 'David Paulson (Exchange)' if they feel it is needed.")
        }
    }
    elseif($HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors -gt 2)
    {
        Write-Red("`tNumber of Processors: {0} - Error: We recommend only having 2 Processor Sockets." -f $HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors)
    }
    else 
    {
        Write-Green("`tNumber of Processors: {0}" -f $HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors)
    }

    #Core count
    if(($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 24 -and 
    $HealthExSvrObj.ExchangeInformation.ExchangeVersion -lt [HealthChecker.ExchangeVersion]::Exchange2019) -or 
    ($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 48))
    {
        Write-Yellow("`tNumber of Physical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        Write-Yellow("`tNumber of Logical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
    }
    else
    {
        Write-Green("`tNumber of Physical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        Write-Green("`tNumber of Logical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
    }

    #NUMA BIOS CHECK - AKA check to see if we can properly see all of our cores on the box. 
	if($HealthExSvrObj.HardwareInfo.Model -like "*ProLiant*")
	{
		if($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -eq -1)
		{
			Write-Yellow("`tNUMA Group Size Optimization: Unable to determine --- Warning: If this is set to Clustered, this can cause multiple types of issues on the server")
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
		{
			Write-Red("`tNUMA Group Size Optimization: BIOS Set to Clustered --- Error: This setting should be set to Flat. By having this set to Clustered, we will see multiple different types of issues.")
		}
		else
		{
			Write-Green("`tNUMA Group Size Optimization: BIOS Set to Flat")
		}
	}
	else
	{
		if($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -eq -1)
		{
			Write-Yellow("`tAll Processor Cores Visible: Unable to determine --- Warning: If we aren't able to see all processor cores from Exchange, we could see performance related issues.")
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
		{
			Write-Red("`tAll Processor Cores Visible: Not all Processor Cores are visible to Exchange and this will cause a performance impact --- Error")
		}
		else
		{
			Write-Green("`tAll Processor Cores Visible: Passed")
		}
	}
    if($HealthExSvrObj.HardwareInfo.Processor.ProcessorIsThrottled)
    {
        #We are set correctly at the OS layer
        if($HealthExSvrObj.OSVersion.HighPerformanceSet)
        {
            Write-Red("`tError: Processor speed is being throttled. Power plan is set to `"High performance`", so it is likely that we are throttling in the BIOS of the computer settings")
        }
        else
        {
            Write-Red("`tError: Processor speed is being throttled. Power plan isn't set to `"High performance`". Change this ASAP because you are throttling your CPU and is likely causing issues.")
            Write-Yellow("`tNote: This change doesn't require a reboot and takes affect right away. Re-run the script after doing so")
        }
        Write-Red("`tCurrent Processor Speed: " + $HealthExSvrObj.HardwareInfo.Processor.CurrentMegacyclesPerCore + " --- Error: Processor appears to be throttled. This will cause performance issues. See Max Processor Speed to see what this should be at.")
        Write-Red("`tMax Processor Speed: " + $HealthExSvrObj.HardwareInfo.Processor.MaxMegacyclesPerCore )
    }
    else
    {
        Write-Grey("`tMegacycles Per Core: " + $HealthExSvrObj.HardwareInfo.Processor.MaxMegacyclesPerCore)
    }
    
    #Memory Going to check for greater than 96GB of memory for Exchange 2013
    #The value that we shouldn't be greater than is 103,079,215,104 (96 * 1024 * 1024 * 1024) 
    #Exchange 2016 we are going to check to see if there is over 192 GB https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Ask-the-Perf-Guy-Update-to-scalability-guidance-for-Exchange/ba-p/607260
    #For Exchange 2016 the value that we shouldn't be greater than is 206,158,430,208 (192 * 1024 * 1024 * 1024)
    #For Exchange 2019 the value that we shouldn't be greater than is 274,877,906,944 (256 * 1024 * 1024 * 1024) - https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-2019-Public-Preview/ba-p/608158
    #For Exchange 2019 we recommend a min of 128GB  for Mailbox and 64GB for Edge - https://docs.microsoft.com/en-us/exchange/plan-and-deploy/system-requirements?view=exchserver-2019#operating-system
    $totalPhysicalMemory = [System.Math]::Round($HealthExSvrObj.HardwareInfo.TotalMemory / 1024 /1024 /1024) 
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2019 -and
        $HealthExSvrObj.HardwareInfo.TotalMemory -gt 274877906944)
    {
        Write-Yellow("`tPhysical Memory: {0} GB --- We recommend for the best performance to be scaled at or below 256 GB of Memory." -f $totalPhysicalMemory)
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2016 -and
        $HealthExSvrObj.HardwareInfo.TotalMemory -gt 206158430208)
    {
        Write-Yellow("`tPhysical Memory: {0} GB --- We recommend for the best performance to be scaled at or below 192 GB of Memory." -f $totalPhysicalMemory)
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -and
     $HealthExSvrObj.HardwareInfo.TotalMemory -gt 103079215104)
    {
        Write-Yellow ("`tPhysical Memory: " + $totalPhysicalMemory + " GB --- Warning: We recommend for the best performance to be scaled at or below 96GB of Memory. However, having higher memory than this has yet to be linked directly to a MAJOR performance issue of a server.")
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2019 -and 
        $HealthExSvrObj.HardwareInfo.TotalMemory -lt 137438953472 -and 
        $HealthExSvrObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::Edge)
    {
        Write-Yellow("`tPhysical Memory: {0} GB --- Warning: We recommend for the best performance to have a minimum of 128GB of RAM installed on the machine." -f $totalPhysicalMemory)
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2019 -and 
        $HealthExSvrObj.HardwareInfo.TotalMemory -lt 68719476736 -and 
        $HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::Edge)
    {
        Write-Yellow("`tPhysical Memory: {0} GB --- Warning: We recommend for the best performance to have a minimum of 64GB of RAM installed on the machine." -f $totalPhysicalMemory)
    }
    else
    {
        Write-Grey("`tPhysical Memory: " + $totalPhysicalMemory + " GB") 
    }

    ################
	#Service Health#
	################
    #We don't want to run if the server is 2013 CAS role or if the Role = None
    if(-not(($HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::None) -or 
        (($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013) -and 
        ($HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::ClientAccess))))
    {
		if($HealthExSvrObj.ExchangeInformation.ExchangeServicesNotRunning)
	    {
		    Write-Yellow("`r`nWarning: The following services are not running:")
        $HealthExSvrObj.ExchangeInformation.ExchangeServicesNotRunning | %{Write-Grey($_)}
	    }

    }

    #################
	#TCP/IP Settings#
	#################
    Write-Grey("`r`nTCP/IP Settings:")
    if($HealthExSvrObj.OSVersion.TCPKeepAlive -eq 0)
    {
        Write-Red("Error: The TCP KeepAliveTime value is not specified in the registry.  Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration.  To avoid issues, add the KeepAliveTime REG_DWORD entry under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters and set it to a value between 900000 and 1800000 decimal.  You want to ensure that the TCP idle timeout value gets higher as you go out from Exchange, not lower.  For example if the Exchange server has a value of 30 minutes, the Load Balancer could have an idle timeout of 35 minutes, and the firewall could have an idle timeout of 40 minutes.  Please note that this change will require a restart of the system.  Refer to the sections `"CAS Configuration`" and `"Load Balancer Configuration`" in this blog post for more details:  https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792")
    }
    elseif($HealthExSvrObj.OSVersion.TCPKeepAlive -lt 900000 -or $HealthExSvrObj.OSVersion.TCPKeepAlive -gt 1800000)
    {
        Write-Yellow("Warning: The TCP KeepAliveTime value is not configured optimally.  It is currently set to " + $HealthExSvrObj.OSVersion.TCPKeepAlive + ". This can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration.  To avoid issues, set the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime registry entry to a value between 15 and 30 minutes (900000 and 1800000 decimal).  You want to ensure that the TCP idle timeout gets higher as you go out from Exchange, not lower.  For example if the Exchange server has a value of 30 minutes, the Load Balancer could have an idle timeout of 35 minutes, and the firewall could have an idle timeout of 40 minutes.  Please note that this change will require a restart of the system.  Refer to the sections `"CAS Configuration`" and `"Load Balancer Configuration`" in this blog post for more details:  https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792")
    }
    else
    {
        Write-Green("The TCP KeepAliveTime value is configured optimally (" + $HealthExSvrObj.OSVersion.TCPKeepAlive + ")")
    }
    Write-Grey("`r`nRPC Minimum Connection Timeout:")
    if($HealthExSvrObj.OSVersion.MinimumConnectionTimeout -eq 0)
    {
        Write-Grey("`tNote: The RPC MinimumConnectionTimeout is currently not set on the system. This may cause some issues with client connectivity. `r`n`tMore Information: `r`n`thttps://blogs.technet.microsoft.com/messaging_with_communications/2012/06/06/outlook-anywhere-network-timeout-issue/")
    }
    elseif($HealthExSvrObj.OSVersion.MinimumConnectionTimeout -eq 120)
    {
        Write-Grey("`tNote: The RPC MinimumConnectionTimeout is currently set to 120 which is the recommended value.")
    }
    else 
    {
        Write-Grey("`tNote: The RPC MinimumConnectionTimeout is currently set to {0} which is not the recommended value. `r`n`tMore Information: `r`n`thttps://blogs.technet.microsoft.com/messaging_with_communications/2012/06/06/outlook-anywhere-network-timeout-issue/" -f $HealthExSvrObj.OSVersion.MinimumConnectionTimeout)    
    }

    ###############################
	#LmCompatibilityLevel Settings#
	###############################
    Write-Grey("`r`nLmCompatibilityLevel Settings:")
    Write-Grey("`tLmCompatibilityLevel is set to: " + $HealthExSvrObj.OSVersion.LmCompat.LmCompatibilityLevel)
    Write-Grey("`tLmCompatibilityLevel Description: " + $HealthExSvrObj.OSVersion.LmCompat.LmCompatibilityLevelDescription)
    Write-Grey("`tLmCompatibilityLevel Ref: " + $HealthExSvrObj.OSVersion.LmCompat.LmCompatibilityLevelRef)

    ################
    # TLS Settings #
    ################

    Write-Grey("`r`nTLS Settings:")
    foreach($TLS in $HealthExSvrObj.OSVersion.TLSSettings)
    {
        Write-Grey("`tTLS {0}" -f $TLS.TLSName)
        Write-Grey("`tServer Enabled: {0}" -f $TLS.ServerEnabled)
        Write-Grey("`tServer Disabled By Default: {0}" -f $TLS.ServerDisabledByDefault)
        Write-Grey("`tClient Enabled: {0}" -f $TLS.ClientEnabled)
        Write-Grey("`tClient Disabled by Default: {0}" -f $TLS.ClientDisabledByDefault)
        if($TLS.ServerEnabled -ne $TLS.ClientEnabled)
        {
            Write-Red("`t`tError: Mismatch in TLS version for client and server. Exchange can be both client and a server. This can cause issues within Exchange for communication.")
        }
        if(($TLS.TLSName -eq "1.0" -or $TLS.TLSName -eq "1.1") -and
            ($TLS.ServerEnabled -eq $false -or $TLS.ClientEnabled -eq $false -or 
            $TLS.ServerDisabledByDefault -or $TLS.ClientDisabledByDefault) -and
            ($HealthExSvrObj.OSVersion.NetDefaultTlsVersion.SystemDefaultTlsVersions -eq $false -or $HealthExSvrObj.OSVersion.NetDefaultTlsVersion.WowSystemDefaultTlsVersions -eq $false)) 
            {
                Write-Red("`t`tError: Failed to set .NET SystemDefaultTlsVersions. Please visit on how to properly enable TLS 1.2 https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761")
            }
    }

	##############
	#Hotfix Check#
	##############
    
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        Display-KBHotfixCheck -HealthExSvrObj $HealthExSvrObj
    }
    Display-KBHotFixCompareIssues -HealthExSvrObj $HealthExSvrObj

    ##########################
    #Exchange Web App GC Mode#
    ##########################

    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        Write-Grey("`r`nExchange Web App Pools - GC Server Mode Enabled | Status:")
        foreach($webAppKey in $HealthExSvrObj.ExchangeInformation.ExchangeAppPools.Keys)
        {
            $xmlData = [xml]$HealthExSvrObj.ExchangeInformation.ExchangeAppPools[$webAppKey].Content
            $enabled = $xmlData.Configuration.runtime.gcServer.enabled
            $status = $HealthExSvrObj.ExchangeInformation.ExchangeAppPools[$webAppKey].Status
            Write-Grey("`t{0}: {1} | {2}" -f $webAppKey, $enabled, $status)
        }
    }

    #####################
    #Vulnerability Check#
    #####################

    Display-MSExchangeVulnerabilities $HealthExSvrObj


    Write-Grey("`r`n`r`n")

}

Function Build-ServerObject
{
    param(
    [Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
    )

    $ServerObject = New-Object –TypeName PSObject

    $ServerObject | Add-Member –MemberType NoteProperty –Name ServerName –Value $HealthExSvrObj.ServerName

    if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::VMWare -or $HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::HyperV)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name VirtualServer –Value "Yes"
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name VirtualServer –Value "No"
    }

    $ServerObject | Add-Member –MemberType NoteProperty –Name HardwareType –Value $HealthExSvrObj.HardwareInfo.ServerType.ToString()

    if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name Manufacturer –Value $HealthExSvrObj.HardwareInfo.Manufacturer
        $ServerObject | Add-Member –MemberType NoteProperty –Name Model –Value $HealthExSvrObj.HardwareInfo.Model
    }

    $ServerObject | Add-Member –MemberType NoteProperty –Name OperatingSystem –Value $HealthExSvrObj.OSVersion.OperatingSystemName
    $ServerObject | Add-Member –MemberType NoteProperty –Name Exchange –Value $HealthExSvrObj.ExchangeInformation.ExchangeFriendlyName
    $ServerObject | Add-Member –MemberType NoteProperty –Name BuildNumber –Value $HealthExSvrObj.ExchangeInformation.ExchangeBuildNumber

    #If IU or Security Hotfix detected
    if($HealthExSvrObj.ExchangeInformation.KBsInstalled -ne $null)
    {
        $KBArray = @()
        foreach($kb in $HealthExSvrObj.ExchangeInformation.KBsInstalled)
        {
            $KBArray += $kb
        }

        $ServerObject | Add-Member –MemberType NoteProperty –Name InterimUpdatesInstalled -Value $KBArray
    }

    if($HealthExSvrObj.ExchangeInformation.SupportedExchangeBuild -eq $false -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        $Dif_Days = ((Get-Date) - ([System.Convert]::ToDateTime([DateTime]$HealthExSvrObj.ExchangeInformation.BuildReleaseDate))).Days
        $ServerObject | Add-Member –MemberType NoteProperty –Name BuildDaysOld –Value $Dif_Days
		$ServerObject | Add-Member –MemberType NoteProperty –Name SupportedExchangeBuild -Value $HealthExSvrObj.ExchangeInformation.SupportedExchangeBuild
    }
	else
	{
		$ServerObject | Add-Member –MemberType NoteProperty –Name SupportedExchangeBuild -Value $True
	}

    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -and ($HealthExSvrObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::Edge -and $HealthExSvrObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::MultiRole))
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name ServerRole -Value "Not Multirole"
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name ServerRole -Value $HealthExSvrObj.ExchangeInformation.ExServerRole.ToString()
    }


    ###########
    #Page File#
    ###########

    if($HealthExSvrObj.HardwareInfo.AutoPageFile) 
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name AutoPageFile -Value "Yes"
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name AutoPageFile -Value "No"
    }
    
    if($HealthExSvrObj.OSVersion.PageFile.PageFile.Count -gt 1)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name MultiplePageFiles -Value "Yes"
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name MultiplePageFiles -Value "No"
    }
    
    
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2010) 
    {
        #Exchange 2010, we still recommend that we have the page file set to RAM + 10 MB 
        #Page File Size is Less than Physical Memory Size Plus 10 MB 
        #https://technet.microsoft.com/en-us/library/cc431357(v=exchg.80).aspx
        $sDisplay = Verify-PagefileEqualMemoryPlus10 -page_obj $HealthExSvrObj.OSVersion.PageFile -hardware_obj $HealthExSvrObj.HardwareInfo
        if($sDisplay -eq "Good")
        {

            $ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSize -Value "$($HealthExSvrObj.OSVersion.PageFile.MaxPageSize)"
      			$ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSizeSetRight -Value "Yes"

        }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSize -Value "$($HealthExSvrObj.OSVersion.PageFile.MaxPageSize)"
			$ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSizeSetRight -Value "No"
        }
    }

    #Exchange 2013+ with memory greater than 32 GB. Should be set to 32 + 10 MB for a value 
    #32GB = 1024 * 1024 * 1024 * 32 = 34,359,738,368 
    elseif($HealthExSvrObj.HardwareInfo.TotalMemory -ge 34359738368)

    {
        if($HealthExSvrObj.OSVersion.PageFile.MaxPageSize -eq 32778)
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSize -Value "$($HealthExSvrObj.OSVersion.PageFile.MaxPageSize)"
			$ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSizeSetRight -Value "Yes"
        }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSize -Value "$($HealthExSvrObj.OSVersion.PageFile.MaxPageSize)"
			$ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSizeSetRight -Value "No"
        }
    }
    #Exchange 2013 with page file size that should match total memory plus 10 MB 
    else
    {
        $sDisplay = Verify-PagefileEqualMemoryPlus10 -page_obj $HealthExSvrObj.OSVersion.PageFile -hardware_obj $HealthExSvrObj.HardwareInfo
        if($sDisplay -eq "Good")
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSize -Value "$($HealthExSvrObj.OSVersion.PageFile.MaxPageSize)"
			$ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSizeSetRight -Value "Yes"
        }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSize -Value "$($HealthExSvrObj.OSVersion.PageFile.MaxPageSize)"
			$ServerObject | Add-Member –MemberType NoteProperty –Name PagefileSizeSetRight -Value "No"
        }
    }

    ################
    #.NET FrameWork#
    ################
    
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -gt [HealthChecker.ExchangeVersion]::Exchange2010)
    {

        if($HealthExSvrObj.NetVersionInfo.SupportedVersion)
        {
            if($HealthExSvrObj.ExchangeInformation.RecommendedNetVersion)
            {
                $ServerObject | Add-Member –MemberType NoteProperty –Name DotNetVersion -Value $HealthExSvrObj.NetVersionInfo.FriendlyName
            }
            else
            {
                $ServerObject | Add-Member –MemberType NoteProperty –Name DotNetVersion -Value "$($HealthExSvrObj.NetVersionInfo.FriendlyName) $($HealthExSvrObj.NetVersionInfo.DisplayWording)"
            }
        }
        else
        {
                $ServerObject | Add-Member –MemberType NoteProperty –Name DotNetVersion -Value "$($HealthExSvrObj.NetVersionInfo.FriendlyName) $($HealthExSvrObj.NetVersionInfo.DisplayWording)"
        }

    }


    ################
    #Power Settings#
    ################

    if($HealthExSvrObj.OSVersion.HighPerformanceSet)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name PowerPlan -Value $HealthExSvrObj.OSVersion.PowerPlanSetting
		$ServerObject | Add-Member –MemberType NoteProperty –Name PowerPlanSetRight -Value $True
    }
    elseif($HealthExSvrObj.OSVersion.PowerPlan -eq $null) 
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name PowerPlan -Value "Not Accessible"
		$ServerObject | Add-Member –MemberType NoteProperty –Name PowerPlanSetRight -Value $False
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name PowerPlan -Value "$($HealthExSvrObj.OSVersion.PowerPlanSetting)"
		$ServerObject | Add-Member –MemberType NoteProperty –Name PowerPlanSetRight -Value $False
    }



    #####################
	#Http Proxy Settings#
	#####################

    $ServerObject | Add-Member –MemberType NoteProperty –Name HTTPProxy -Value $HealthExSvrObj.OSVersion.HttpProxy


    ##################
    #Network Settings#
    ##################

    if($HealthExSvrObj.OSVersion.OSVersion -ge [HealthChecker.OSVersionName]::Windows2012R2)
    {
        if((($HealthExSvrObj.OSVersion.NetworkAdapters).count) -gt 1)
        {
			$i = 1
			
			$ServerObject | Add-Member –MemberType NoteProperty –Name NumberNICs ($HealthExSvrObj.OSVersion.NetworkAdapters).count

            foreach($adapter in $HealthExSvrObj.OSVersion.NetworkAdapters)
            {
                $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_Name_$($i) -Value $adapter.Name
                $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_Description_$($i) -Value $adapter.Description

                if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
                {
                    if((New-TimeSpan -Start (Get-Date) -End $adapter.DriverDate).Days -lt [int]-365)
                    {
                        $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_Driver_$($i) -Value "Outdated (>1 Year Old)"
                    }
                    $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_DriverDate_$($i) -Value $adapter.DriverDate
                    $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_DriverVersion_$($i) -Value $adapter.DriverVersion
                    $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_LinkSpeed_$($i) -Value $adapter.LinkSpeed
                }
                else
                {
                    $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_LinkSpeed_$($i) -Value "VM - Not Applicable"
                }
                if($adapter.RSSEnabled -eq "NoRSS")
                {
                    $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_RSS_$($i) -Value "NoRSS"
                }
                elseif($adapter.RSSEnabled -eq "True")
                {
                    $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_RSS_$($i) -Value  "Enabled"
                }
                else
                {
                    $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_RSS_$($i) -Value "Disabled"
                }
				
				$i++
            }

               

             
        }
    }
    else
    {
        
        foreach($adapter in $HealthExSvrObj.OSVersion.NetworkAdapters)
        {
			$ServerObject | Add-Member –MemberType NoteProperty –Name NIC_Name_1 -Value $adapter.Name
            $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_Description_1 -Value $adapter.Description
            if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
            {
                $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_LinkSpeed_1 -Value $adapter.LinkSpeed
            }
            else 
            {
                $ServerObject | Add-Member –MemberType NoteProperty –Name NIC_LinkSpeed_1 -Value "VM - Not Applicable"  
            }
        }
        
    }
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        if($HealthExSvrObj.OSVersion.NetworkAdapters.Count -gt 1 -and ($HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::Mailbox -or $HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::MultiRole))
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name E2013MultipleNICs -Value "Yes"
        }
    }

    #######################
    #Processor Information#
    #######################

    $ServerObject | Add-Member –MemberType NoteProperty –Name ProcessorName -Value $HealthExSvrObj.HardwareInfo.Processor.ProcessorName

    #Recommendation by PG is no more than 24 cores (this should include logical with Hyper Threading
    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 24 -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name HyperThreading -Value "Enabled"
        }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name HyperThreading -Value "Disabled"
        }
    }
    elseif($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
    {
        if($HealthExSvrObj.HardwareInfo.Processor.ProcessorName.StartsWith("AMD"))
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name AMD_HyperThreading -Value "Enabled"
        }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name AMD_HyperThreading -Value "Disabled"
        }
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name HyperThreading -Value "Disabled"
    }

    $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfProcessors -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors

    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 24)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfPhysicalCores -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfLogicalProcessors -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfPhysicalCores -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfLogicalProcessors -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors
    }
	if($HealthExSvrObj.HardwareInfo.Model -like "*ProLiant*")
	{
		if($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -eq -1)
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name NUMAGroupSize -Value "Undetermined"
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name NUMAGroupSize -Value "Clustered"
		}
		else
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name NUMAGroupSize -Value "Flat"
		}
	}
	else
	{
		if($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -eq -1)
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name AllProcCoresVisible -Value "Undetermined"
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name AllProcCoresVisible -Value "No"
		}
		else
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name AllProcCoresVisible -Value "Yes"
		}
	}
    if($HealthExSvrObj.HardwareInfo.Processor.ProcessorIsThrottled)
    {
        #We are set correctly at the OS layer
        if($HealthExSvrObj.OSVersion.HighPerformanceSet)
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name ProcessorSpeed -Value "Throttled, Not Power Plan"
        }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name ProcessorSpeed -Value "Throttled, Power Plan"
        }
        $ServerObject | Add-Member –MemberType NoteProperty –Name CurrentProcessorSpeed -Value $HealthExSvrObj.HardwareInfo.Processor.CurrentMegacyclesPerCore
        $ServerObject | Add-Member –MemberType NoteProperty –Name MaxProcessorSpeed -Value $HealthExSvrObj.HardwareInfo.Processor.MaxMegacyclesPerCore
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name MaxMegacyclesPerCore -Value $HealthExSvrObj.HardwareInfo.Processor.MaxMegacyclesPerCore
    }


    #Memory Going to check for greater than 96GB of memory for Exchange 2013
    #The value that we shouldn't be greater than is 103,079,215,104 (96 * 1024 * 1024 * 1024) 
    #Exchange 2016 we are going to check to see if there is over 192 GB https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Ask-the-Perf-Guy-Update-to-scalability-guidance-for-Exchange/ba-p/607260
    #For Exchange 2016 the value that we shouldn't be greater than is 206,158,430,208 (192 * 1024 * 1024 * 1024)
    $totalPhysicalMemory = [System.Math]::Round($HealthExSvrObj.HardwareInfo.TotalMemory / 1024 /1024 /1024) 

    $ServerObject | Add-Member –MemberType NoteProperty –Name TotalPhysicalMemory -Value "$totalPhysicalMemory GB"
	
	if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2016 -and
        $HealthExSvrObj.HardwareInfo.TotalMemory -gt 206158430208)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name E2016MemoryRight -Value $False
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -and
     $HealthExSvrObj.HardwareInfo.TotalMemory -gt 103079215104)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name E2013MemoryRight -Value $False
    }
	else
	{
		$ServerObject | Add-Member –MemberType NoteProperty –Name E2016MemoryRight -Value $True
		$ServerObject | Add-Member –MemberType NoteProperty –Name E2013MemoryRight -Value $True
	}

    ################
	#Service Health#
	################
    #We don't want to run if the server is 2013 CAS role or if the Role = None
    if(-not(($HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::None) -or 
        (($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013) -and 
        ($HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::ClientAccess))))
    {
	    
	    if($HealthExSvrObj.ExchangeInformation.ExchangeServicesNotRunning)
	    {
		    $ServerObject | Add-Member –MemberType NoteProperty –Name ServiceHealth -Value "Impacted"
			$ServerObject | Add-Member –MemberType NoteProperty –Name ServicesImpacted -Value $HealthExSvrObj.ExchangeInformation.ExchangeServicesNotRunning
	    }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name ServiceHealth -Value "Healthy"
        }
    }

    #################
	#TCP/IP Settings#
	#################
    if($HealthExSvrObj.OSVersion.TCPKeepAlive -eq 0)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name TCPKeepAlive -Value "Not Set" 
    }
    elseif($HealthExSvrObj.OSVersion.TCPKeepAlive -lt 900000 -or $HealthExSvrObj.OSVersion.TCPKeepAlive -gt 1800000)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name TCPKeepAlive -Value "Not Optimal"
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name TCPKeepAlive -Value "Optimal"
    }

    ###############################
	#LmCompatibilityLevel Settings#
	###############################
    $ServerObject | Add-Member –MemberType NoteProperty –Name LmCompatibilityLevel -Value $HealthExSvrObj.OSVersion.LmCompat.LmCompatibilityLevel


	##############
	#Hotfix Check#
	##############
    
    #Issue: throws errors 
    <#
    Add-Member : Cannot add a member with the name "Passed" because a member with that name already exists. To overwrite
    the member anyway, add the Force parameter to your command.
    #>
    #if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    #{
        #If((Display-KBHotfixCheck -HealthExSvrObj $HealthExSvrObj) -like "*Installed*")
        #{
       #     $ServerObject | Add-Member –MemberType NoteProperty –Name KB3041832 -Value "Installed"
        #}
    #}


    Write-debug "Building ServersObject " 
	$ServerObject
    

}


Function Get-HealthCheckFilesItemsFromLocation{
    $items = Get-ChildItem $XMLDirectoryPath | Where-Object{$_.Name -like "HealthCheck-*-*.xml"}
    if($items -eq $null)
    {
        Write-Host("Doesn't appear to be any Health Check XML files here....stopping the script")
        exit 
    }
    return $items
}

Function Get-OnlyRecentUniqueServersXMLs {
param(
[Parameter(Mandatory=$true)][array]$FileItems 
)   

    $aObject = @() 
    foreach($item in $FileItems)
    {
        $obj = New-Object PSCustomobject 
        [string]$itemName = $item.Name
        $ServerName = $itemName.Substring(($itemName.IndexOf("-") + 1), ($itemName.LastIndexOf("-") - $itemName.IndexOf("-") - 1))
        $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerName
        $obj | Add-Member -MemberType NoteProperty -Name FileName -Value $itemName
        $obj | Add-Member -MemberType NoteProperty -Name FileObject -Value $item 
        $aObject += $obj
    }

    $grouped = $aObject | Group-Object ServerName 

    $FilePathList = @()
    foreach($gServer in $grouped)
    {
        
        if($gServer.Count -gt 1)
        {
            #going to only use the most current file for this server providing that they are using the newest updated version of Health Check we only need to sort by name
            $groupData = $gServer.Group #because of win2008
            $FilePathList += ($groupData | Sort-Object FileName -Descending | Select-Object -First 1).FileObject.VersionInfo.FileName

        }
        else {
            $FilePathList += ($gServer.Group).FileObject.VersionInfo.FileName
        }
        
    }

    return $FilePathList
}

Function Import-MyData {
param(
[Parameter(Mandatory=$true)][array]$FilePaths
)
    [System.Collections.Generic.List[System.Object]]$myData = New-Object -TypeName System.Collections.Generic.List[System.Object]
    foreach($filePath in $FilePaths)
    {
        $importData = Import-Clixml -Path $filePath
        $myData.Add($importData)
    }
    return $myData
}

Function Build-HtmlServerReport {

    $Files = Get-HealthCheckFilesItemsFromLocation
    $FullPaths = Get-OnlyRecentUniqueServersXMLs $Files
    $ImportData = Import-MyData -FilePaths $FullPaths

    $AllServersOutputObject = @()
    foreach($data in $ImportData)
    {
        $AllServersOutputObject += Build-ServerObject $data
    }
    
    Write-Debug "Building HTML report from AllServersOutputObject" 
	#Write-Debug $AllServersOutputObject 
    
	
	
    $htmlhead="<html>
            <style>
            BODY{font-family: Arial; font-size: 8pt;}
            H1{font-size: 16px;}
            H2{font-size: 14px;}
            H3{font-size: 12px;}
            TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
            TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
            TD{border: 1px solid black; padding: 5px; }
            td.pass{background: #7FFF00;}
            td.warn{background: #FFE600;}
            td.fail{background: #FF0000; color: #ffffff;}
            td.info{background: #85D4FF;}
            </style>
            <body>
            <h1 align=""center"">Exchange Health Checker v$($Script:healthCheckerVersion)</h1>
            <p>This shows a brief overview of known areas of concern. Details about each server are below.</p>
            <p align='center'>Note: KBs that could be missing on the server are not included in this version of the script. Please check this in the .txt file of the Health Checker script results</p>"
    

    $HtmlTableHeader = "<p>
                        <table>
                        <tr>
                        <th>Server Name</th>
                        <th>Virtual Server</th>
                        <th>Hardware Type</th>
                        <th>OS</th>
                        <th>Exchange Version</th>
                        <th>Build Number</th>
                        <th>Build Days Old</th>
                        <th>Server Role</th>
                        <th>Auto Page File</th>
						<th>System Memory</th>
                        <th>Multiple Page Files</th>
                        <th>Page File Size</th>
                        <th>.Net Version</th>
                        <th>Power Plan</th>
                        <th>Hyper-Threading</th>
                        <th>Processor Speed</th>
                        <th>Service Health</th>
                        <th>TCP Keep Alive</th>
                        <th>LmCompatibilityLevel</th>
                        </tr>"
                        
    $ServersHealthHtmlTable = $ServersHealthHtmlTable + $htmltableheader 
    
    $ServersHealthHtmlTable += "<H2>Servers Overview</H2>"
                        
    foreach($ServerArrayItem in $AllServersOutputObject)
    {
        Write-Debug $ServerArrayItem
        $HtmlTableRow = "<tr>"
        $HtmlTableRow += "<td>$($ServerArrayItem.ServerName)</td>"	
        $HtmlTableRow += "<td>$($ServerArrayItem.VirtualServer)</td>"	
        $HtmlTableRow += "<td>$($ServerArrayItem.HardwareType)</td>"	
        $HtmlTableRow += "<td>$($ServerArrayItem.OperatingSystem)</td>"	
        $HtmlTableRow += "<td>$($ServerArrayItem.Exchange)</td>"			
        $HtmlTableRow += "<td>$($ServerArrayItem.BuildNumber)</td>"	
        
        If(!$ServerArrayItem.SupportedExchangeBuild) 
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.BuildDaysOld)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.BuildDaysOld)</td>"
        }

        
        $HtmlTableRow += "<td>$($ServerArrayItem.ServerRole)</td>"	
        
        If($ServerArrayItem.AutoPageFile -eq "Yes")
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.AutoPageFile)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.AutoPageFile)</td>"	
        }
		
		
		If(!$ServerArrayItem.E2013MemoryRight)
        {
            $HtmlTableRow += "<td class=""warn"">$($ServerArrayItem.TotalPhysicalMemory)</td>"	
        }
        ElseIf (!$ServerArrayItem.E2016MemoryRight)
        {
            $HtmlTableRow += "<td class=""warn"">$($ServerArrayItem.TotalPhysicalMemory)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.TotalPhysicalMemory)</td>"	
        }
		
		
                    
        If($ServerArrayItem.MultiplePageFiles -eq "Yes")
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.MultiplePageFiles)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.MultiplePageFiles)</td>"	
        }
        
        If($ServerArrayItem.PagefileSizeSetRight -eq "No")
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.PageFileSize)</td>"	
        }
        ElseIf ($ServerArrayItem.PagefileSizeSetRight -eq "Yes")
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.PageFileSize)</td>"	
        }
        ElseIf (!$ServerArrayItem.PagefileSizeSetRight)
        {
            $HtmlTableRow += "<td class=""warn"">Undetermined</td>"	
        }
        
        $HtmlTableRow += "<td>$($ServerArrayItem.DotNetVersion)</td>"			
        
        If($ServerArrayItem.PowerPlan -ne "High performance")
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.PowerPlan)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.PowerPlan)</td>"	
        }
        
        If($ServerArrayItem.HyperThreading -eq "Yes" -or $ServerArrayItem.AMD_HyperThreading -eq "Yes")
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.HyperThreading)$($ServerArrayItem.AMD_HyperThreading)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.HyperThreading)$($ServerArrayItem.AMD_HyperThreading)</td>"	
        }
        
        If($ServerArrayItem.ProcessorSpeed -like "Throttled*")
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.MaxProcessorSpeed)/$($ServerArrayItem.CurrentProcessorSpeed)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.MaxMegacyclesPerCore)</td>"	
        }
        
        If($ServerArrayItem.ServiceHealth -like "Impacted*")
        {
            $HtmlTableRow += "<td class=""fail"">Impacted</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>Healthy</td>"	
        }
        
        If($ServerArrayItem.TCPKeepAlive -eq "Not Optimal")
        {
            $HtmlTableRow += "<td class=""warn"">$($ServerArrayItem.TCPKeepAlive)</td>"	
        }
		ElseIf($ServerArrayItem.TCPKeepAlive -eq "Not Set")
        {
            $HtmlTableRow += "<td class=""fail"">$($ServerArrayItem.TCPKeepAlive)</td>"	
        }
        Else
        {
            $HtmlTableRow += "<td>$($ServerArrayItem.TCPKeepAlive)</td>"	
        }
        
        $HtmlTableRow += "<td>$($ServerArrayItem.LmCompatibilityLevel)</td>"	

        $HtmlTableRow += "</tr>"
                    
                    
        $ServersHealthHtmlTable = $ServersHealthHtmlTable + $htmltablerow
        
    }
    
    $ServersHealthHtmlTable += "</table></p>"
    
    $WarningsErrorsHtmlTable += "<H2>Warnings/Errors in your environment.</H2><table>"
    
    If($AllServersOutputObject.PowerPlanSetRight -contains $False)
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""fail"">Power Plan</td><td>Error: High Performance Power Plan is recommended</td></tr>"
	}	
	If($AllServersOutputObject.SupportedExchangeBuild -contains $False)
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""fail"">Old Build</td><td>Error: Out of date Cumulative Update detected. Please upgrade to one of the two most recently released Cumulative Updates.</td></tr>"
	}
	If($AllServersOutputObject.TCPKeepAlive -contains "Not Set")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""fail"">TCP Keep Alive</td><td>Error: The TCP KeepAliveTime value is not specified in the registry.  Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration.  To avoid issues, add the KeepAliveTime REG_DWORD entry under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters and set it to a value between 900000 and 1800000 decimal.  You want to ensure that the TCP idle timeout value gets higher as you go out from Exchange, not lower.  For example if the Exchange server has a value of 30 minutes, the Load Balancer could have an idle timeout of 35 minutes, and the firewall could have an idle timeout of 40 minutes.  Please note that this change will require a restart of the system.  Refer to the sections `"CAS Configuration`" and `"Load Balancer Configuration`" in this blog post for more details:  https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792</td></tr>"	
	}
	
	If($AllServersOutputObject.TCPKeepAlive -contains "Not Optimal")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""warn"">TCP Keep Alive</td><td>Warning: The TCP KeepAliveTime value is not configured optimally. This can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration. To avoid issues, set the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime registry entry to a value between 15 and 30 minutes (900000 and 1800000 decimal).  You want to ensure that the TCP idle timeout gets higher as you go out from Exchange, not lower.  For example if the Exchange server has a value of 30 minutes, the Load Balancer could have an idle timeout of 35 minutes, and the firewall could have an idle timeout of 40 minutes.  Please note that this change will require a restart of the system.  Refer to the sections `"CAS Configuration`" and `"Load Balancer Configuration`" in this blog post for more details:  https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792</td></tr>"	
	}
	
	If($AllServersOutputObject.PagefileSizeSetRight -contains "No")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""fail"">Pagefile Size</td><td>Page set incorrectly detected. See https://docs.microsoft.com/en-us/previous-versions/office/exchange-server-analyzer/cc431357(v=exchg.80) - Please double check page file setting, as WMI Object Win32_ComputerSystem doesn't report the best value for total memory available.</td></tr>"
	}

    If($AllServersOutputObject.VirtualServer -contains "Yes")
    {
        $WarningsErrorsHtmlTable += "<tr><td class=""warn"">Virtual Servers</td><td>$($VirtualizationWarning)</td></tr>" 
    }

	If($AllServersOutputObject.E2013MultipleNICs -contains "Yes")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""Warn"">Multiple NICs</td><td>Multiple active network adapters detected. Exchange 2013 or greater may not need separate adapters for MAPI and replication traffic.  For details please refer to https://docs.microsoft.com/en-us/exchange/planning-for-high-availability-and-site-resilience-exchange-2013-help#NR</td></tr>"
	}
	
	$a = ($ServerArrayItem.NumberNICs)
	 while($a -ge 1)
	 {
		$rss = "NIC_RSS_{0}" -f $a 
		
		If($AllServersOutputObject.$rss -contains "Disabled")
		{
			$WarningsErrorsHtmlTable += "<tr><td class=""Warn"">RSS</td><td>Enabling RSS is recommended.</td></tr>"
			break;
		}	
		ElseIf($AllServersOutputObject.$rss -contains "NoRSS")
		{
			$WarningsErrorsHtmlTable += "<tr><td class=""Warn"">RSS</td><td>Enabling RSS is recommended.</td></tr>"
			break;
		}	
		
		$a--
	 }
	 
	If($AllServersOutputObject.NUMAGroupSize -contains "Undetermined")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""Warn"">NUMA Group Size Optimization</td><td>Unable to determine --- Warning: If this is set to Clustered, this can cause multiple types of issues on the server</td></tr>"
	}
	ElseIf($AllServersOutputObject.NUMAGroupSize -contains "Clustered")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""fail"">NUMA Group Size Optimization</td><td>BIOS Set to Clustered --- Error: This setting should be set to Flat. By having this set to Clustered, we will see multiple different types of issues.</td></tr>"
	}
	
	If($AllServersOutputObject.AllProcCoresVisible -contains "Undetermined")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""Warn"">All Processor Cores Visible</td><td>Unable to determine --- Warning: If we aren't able to see all processor cores from Exchange, we could see performance related issues.</td></tr>"
	}
	ElseIf($AllServersOutputObject.AllProcCoresVisible -contains "No")
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""fail"">All Processor Cores Visible</td><td>Not all Processor Cores are visible to Exchange and this will cause a performance impact</td></tr>"
	}
	
	If($AllServersOutputObject.E2016MemoryRight -contains $False)
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""Warn"">Exchange 2016 Memory</td><td>Memory greater than 192GB. We recommend for the best performance to be scaled at or below 192 GB of Memory.</td></tr>"
	}
	
	If($AllServersOutputObject.E2013MemoryRight -contains $False)
	{
		$WarningsErrorsHtmlTable += "<tr><td class=""Warn"">Exchange 2013 Memory</td><td>Memory greater than 96GB. We recommend for the best performance to be scaled at or below 96GB of Memory. However, having higher memory than this has yet to be linked directly to a MAJOR performance issue of a server.</td></tr>"
	}	
	
    $WarningsErrorsHtmlTable += "</table>"

	
    $ServerDetailsHtmlTable += "<p><H2>Server Details</H2><table>"
    
    Foreach($ServerArrayItem in $AllServersOutputObject)
    {

        $ServerDetailsHtmlTable += "<tr><th>Server Name</th><th>$($ServerArrayItem.ServerName)</th></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Manufacturer</td><td>$($ServerArrayItem.Manufacturer)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Model</td><td>$($ServerArrayItem.Model)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Hardware Type</td><td>$($ServerArrayItem.HardwareType)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Operating System</td><td>$($ServerArrayItem.OperatingSystem)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Exchange</td><td>$($ServerArrayItem.Exchange)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Build Number</td><td>$($ServerArrayItem.BuildNumber)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Server Role</td><td>$($ServerArrayItem.ServerRole)</td></tr>"
		$ServerDetailsHtmlTable += "<tr><td>System Memory</td><td>$($ServerArrayItem.TotalPhysicalMemory)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Page File Size</td><td>$($ServerArrayItem.PagefileSize)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>.Net Version Installed</td><td>$($ServerArrayItem.DotNetVersion)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>HTTP Proxy</td><td>$($ServerArrayItem.HTTPProxy)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Processor</td><td>$($ServerArrayItem.ProcessorName)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Number of Processors</td><td>$($ServerArrayItem.NumberOfProcessors)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Logical/Physical Cores</td><td>$($ServerArrayItem.NumberOfLogicalProcessors)/$($ServerArrayItem.NumberOfPhysicalCores)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Max Speed Per Core</td><td>$($ServerArrayItem.MaxMegacyclesPerCore)</td></tr>"
		$ServerDetailsHtmlTable += "<tr><td>NUMA Group Size</td><td>$($ServerArrayItem.NUMAGroupSize)</td></tr>"
		$ServerDetailsHtmlTable += "<tr><td>All Procs Visible</td><td>$($ServerArrayItem.AllProcCoresVisible)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>System Memory</td><td>$($ServerArrayItem.TotalPhysicalMemory)</td></tr>"
		$ServerDetailsHtmlTable += "<tr><td>Multiple NICs</td><td>$($ServerArrayItem.E2013MultipleNICs)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Services Down</td><td>$($ServerArrayItem.ServicesImpacted)</td></tr>"
		
		#NIC 
		$a = ($ServerArrayItem.NumberNICs)
		 while($a -ge 1)
		 {
            $name = "NIC_Name_{0}" -f $a 
		    $ServerDetailsHtmlTable += "<tr><td>NIC Name</td><td>$($ServerArrayItem.$name)</td></tr>"
			$description = "NIC_Description_{0}" -f $a 
		    $ServerDetailsHtmlTable += "<tr><td>NIC Description</td><td>$($ServerArrayItem.$description)</td></tr>"
			$driver = "NIC_Driver_{0}" -f $a 
		    $ServerDetailsHtmlTable += "<tr><td>NIC Driver</td><td>$($ServerArrayItem.$driver)</td></tr>"
			$linkspeed = "NIC_LinkSpeed_{0}" -f $a 
		    $ServerDetailsHtmlTable += "<tr><td>NIC LinkSpeed</td><td>$($ServerArrayItem.$linkspeed)</td></tr>"
			$rss = "NIC_RSS_{0}" -f $a 
		    $ServerDetailsHtmlTable += "<tr><td>RSS</td><td>$($ServerArrayItem.$rss)</td></tr>"
			$a--
		 }
		 
    }
    
    $ServerDetailsHtmlTable += "</table></p>"
    
    $htmltail = "</body>
    </html>"

    $htmlreport = $htmlhead  + $ServersHealthHtmlTable + $WarningsErrorsHtmlTable + $ServerDetailsHtmlTable  + $htmltail
    
    $htmlreport | Out-File $HtmlReportFile -Encoding UTF8
}


##############################################################
#
#           DC to Exchange cores Report Functions 
#
##############################################################

Function Get-ComputerCoresObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-ComputerCoresObject")
    Write-VerboseOutput("Passed: {0}" -f $Machine_Name)

    $returnObj = New-Object pscustomobject 
    $returnObj | Add-Member -MemberType NoteProperty -Name Error -Value $false
    $returnObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Machine_Name
    $returnObj | Add-Member -MemberType NoteProperty -Name NumberOfCores -Value ([int]::empty)
    $returnObj | Add-Member -MemberType NoteProperty -Name Exception -Value ([string]::empty)
    $returnObj | Add-Member -MemberType NoteProperty -Name ExceptionType -Value ([string]::empty)
    try {
        $wmi_obj_processor = Get-WmiObject -Class Win32_Processor -ComputerName $Machine_Name

        foreach($processor in $wmi_obj_processor)
        {
            $returnObj.NumberOfCores +=$processor.NumberOfCores
        }
        
        Write-Grey("Server {0} Cores: {1}" -f $Machine_Name, $returnObj.NumberOfCores)
    }
    catch {
        Invoke-CatchActions
        $thisError = $Error[0]
        if($thisError.Exception.Gettype().FullName -eq "System.UnauthorizedAccessException")
        {
            Write-Yellow("Unable to get processor information from server {0}. You do not have the correct permissions to get this data from that server. Exception: {1}" -f $Machine_Name, $thisError.ToString())
        }
        else 
        {
            Write-Yellow("Unable to get processor information from server {0}. Reason: {1}" -f $Machine_Name, $thisError.ToString())
        }
        $returnObj.Exception = $thisError.ToString() 
        $returnObj.ExceptionType = $thisError.Exception.Gettype().FullName
        $returnObj.Error = $true
    }
    
    return $returnObj
}

Function Get-ExchangeDCCoreRatio {

    Set-ScriptLogFileLocation -FileName "HealthCheck-ExchangeDCCoreRatio"
    Write-VerboseOutput("Calling: Get-ExchangeDCCoreRatio")
    Write-Grey("Exchange Server Health Checker Report - AD GC Core to Exchange Server Core Ratio - v{0}" -f $healthCheckerVersion)
    $coreRatioObj = New-Object pscustomobject 
    try 
    {
        Write-VerboseOutput("Attempting to load Active Directory Module")
        Import-Module ActiveDirectory 
        Write-VerboseOutput("Successfully loaded")
    }
    catch 
    {
        Write-Red("Failed to load Active Directory Module. Stopping the script")
        exit 
    }

    $ADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
    [array]$DomainControllers = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter {isGlobalCatalog -eq $true -and Site -eq $ADSite} -Server $_ }

    [System.Collections.Generic.List[System.Object]]$DCList = New-Object System.Collections.Generic.List[System.Object]
    $DCCoresTotal = 0
    Write-Break
    Write-Grey("Collecting data for the Active Directory Environment in Site: {0}" -f $ADSite)
    $iFailedDCs = 0 
    foreach($DC in $DomainControllers)
    {
        $DCCoreObj = Get-ComputerCoresObject -Machine_Name $DC.Name 
        $DCList.Add($DCCoreObj)
        if(-not ($DCCoreObj.Error))
        {
            $DCCoresTotal += $DCCoreObj.NumberOfCores
        }
        else 
        {
            $iFailedDCs++     
        } 
    }

    $coreRatioObj | Add-Member -MemberType NoteProperty -Name DCList -Value $DCList
    if($iFailedDCs -eq $DomainControllers.count)
    {
        #Core count is going to be 0, no point to continue the script
        Write-Red("Failed to collect data from your DC servers in site {0}." -f $ADSite)
        Write-Yellow("Because we can't determine the ratio, we are going to stop the script. Verify with the above errors as to why we failed to collect the data and address the issue, then run the script again.")
        exit 
    }

    [array]$ExchangeServers = Get-ExchangeServer | Where-Object {$_.Site -match $ADSite}
    $EXCoresTotal = 0
    [System.Collections.Generic.List[System.Object]]$EXList = New-Object System.Collections.Generic.List[System.Object]
    Write-Break
    Write-Grey("Collecting data for the Exchange Environment in Site: {0}" -f $ADSite)
    foreach($svr in $ExchangeServers)
    {
        $EXCoreObj = Get-ComputerCoresObject -Machine_Name $svr.Name 
        $EXList.Add($EXCoreObj)
        if(-not ($EXCoreObj.Error))
        {
            $EXCoresTotal += $EXCoreObj.NumberOfCores
        }
    }
    $coreRatioObj | Add-Member -MemberType NoteProperty -Name ExList -Value $EXList

    Write-Break
    $CoreRatio = $EXCoresTotal / $DCCoresTotal
    Write-Grey("Total DC/GC Cores: {0}" -f $DCCoresTotal)
    Write-Grey("Total Exchange Cores: {0}" -f $EXCoresTotal)
    Write-Grey("You have {0} Exchange Cores for every Domain Controller Global Catalog Server Core" -f $CoreRatio)
    if($CoreRatio -gt 8)
    {
        Write-Break
        Write-Red("Your Exchange to Active Directory Global Catalog server's core ratio does not meet the recommended guidelines of 8:1")
        Write-Red("Recommended guidelines for Exchange 2013/2016 for every 8 Exchange cores you want at least 1 Active Directory Global Catalog Core.")
        Write-Yellow("Documentation:")
        Write-Yellow("`thttps://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Ask-the-Perf-Guy-Sizing-Exchange-2013-Deployments/ba-p/594229")
        Write-Yellow("`thttps://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#active-directory")

    }
    else 
    {
        Write-Break
        Write-Green("Your Exchange Environment meets the recommended core ratio of 8:1 guidelines.")    
    }
    
    $XMLDirectoryPath = $OutputFullPath.Replace(".txt",".xml")
    $coreRatioObj | Export-Clixml $XMLDirectoryPath 
    Write-Grey("Output file written to {0}" -f $OutputFullPath)
    Write-Grey("Output XML Object file written to {0}" -f $XMLDirectoryPath)

}

Function Set-ScriptLogFileLocation {
param(
[Parameter(Mandatory=$true)][string]$FileName,
[Parameter(Mandatory=$false)][bool]$IncludeServerName = $false 
)
    $endName = "-{0}.txt" -f $dateTimeStringFormat
    if($IncludeServerName)
    {
        $endName = "-{0}{1}" -f $Script:Server, $endName
    }
    
    $Script:OutputFullPath = "{0}\{1}{2}" -f $OutputFilePath, $FileName, $endName
    $Script:OutXmlFullPath =  $Script:OutputFullPath.Replace(".txt",".xml")
    Load-ExShell
}

Function Get-ErrorsThatOccurred {

    if($Error.Count -gt $Script:ErrorStartCount)
    {
        Write-Grey(" "); Write-Grey(" ")
        Function Write-Errors {
            $index = 0; 
            "Errors that occurred that wasn't handled" | Out-File ($Script:OutputFullPath) -Append
            while($index -lt ($Error.Count - $Script:ErrorStartCount))
            {
                #for 2008R2 can't use .Contains on an array object, need to do something else. 
                $goodError = $false 
                foreach($okayErrors in $Script:ErrorsExcluded)
                {
                    if($okayErrors.Equals($Error[$index]))
                    {
                        $goodError = $true 
                        break
                    }
                }
                if(!($goodError))
                {
                    $Error[$index] | Out-File ($Script:OutputFullPath) -Append
                }
                $index++
            }
            Write-Grey(" "); Write-Grey(" ")
            "Errors that were handled" | Out-File ($Script:OutputFullPath) -Append
            foreach($okayErrors in $Script:ErrorsExcluded)
            {
                $okayErrors | Out-File ($Script:OutputFullPath) -Append
            }
        }

        if(($Error.Count - $Script:ErrorStartCount) -ne $Script:ErrorsExcludedCount)
        {
            Write-Red("There appears to have been some errors in the script. To assist with debugging of the script, please RE-RUN the script with -Verbose send the .txt and .xml file to ExToolsFeedback@microsoft.com.")
	        Write-Errors
        }
        elseif($Script:VerboseEnabled)
        {
            Write-VerboseOutput("All errors that occurred were in try catch blocks and was handled correctly.")
	        Write-Errors
        }
    }
    else 
    {
        Write-VerboseOutput("No errors occurred in the script.")
    }
}

Function Write-HealthCheckerVersion {
    
    $currentVersion = Test-ScriptVersion -ApiUri "api.github.com" -RepoOwner "dpaulson45" -RepoName "HealthChecker" -CurrentVersion $healthCheckerVersion -DaysOldLimit 90
    if($currentVersion)
    {
        Write-Green("Exchange Health Checker version {0}" -f $healthCheckerVersion)
    }
    else 
    {
        Write-Yellow("Exchange Health Checker version {0}. This script is probably outdated. Please verify before relying on the results." -f $healthCheckerVersion)
    }

}

Function LoadBalancingMain {

    Set-ScriptLogFileLocation -FileName "LoadBalancingReport" 
    Write-HealthCheckerVersion
    Write-Green("Client Access Load Balancing Report on " + $date)
    Get-CASLoadBalancingReport
    Write-Grey("Output file written to " + $OutputFullPath)
    Get-ErrorsThatOccurred
    Write-Break
    Write-Break

}
Function HealthCheckerMain {

    Set-ScriptLogFileLocation -FileName "HealthCheck" -IncludeServerName $true 
    Write-HealthCheckerVersion
    $HealthObject = Build-HealthExchangeServerObject $Server
    Display-ResultsToScreen $healthObject
    Get-ErrorsThatOccurred
    $HealthObject | Export-Clixml -Path $OutXmlFullPath -Encoding UTF8 -Depth 5
    Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
    Write-Grey("Exported Data Object Written to {0} " -f $Script:OutXmlFullPath)
}
Function Main {
    
    if(-not (Is-Admin))
	{
		Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Mangement Shell as an Administrator." 
		sleep 2;
		exit
    }

    $Script:ErrorStartCount = $Error.Count #useful for debugging 
    $Script:ErrorsExcludedCount = 0 #this is a way to determine if the only errors occurred were in try catch blocks. If there is a combination of errors in and out, then i will just dump it all out to avoid complex issues. 
    $Script:ErrorsExcluded = @() 
    $Script:date = (Get-Date)
    $Script:dateTimeStringFormat = $date.ToString("yyyyMMddHHmmss")
    
    if($BuildHtmlServersReport)
    {
        Set-ScriptLogFileLocation -FileName "HealthChecker-HTMLServerReport" 
        Build-HtmlServerReport
        Get-ErrorsThatOccurred
        sleep 2;
        exit
    }

    if((Test-Path $OutputFilePath) -eq $false)
    {
        Write-Host "Invalid value specified for -OutputFilePath." -ForegroundColor Red
        exit 
    }

    if($LoadBalancingReport)
    {
        LoadBalancingMain
        exit
    }

    if($DCCoreRatio)
    {
        $oldErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        try 
        {
            Get-ExchangeDCCoreRatio
            Get-ErrorsThatOccurred
        }
        finally
        {
            $ErrorActionPreference = $oldErrorAction
            exit 
        }
    }

	if($MailboxReport)
	{
        Set-ScriptLogFileLocation -FileName "HealthCheck-MailboxReport" -IncludeServerName $true 
        Get-MailboxDatabaseAndMailboxStatistics -Machine_Name $Server
        Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
        Get-ErrorsThatOccurred
        exit
	}

	HealthCheckerMain
}

try 
{
    Main 
}
finally 
{
    if($Script:VerboseEnabled)
    {
        $Host.PrivateData.VerboseForegroundColor = $VerboseForeground
    }
}
