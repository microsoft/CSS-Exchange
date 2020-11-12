<#
.NOTES
	Name: HealthChecker.ps1
	Original Author: Marc Nivens
    Author: David Paulson
    Contributor: Jason Shinbaum, Michael Schatte, Lukas Sassl
	Requires: Exchange Management Shell and administrator rights on the target Exchange
	server as well as the local machine.
    Major Release History:
        11/10/2020 - Initial Public Release of version 3.
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
[Parameter(Mandatory=$false,ParameterSetName="AnalyzeDataOnly")]
    [ValidateScript({-not $_.ToString().EndsWith('\')})][string]$XMLDirectoryPath = ".",
[Parameter(Mandatory=$false,ParameterSetName="HTMLReport")]
    [switch]$BuildHtmlServersReport,
[Parameter(Mandatory=$false,ParameterSetName="HTMLReport")]
    [string]$HtmlReportFile="ExchangeAllServersReport.html",
[Parameter(Mandatory=$false,ParameterSetName="DCCoreReport")]
    [switch]$DCCoreRatio,
[Parameter(Mandatory=$false,ParameterSetName="AnalyzeDataOnly")]
    [switch]$AnalyzeDataOnly,
[Parameter(Mandatory=$false)][switch]$SaveDebugLog
)

$healthCheckerVersion = "3.0.0"
$VirtualizationWarning = @"
Virtual Machine detected.  Certain settings about the host hardware cannot be detected from the virtual machine.  Verify on the VM Host that: 

    - There is no more than a 1:1 Physical Core to Virtual CPU ratio (no oversubscribing)
    - If Hyper-Threading is enabled do NOT count Hyper-Threaded cores as physical cores
    - Do not oversubscribe memory or use dynamic memory allocation
    
Although Exchange technically supports up to a 2:1 physical core to vCPU ratio, a 1:1 ratio is strongly recommended for performance reasons.  Certain third party Hyper-Visors such as VMWare have their own guidance.  

VMWare recommends a 1:1 ratio.  Their guidance can be found at https://www.vmware.com/files/pdf/Exchange_2013_on_VMware_Best_Practices_Guide.pdf.  
Related specifically to VMWare, if you notice you are experiencing packet loss on your VMXNET3 adapter, you may want to review the following article from VMWare:  http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2039495. 

For further details, please review the virtualization recommendations on Microsoft Docs at the following locations: 
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

try{
#Enums and custom data types 
Add-Type -TypeDefinition @"
using System;
using System.Collections;
    namespace HealthChecker
    {
        public class HealthCheckerExchangeServer
        {
            public string ServerName;        //String of the server that we are working with 
            public HardwareInformation HardwareInformation;  // Hardware Object Information 
            public OperatingSystemInformation  OSInformation; // OS Version Object Information 
            public ExchangeInformation ExchangeInformation; //Detailed Exchange Information 
            public string HealthCheckerVersion; //To determine the version of the script on the object.
        }
    
        // ExchangeInformation 
        public class ExchangeInformation 
        {
            public ExchangeBuildInformation BuildInformation = new ExchangeBuildInformation();   //Exchange build information
            public object GetExchangeServer;      //Stores the Get-ExchangeServer Object 
            public ExchangeNetFrameworkInformation NETFramework = new ExchangeNetFrameworkInformation(); 
            public bool MapiHttpEnabled; //Stored from organization config 
            public string ExchangeServicesNotRunning; //Contains the Exchange services not running by Test-ServiceHealth 
            public Hashtable ApplicationPools;
            public ExchangeRegistryValues RegistryValues = new ExchangeRegistryValues();
            public ExchangeServerMaintenance ServerMaintenance;
        }
    
        public class ExchangeBuildInformation
        {
            public ExchangeServerRole ServerRole; //Roles that are currently set and installed. 
            public ExchangeMajorVersion MajorVersion; //Exchange Version (Exchange 2010/2013/2019)
            public ExchangeCULevel CU;             // Exchange CU Level 
            public string FriendlyName;     //Exchange Friendly Name is provided
            public string BuildNumber;      //Exchange Build Number 
            public string ReleaseDate;      // Exchange release date for which the CU they are currently on
            public bool SupportedBuild;     //Determines if we are within the correct build of Exchange.
            public object ExchangeSetup;    //Stores the Get-Command ExSetup object
            public System.Array KBsInstalled;  //Stored object IU or Security KB fixes 
        }
    
        public class ExchangeNetFrameworkInformation
        {
            public NetMajorVersion MinSupportedVersion; //Min Supported .NET Framework version
            public NetMajorVersion MaxSupportedVersion; //Max (Recommended) Supported .NET version. 
            public bool OnRecommendedVersion; //RecommendedNetVersion Info includes all the factors. Windows Version & CU. 
            public string DisplayWording; //Display if we are in Support or not
        }

        public class ExchangeServerMaintenance
        {
            public System.Array InactiveComponents;
            public object GetServerComponentState;
            public object GetClusterNode;
            public object GetMailboxServer;
        }
    
        //enum for CU levels of Exchange
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
            CU22,
            CU23
        }
    
        //enum for the server roles that the computer is 
        public enum ExchangeServerRole
        {
            MultiRole,
            Mailbox,
            ClientAccess,
            Hub,
            Edge,
            None
        }
    
        //enum for the Exchange version 
        public enum ExchangeMajorVersion
        {
            Unknown,
            Exchange2010,
            Exchange2013,
            Exchange2016,
            Exchange2019
        }

        public class ExchangeRegistryValues
        {
            public int CtsProcessorAffinityPercentage;    //Stores the CtsProcessorAffinityPercentage registry value from HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Search\SystemParameters
        }
        // End ExchangeInformation 
    
        // OperatingSystemInformation
        public class OperatingSystemInformation 
        {
            public OSBuildInformation BuildInformation = new OSBuildInformation(); // contains build information 
            public NetworkInformation NetworkInformation = new NetworkInformation(); //stores network information and settings
            public PowerPlanInformation PowerPlan = new PowerPlanInformation(); //stores the power plan information 
            public PageFileInformation PageFile;             //stores the page file information 
            public LmCompatibilityLevelInformation LmCompatibility; // stores Lm Compatibility Level Information
            public bool ServerPendingReboot; // determines if the server is pending a reboot. TODO: Adjust to contain the registry values that we are looking at. 
            public TimeZoneInformation TimeZone = new TimeZoneInformation();    //stores time zone information 
            public Hashtable TLSSettings;            // stores the TLS settings on the server. 
            public InstalledUpdatesInformation InstalledUpdates = new InstalledUpdatesInformation();  //store the install update 
            public ServerBootUpInformation ServerBootUp = new ServerBootUpInformation();   // stores the server boot up time information 
            public System.Array VcRedistributable;            //stores the Visual C++ Redistributable
            public OSNetFrameworkInformation NETFramework = new OSNetFrameworkInformation();          //stores OS Net Framework
            public bool CredentialGuardEnabled;
            public OSRegistryValues RegistryValues = new OSRegistryValues();
            public Smb1ServerSettings Smb1ServerSettings = new Smb1ServerSettings();
        }
    
        public class OSBuildInformation 
        {
            public OSServerVersion MajorVersion; //OS Major Version 
            public string VersionBuild;           //hold the build number
            public string FriendlyName;           //string holder of the Windows Server friendly name
            public object OperatingSystem;        // holds Win32_OperatingSystem 
        }
    
        public class NetworkInformation 
        {
            public double TCPKeepAlive;           // value used for the TCP/IP keep alive value in the registry 
            public double RpcMinConnectionTimeout;  //holds the value for the RPC minimum connection timeout. 
            public string HttpProxy;                // holds the setting for HttpProxy if one is set. 
            public object PacketsReceivedDiscarded;   //hold all the packets received discarded on the server. 
            public double IPv6DisabledComponents;    //value stored in the registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents 
            public bool IPv6DisabledOnNICs;          //value that determines if we have IPv6 disabled on some NICs or not.
            public System.Array NetworkAdapters;           //stores all the NICs on the servers. 
            public string PnPCapabilities;      //Value from PnPCapabilities registry
            public bool SleepyNicDisabled;     //If the NIC can be in power saver mode by the OS.
        }
    
        public class PowerPlanInformation
        {
            public bool HighPerformanceSet;      // If the power plan is High Performance
            public string PowerPlanSetting;      //value for the power plan that is set
            public object PowerPlan;            //object to store the power plan information
        }
    
        public class PageFileInformation
        {
            public object PageFile;       //store the information that we got for the page file
            public double MaxPageSize;    //holds the information of what our page file is set to
        }

        public class OSRegistryValues
        {
            public int CurrentVersionUbr; // stores SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR
            public int LanManServerDisabledCompression; // stores SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\DisabledCompression
        }
    
        public class LmCompatibilityLevelInformation 
        {
            public int RegistryValue;       //The LmCompatibilityLevel for the server (INT 1 - 5)
            public string Description;      //description of the LmCompat that the server is set to
        }
    
        public class TimeZoneInformation
        {
            public string CurrentTimeZone; //stores the value for the current time zone of the server. 
            public int DynamicDaylightTimeDisabled; // the registry value for DynamicDaylightTimeDisabled.
            public string TimeZoneKeyName; // the registry value TimeZoneKeyName.
            public string StandardStart;   // the registry value for StandardStart.
            public string DaylightStart;   // the registry value for DaylightStart.
            public bool DstIssueDetected;  // Determines if there is a high chance of an issue.
            public System.Array ActionsToTake; //array of verbage of the issues detected. 
        }
    
        public class ServerRebootInformation 
        {
            public bool PendingFileRenameOperations;            //bool "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\" item PendingFileRenameOperations.
            public object SccmReboot;                           // object to store CimMethod for class name CCM_ClientUtilities
            public bool SccmRebootPending;                      // SccmReboot has either PendingReboot or IsHardRebootPending is set to true.
            public bool ComponentBasedServicingPendingReboot;   // bool HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending
            public bool AutoUpdatePendingReboot;                // bool HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
            public bool PendingReboot;                         // bool if reboot types are set to true
        }
    
        public class InstalledUpdatesInformation
        {
            public System.Array HotFixes;     //array to keep all the hotfixes of the server
            public System.Array HotFixInfo;   //object to store hotfix information 
            public System.Array InstalledUpdates; //store the install updates 
        }
    
        public class ServerBootUpInformation
        {
            public string Days;
            public string Hours; 
            public string Minutes; 
            public string Seconds; 
        }
    
        //enum for the dword values of the latest supported VC++ redistributable releases
        //https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads
        public enum VCRedistVersion
        {
            Unknown = 0,
            VCRedist2012 = 184610406,
            VCRedist2013 = 201367256
        }
    
        public class SoftwareInformation
        {
            public string DisplayName;
            public string DisplayVersion;
            public string InstallDate;
            public int VersionIdentifier;
        }
    
        public class OSNetFrameworkInformation 
        {
            public NetMajorVersion NetMajorVersion; //NetMajorVersion value 
            public string FriendlyName;  //string of the friendly name 
            public int RegistryValue; //store the registry value
            public Hashtable FileInformation; //stores Get-Item information for .NET Framework
        }
    
        //enum for the OSServerVersion that we are
        public enum OSServerVersion
        {
            Unknown,
            Windows2008, 
            Windows2008R2,
            Windows2012,
            Windows2012R2,
            Windows2016,
            Windows2019,
            WindowsCore
        }
    
        //enum for the dword value of the .NET frame 4 that we are on 
        public enum NetMajorVersion 
        {
            Unknown = 0,
            Net4d5 = 378389,
            Net4d5d1 = 378675,
            Net4d5d2 = 379893,
            Net4d5d2wFix = 380035,
            Net4d6 = 393295,
            Net4d6d1 = 394254,
            Net4d6d1wFix = 394294,
            Net4d6d2 = 394802,
            Net4d7 = 460798,
            Net4d7d1 = 461308,
            Net4d7d2 = 461808,
            Net4d8 = 528040
        }

        public class Smb1ServerSettings
        {
            public object RegistryValue;
            public object SmbServerConfiguration;
            public object WindowsFeature;
            public int Smb1Status;
        }
        // End OperatingSystemInformation
            
        // HardwareInformation
        public class HardwareInformation
        {
            public string Manufacturer; //String to display the hardware information 
            public ServerType ServerType; //Enum to determine if the hardware is VMware, HyperV, Physical, or Unknown 
            public double TotalMemory; //Stores the total memory available 
            public object System;   //object to store the system information that we have collected 
            public ProcessorInformation Processor;   //Detailed processor Information 
            public bool AutoPageFile; //True/False if we are using a page file that is being automatically set 
            public string Model; //string to display Model 
        }
    
        //enum for the type of computer that we are
        public enum ServerType
        {
            VMWare,
            AmazonEC2,
            HyperV,
            Physical,
            Unknown
        }
    
        public class ProcessorInformation 
        {
            public string Name;    //String of the processor name 
            public int NumberOfPhysicalCores;    //Number of Physical cores that we have 
            public int NumberOfLogicalCores;  //Number of Logical cores that we have presented to the os 
            public int NumberOfProcessors; //Total number of processors that we have in the system 
            public int MaxMegacyclesPerCore; //Max speed that we can get out of the cores 
            public int CurrentMegacyclesPerCore; //Current speed that we are using the cores at 
            public bool ProcessorIsThrottled;  //True/False if we are throttling our processor 
            public bool DifferentProcessorsDetected; //true/false to detect if we have different processor types detected 
            public bool DifferentProcessorCoreCountDetected; //detect if there are a different number of core counts per Processor CPU socket
            public int EnvironmentProcessorCount; //[system.environment]::processorcount 
            public object ProcessorClassObject;        // object to store the processor information  
        }

        //HTML & display classes
        public class HtmlServerValues
        {
            public System.Array OverviewValues;
            public System.Array ActionItems;   //use HtmlServerActionItemRow
            public System.Array ServerDetails;    // use HtmlServerInformationRow
        }

        public class HtmlServerActionItemRow
        {
            public string Setting;
            public string DetailValue;
            public string RecommendedDetails;
            public string MoreInformation;
            public string Class;
        }

        public class HtmlServerInformationRow
        {
            public string Name;
            public string DetailValue;
            public string Class;
        }

        public class DisplayResultsLineInfo
        {
            public string DisplayValue;
            public string Name;
            public int TabNumber;
            public object TestingValue; //Used for pester testing down the road.
            public string WriteType;

            public string Line
            {
                get
                {
                    if (String.IsNullOrEmpty(this.Name))
                    {
                        return this.DisplayValue;
                    }

                    return String.Concat(this.Name, ": ", this.DisplayValue);
                }
            }
        }

        public class DisplayResultsGroupingKey
        {
            public string Name;
            public int DefaultTabNumber;
            public bool DisplayGroupName;
            public int DisplayOrder;
        }

        public class AnalyzedInformation
        {
            public HealthCheckerExchangeServer HealthCheckerExchangeServer;
            public Hashtable HtmlServerValues = new Hashtable();
            public Hashtable DisplayResults = new Hashtable();
        }
    }
"@ -ErrorAction Stop 
}
catch 
{
    Write-Warning "There was an error trying to add custom classes to the current PowerShell session. You need to close this session and open a new one to have the script properly work."
    exit 
}

##################
#Helper Functions#
##################

#Output functions
function Write-Red($message)
{
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Red
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Yellow($message)
{
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Yellow
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Green($message)
{
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Green
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Grey($message)
{
    Write-DebugLog $message
    Write-Host $message
    $message | Out-File ($OutputFullPath) -Append
}

function Write-VerboseOutput($message)
{
    Write-Verbose $message
    Write-DebugLog $message
    if($Script:VerboseEnabled)
    {
        $message | Out-File ($OutputFullPath) -Append
    }
}

function Write-DebugLog($message)
{
    if(![string]::IsNullOrEmpty($message))
    {
        $Script:Logger.WriteToFileOnly($message)
    }
}

Function Write-Break {
    Write-Host ""
}

#Function Version 1.1
Function Write-HostWriter {
param(
[Parameter(Mandatory=$true)][string]$WriteString 
)
    if($Script:Logger -ne $null)
    {
        $Script:Logger.WriteHost($WriteString)
    }
    elseif($HostFunctionCaller -eq $null)
    {
        Write-Host $WriteString
    }
    else
    {
        &$HostFunctionCaller $WriteString    
    }
}
    
Function Write-VerboseWriter {
param(
[Parameter(Mandatory=$true)][string]$WriteString 
)
    if($VerboseFunctionCaller -eq $null)
    {
            Write-Verbose $WriteString
    }
    else 
    {
        &$VerboseFunctionCaller $WriteString
    }
}

$Script:VerboseFunctionCaller = ${Function:Write-VerboseOutput}

#Function Version 1.0
Function Write-ScriptMethodHostWriter{
param(
[Parameter(Mandatory=$true)][string]$WriteString
)
    if($this.LoggerObject -ne $null)
    {
        $this.LoggerObject.WriteHost($WriteString) 
    }
    elseif($this.HostFunctionCaller -eq $null)
    {
        Write-Host $WriteString
    }
    else 
    {
        $this.HostFunctionCaller($WriteString)
    }
}

#Function Version 1.0
Function Write-ScriptMethodVerboseWriter {
param(
[Parameter(Mandatory=$true)][string]$WriteString
)
    if($this.LoggerObject -ne $null)
    {
        $this.LoggerObject.WriteVerbose($WriteString)
    }
    elseif($this.VerboseFunctionCaller -eq $null -and 
        $this.WriteVerboseData)
    {
        Write-Host $WriteString -ForegroundColor Cyan 
    }
    elseif($this.WriteVerboseData)
    {
        $this.VerboseFunctionCaller($WriteString)
    }
}

Function New-LoggerObject {
[CmdletBinding()]
param(
[Parameter(Mandatory=$false)][string]$LogDirectory = ".",
[Parameter(Mandatory=$false)][string]$LogName = "Script_Logging",
[Parameter(Mandatory=$false)][bool]$EnableDateTime = $true,
[Parameter(Mandatory=$false)][bool]$IncludeDateTimeToFileName = $true,
[Parameter(Mandatory=$false)][int]$MaxFileSizeInMB = 10,
[Parameter(Mandatory=$false)][int]$CheckSizeIntervalMinutes = 10,
[Parameter(Mandatory=$false)][int]$NumberOfLogsToKeep = 10,
[Parameter(Mandatory=$false)][bool]$VerboseEnabled,
[Parameter(Mandatory=$false)][scriptblock]$HostFunctionCaller,
[Parameter(Mandatory=$false)][scriptblock]$VerboseFunctionCaller
)

    #Function Version 1.2
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-ScriptMethodHostWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-ScriptMethodVerboseWriter.ps1
    #>

    ########################
    #
    # Template Functions
    #
    ########################

    Function Write-ToLog {
    param(
    [object]$WriteString,
    [string]$LogLocation
    )
        $WriteString | Out-File ($LogLocation) -Append
    }

    ########################
    #
    # End Template Functions
    #
    ########################


    ########## Parameter Binding Exceptions ##############
    # throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid ParameterName" 
    if($LogDirectory -eq ".")
    {
        $LogDirectory = (Get-Location).Path
    }
    if([string]::IsNullOrEmpty($LogName))
    {
        throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LogName" 
    }
    if(!(Test-Path $LogDirectory))
    {
        throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LogDirectory" 
    }

    $loggerObject = New-Object pscustomobject 
    $loggerObject | Add-Member -MemberType NoteProperty -Name "FileDirectory" -Value $LogDirectory
    $loggerObject | Add-Member -MemberType NoteProperty -Name "FileName" -Value $LogName
    $loggerObject | Add-Member -MemberType NoteProperty -Name "FullPath" -Value $fullLogPath
    $loggerObject | Add-Member -MemberType NoteProperty -Name "InstanceBaseName" -Value ([string]::Empty)
    $loggerObject | Add-Member -MemberType NoteProperty -Name "EnableDateTime" -Value $EnableDateTime
    $loggerObject | Add-Member -MemberType NoteProperty -Name "IncludeDateTimeToFileName" -Value $IncludeDateTimeToFileName
    $loggerObject | Add-Member -MemberType NoteProperty -Name "MaxFileSizeInMB" -Value $MaxFileSizeInMB
    $loggerObject | Add-Member -MemberType NoteProperty -Name "CheckSizeIntervalMinutes" -Value $CheckSizeIntervalMinutes
    $loggerObject | Add-Member -MemberType NoteProperty -Name "NextFileCheckTime" -Value ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
    $loggerObject | Add-Member -MemberType NoteProperty -Name "InstanceNumber" -Value 1
    $loggerObject | Add-Member -MemberType NoteProperty -Name "NumberOfLogsToKeep" -Value $NumberOfLogsToKeep
    $loggerObject | Add-Member -MemberType NoteProperty -Name "WriteVerboseData" -Value $VerboseEnabled
    $loggerObject | Add-Member -MemberType NoteProperty -Name "PreventLogCleanup" -Value $false
    $loggerObject | Add-Member -MemberType ScriptMethod -Name "ToLog" -Value ${Function:Write-ToLog}
    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteHostWriter" -Value ${Function:Write-ScriptMethodHostWriter}
    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteVerboseWriter" -Value ${Function:Write-ScriptMethodVerboseWriter}

    if($HostFunctionCaller -ne $null)
    {
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "HostFunctionCaller" -Value $HostFunctionCaller
    }
    if($VerboseFunctionCaller -ne $null)
    {
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "VerboseFunctionCaller" -Value $VerboseFunctionCaller
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteHost" -Value {
        param(
        [object]$LoggingString
        )
        if($LoggingString -eq $null)
        {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
        }

        if($this.EnableDateTime)
        {
            $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
        }

        $this.WriteHostWriter($LoggingString)
        $this.ToLog($LoggingString, $this.FullPath)
        $this.LogUpKeep()
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteVerbose" -Value {
        param(
        [object]$LoggingString
        )
        if($LoggingString -eq $null)
        {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
        }

        if($this.EnableDateTime)
        {
            $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
        }
        $this.WriteVerboseWriter($LoggingString)
        $this.ToLog($LoggingString, $this.FullPath)
        $this.LogUpKeep() 

    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteToFileOnly" -Value {
        param(
        [object]$LoggingString
        )
        if($LoggingString -eq $null)
        {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
        }

        if($this.EnableDateTime)
        {
            $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
        }
        $this.ToLog($LoggingString, $this.FullPath)
        $this.LogUpKeep()
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "UpdateFileLocation" -Value{

        if($this.FullPath -eq $null)
        {
            if($this.IncludeDateTimeToFileName)
            {
                $this.InstanceBaseName = "{0}_{1}" -f $this.FileName, ((Get-Date).ToString('yyyyMMddHHmmss'))
                $this.FullPath = "{0}\{1}.txt" -f $this.FileDirectory, $this.InstanceBaseName
            }
            else 
            {
                $this.InstanceBaseName = "{0}" -f $this.FileName
                $this.FullPath = "{0}\{1}.txt" -f $this.FileDirectory, $this.InstanceBaseName
            }
        }
        else 
        {

            do{
                $this.FullPath = "{0}\{1}_{2}.txt" -f $this.FileDirectory, $this.InstanceBaseName, $this.InstanceNumber
                $this.InstanceNumber++
            }while(Test-Path $this.FullPath)
            $this.WriteVerbose("Updated to New Log")
        }
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "LogUpKeep" -Value {

        if($this.NextFileCheckTime -gt [System.DateTime]::Now)
        {
            return 
        }
        $this.NextFileCheckTime = (Get-Date).AddMinutes($this.CheckSizeIntervalMinutes)
        $this.CheckFileSize()
        $this.CheckNumberOfFiles()
        $this.WriteVerbose("Did Log Object Up Keep")
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "CheckFileSize" -Value {

        $item = Get-ChildItem $this.FullPath
        if(($item.Length / 1MB) -gt $this.MaxFileSizeInMB)
        {
            $this.UpdateFileLocation()
        }
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "CheckNumberOfFiles" -Value {

        $filter = "{0}*" -f $this.InstanceBaseName
        $items = Get-ChildItem -Path $this.FileDirectory | ?{$_.Name -like $filter}
        if($items.Count -gt $this.NumberOfLogsToKeep)
        {
            do{
                $items | Sort-Object LastWriteTime | Select -First 1 | Remove-Item -Force 
                $items = Get-ChildItem -Path $this.FileDirectory | ?{$_.Name -like $filter}
            }while($items.Count -gt $this.NumberOfLogsToKeep)
        }
    }

    $loggerObject | Add-Member -MemberType ScriptMethod -Name "RemoveLatestLogFile" -Value {

        if(!$this.PreventLogCleanup)
        {
            $item = Get-ChildItem $this.FullPath
            Remove-Item $item -Force
        }
    }

    $loggerObject.UpdateFileLocation()
    try 
    {
        "[{0}] : Creating a new logger instance" -f [System.DateTime]::Now | Out-File ($loggerObject.FullPath) -Append
    }
    catch 
    {
        throw 
    }

    return $loggerObject
}

$Script:Logger = New-LoggerObject -LogName "HealthChecker-Debug" -LogDirectory $OutputFilePath -VerboseEnabled $true -EnableDateTime $false -ErrorAction SilentlyContinue

############################################################
############################################################

Function Invoke-CatchActions{
param(
    [object]$CopyThisError
)

    Write-VerboseOutput("Calling: Invoke-CatchActions")
    $Script:ErrorsExcludedCount++
    if($CopyThisError -eq $null)
    {
        $Script:ErrorsExcluded += $Error[0]
    }
    else 
    {
        $Script:ErrorsExcluded += $CopyThisError
    }
}

Function Test-IsCurrentVersion {
param(
[Parameter(Mandatory=$true)][string]$CurrentVersion,
[Parameter(Mandatory=$true)][string]$TestingVersion
)
    Write-VerboseOutput("Calling: Test-IsCurrentVersion")
    $splitCurrentVersion = $CurrentVersion.Split(".")
    $splitTestingVersion = $TestingVersion.Split(".")
    if($splitCurrentVersion.Count -eq $splitTestingVersion.Count)
    {
        for($i = 0; $i -lt $splitCurrentVersion.Count; $i++)
        {
            if($splitCurrentVersion[$i] -lt $splitTestingVersion[$i])
            {
                return $false
            }
        }
        return $true 
    }
    else 
    {
        Write-VerboseOutput("Split count isn't the same, assuming that we are not on current version.")
        return $false 
    }
}

Function Test-ScriptVersion {
param(
[Parameter(Mandatory=$true)][string]$ApiUri, 
[Parameter(Mandatory=$true)][string]$RepoOwner,
[Parameter(Mandatory=$true)][string]$RepoName,
[Parameter(Mandatory=$true)][string]$CurrentVersion,
[Parameter(Mandatory=$true)][int]$DaysOldLimit,
[Parameter(Mandatory=$false)][Scriptblock]$CatchActionFunction
)
    Write-VerboseOutput("Calling: Test-ScriptVersion")

    $isCurrent = $false 
    
    if(Test-Connection -ComputerName $ApiUri -Count 1 -Quiet)
    {
        try 
        {
            $ScriptBlock = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                ConvertFrom-Json(Invoke-WebRequest -Uri ($uri = "https://$($args[0])/repos/$($args[1])/$($args[2])/releases/latest"))
            }

            $WebRequestJob = Start-Job -ScriptBlock $ScriptBlock -Name "WebRequestJob" -ArgumentList $ApiUri,$RepoOwner,$RepoName
            do
            {
                $i++
                if((Get-Job -Id $WebRequestJob.Id).State -eq "Completed")
                {
                    Write-VerboseOutput("WebRequest after {0} attempts successfully completed. Receiving results." -f $i)

                    try
                    {
                        $releaseInformation = Receive-Job -Id $WebRequestJob.Id -Keep -ErrorAction Stop
                    }
                    catch
                    {
                        if ($CatchActionFunction -ne $null)
                        {
                            & $CatchActionFunction
                        }
                    }

                    Write-VerboseOutput("Removing background worker job")
                    Remove-Job -Id $WebRequestJob.Id
                    Break
                }
                else
                {
                    Write-VerboseOutput("Attempt: {0} WebRequest not yet complete." -f $i)
                    if($i -eq 30)
                    {
                        Write-VerboseOutput("Reached 30 attempts. Removing background worker job.")
                        Remove-Job -Id $WebRequestJob.Id
                    }
                    Start-Sleep -Seconds 1
                }
            }
            while($i -lt 30)
        }
        catch 
        {
            Invoke-CatchActions
            Write-VerboseOutput("Failed to run Invoke-WebRequest")
        }

        if($releaseInformation -ne $null)
        {
            Write-VerboseOutput("We're online: {0} connected successfully." -f $uri)
            $latestVersion = ($releaseInformation.tag_name).Split("v")[1]
            if(Test-IsCurrentVersion -CurrentVersion $CurrentVersion -TestingVersion $latestVersion)
            {
                Write-VerboseOutput("Version '{0}' is the latest version." -f $latestVersion)
                $isCurrent = $true 
            }
            else 
            {
                Write-VerboseOutput("Version '{0}' is outdated. Lastest version is '{1}'" -f $CurrentVersion, $latestVersion)
            }
        }
        else 
        {
            Write-VerboseOutput("Release information was null.")
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

    Write-VerboseOutput("Exiting: Test-ScriptVersion | Returning: {0}" -f $isCurrent)
    return $isCurrent
}

Function Test-RequiresServerFqdn {

    Write-VerboseOutput("Calling: Test-RequiresServerFqdn")
    try
    {
        $Script:ServerFQDN = (Get-ExchangeServer $Script:Server).FQDN
        Invoke-Command -ComputerName $Script:Server -ScriptBlock {Get-Date | Out-Null} -ErrorAction Stop
        Write-VerboseOutput("Connected successfully using NetBIOS name.")
    }
    catch
    {
        Invoke-CatchActions
        Write-VerboseOutput("Failed to connect to {0} using NetBIOS name. Fallback to Fqdn: {1}" -f $Script:Server, $Script:ServerFQDN)
        $Script:Server = $Script:ServerFQDN
    }
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-WmiObjectHandler/Get-WmiObjectHandler.ps1
Function Get-WmiObjectHandler {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][string]$ComputerName = $env:COMPUTERNAME,
    [Parameter(Mandatory=$true)][string]$Class,
    [Parameter(Mandatory=$false)][string]$Filter,
    [Parameter(Mandatory=$false)][string]$Namespace,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Get-WmiObjectHandler")
    Write-VerboseWriter("Passed: [string]ComputerName: {0} | [string]Class: {1} | [string]Filter: {2} | [string]Namespace: {3}" -f $ComputerName, $Class, $Filter, $Namespace)
    $execute = @{
        ComputerName = $ComputerName 
        Class = $Class
    }
    if(![string]::IsNullOrEmpty($Filter))
    {
        $execute.Add("Filter", $Filter) 
    }
    if(![string]::IsNullOrEmpty($Namespace))
    {
        $execute.Add("Namespace", $Namespace)
    }
    try 
    {
        $wmi = Get-WmiObject @execute -ErrorAction Stop
        return $wmi 
    }
    catch 
    {
        Write-VerboseWriter("Failed to run Get-WmiObject object on class '{0}'" -f $Class)
        if($CatchActionFunction -ne $null)
        {
            & $CatchActionFunction 
        }
    }    
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
Function Invoke-RegistryGetValue {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][string]$RegistryHive = "LocalMachine",
    [Parameter(Mandatory=$true)][string]$MachineName,
    [Parameter(Mandatory=$true)][string]$SubKey,
    [Parameter(Mandatory=$false)][string]$GetValue,
    [Parameter(Mandatory=$false)][bool]$ReturnAfterOpenSubKey,
    [Parameter(Mandatory=$false)][object]$DefaultValue,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )

    #Function Version 1.2
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Invoke-RegistryGetValue")
    try
    {
        Write-VerboseWriter("Attempting to open the Base Key '{0}' on Server '{1}'" -f $RegistryHive, $MachineName)
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $MachineName)
        Write-VerboseWriter("Attempting to open the Sub Key '{0}'" -f $SubKey)
        $RegKey= $Reg.OpenSubKey($SubKey)

        if ($ReturnAfterOpenSubKey)
        {
            Write-VerboseWriter("Returning OpenSubKey")
            return $RegKey
        }

        Write-VerboseWriter("Attempting to get the value '{0}'" -f $GetValue)
        $returnGetValue = $RegKey.GetValue($GetValue)

        if ($null -eq $returnGetValue -and
            $null -ne $DefaultValue)
        {
            Write-VerboseWriter("No value found in the registry. Setting to default value: {0}" -f $DefaultValue)
            $returnGetValue = $DefaultValue
        }

        Write-VerboseWriter("Exiting: Invoke-RegistryHandler | Returning: {0}" -f $returnGetValue)
        return $returnGetValue
    }
    catch
    {
        if ($CatchActionFunction -ne $null)
        {
            & $CatchActionFunction
        }

        Write-VerboseWriter("Failed to open the registry")
    }
    
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
Function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [Parameter(Mandatory=$false)][string]$ScriptBlockDescription,
    [Parameter(Mandatory=$false)][object]$ArgumentList,
    [Parameter(Mandatory=$false)][bool]$IncludeNoProxyServerOption = $true, #Default in HealthChecker
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.1
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Invoke-ScriptBlockHandler")
    if(![string]::IsNullOrEmpty($ScriptBlockDescription))
    {
        Write-VerboseWriter($ScriptBlockDescription)
    }
    try 
    {
        if($ComputerName -ne $env:COMPUTERNAME)
        {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $ScriptBlock
                ErrorAction = "Stop"
            }

            if ($IncludeNoProxyServerOption)
            {
                Write-VerboseWriter("Including SessionOption")
                $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
            }
    
            if($ArgumentList -ne $null) 
            {
                $params.Add("ArgumentList", $ArgumentList)
                Write-VerboseWriter("Running Invoke-Command with argument list.")
                
            }
            else
            {
                Write-VerboseWriter("Running Invoke-Command without argument list.")
            }
    
            $invokeReturn = Invoke-Command @params
            return $invokeReturn 
        }
        else 
        {
            if($ArgumentList -ne $null)
            {
                Write-VerboseWriter("Running Script Block locally with argument list.")
                $localReturn = & $ScriptBlock $ArgumentList 
            }
            else 
            {
                Write-VerboseWriter("Running Script Block locally without argument list.")
                $localReturn = & $ScriptBlock      
            }
            return $localReturn 
        }
    }
    catch 
    {
        Write-VerboseWriter("Failed to Invoke-ScriptBlockHandler")
        if($CatchActionFunction -ne $null)
        {
            & $CatchActionFunction 
        }
    }
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Confirm-ExchangeShell/Confirm-ExchangeShell.ps1
Function Confirm-ExchangeShell {
[CmdletBinding()]
param(
[Parameter(Mandatory=$false)][bool]$LoadExchangeShell = $true,
[Parameter(Mandatory=$false)][bool]$LoadExchangeVariables = $true,
[Parameter(Mandatory=$false)][bool]$ByPassLocalExchangeServerTest = $false,
[Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
)
#Function Version 1.6
<#
Required Functions: 
    https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-HostWriter.ps1
    https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
#>
    
$passed = $false 
Write-VerboseWriter("Calling: Confirm-ExchangeShell")
Write-VerboseWriter("Passed: [bool]LoadExchangeShell: {0} | [bool]LoadExchangeVariables: {1} | [bool]ByPassLocalExchangeServerTest: {2}" -f $LoadExchangeShell,
$LoadExchangeVariables, $ByPassLocalExchangeServerTest)
#Test that we are on Exchange 2010 or newer
if(($isLocalExchangeServer = (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup')) -or
($isLocalExchangeServer = (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup')) -or
$ByPassLocalExchangeServerTest)
{
    Write-VerboseWriter("We are on Exchange 2010 or newer")
    if((Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\EdgeTransportRole') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'))
    {
        Write-VerboseWriter("We are on Exchange Edge Transport Server")
        $IsEdgeTransport = $true
    }
    try 
    {
        if(((Get-PSSession | Where-Object {($_.Availability -eq 'Available') -and
            ($_.ConfigurationName -eq 'Microsoft.Exchange')}).Count -eq 0) -and
            ((Get-Module -Name RemoteExchange).Count -eq 1))
        {
            Write-VerboseWriter("Removing RemoteExchange module")
            Remove-Module -Name RemoteExchange
            $currentPSModules = Get-Module
            foreach ($PSModule in $currentPSModules)
            {
                if(($PSModule.ModuleType -eq "Script") -and
                    ($PSModule.ModuleBase -like "*\Microsoft\Exchange\RemotePowerShell\*"))
                {
                    Write-VerboseWriter("Removing module {0} for implicit remoting" -f $PSModule.Name)
                    Remove-Module -Name $PSModule.Name
                }
            }
        }

        Get-ExchangeServer -ErrorAction Stop | Out-Null
        Write-VerboseWriter("Exchange PowerShell Module already loaded.")
        $passed = $true 
    }
    catch 
    {
        Write-VerboseWriter("Failed to run Get-ExchangeServer")
        if($CatchActionFunction -ne $null)
        {
            & $CatchActionFunction
            $watchErrors = $true
        }
        if($LoadExchangeShell -and
            $isLocalExchangeServer)
        {
            Write-HostWriter "Loading Exchange PowerShell Module..."
            try
            {
                if($watchErrors)
                {
                    $currentErrors = $Error.Count
                }
                if($IsEdgeTransport)
                {
                    [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exshell.psc1" -ErrorAction Stop
                    ForEach($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn)
                    {
                        Write-VerboseWriter("Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name)
                        Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                    }
                    Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                    $passed = $true #We are just going to assume this passed.
                }
                else
                {
                    Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                    Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                    $passed = $true #We are just going to assume this passed.
                }
                if($watchErrors)
                {
                    $index = 0
                    while($index -lt ($Error.Count - $currentErrors))
                    {
                        & $CatchActionFunction $Error[$index]
                        $index++
                    }
                } 
            }
            catch 
            {
                Write-HostWriter("Failed to Load Exchange PowerShell Module...")
            }
        }
    }
    finally 
    {
        if($LoadExchangeVariables -and 
            $passed -and
            $isLocalExchangeServer)
        {
            #Diff from master not using Get-ExchangeInstallDirectory because of required functions
            if($ExInstall -eq $null -or $ExBin -eq $null)
            {
                if(Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup')
                {
                    $Global:ExInstall = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath
                }
                else
                {
                    $Global:ExInstall = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
                }
    
                $Global:ExBin = $Global:ExInstall + "\Bin"
    
                Write-VerboseWriter("Set ExInstall: {0}" -f $Global:ExInstall)
                Write-VerboseWriter("Set ExBin: {0}" -f $Global:ExBin)
            }
        }
    }
}
else 
{
    Write-VerboseWriter("Does not appear to be an Exchange 2010 or newer server.")
}
Write-VerboseWriter("Returned: {0}" -f $passed)
return $passed
}

#Master Template https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-Smb1ServerSettings/Get-Smb1ServerSettings.ps1
Function Get-Smb1ServerSettings {
[CmdletBinding()]
param(
[string]$ServerName = $env:COMPUTERNAME,
[scriptblock]$CatchActionFunction
)
    #Function Version 1.2
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
    #>
    
    Write-VerboseWriter("Calling: Get-Smb1ServerSettings")
    Write-VerboseWriter("Passed ServerName: {0}" -f $ServerName)
    $smbServerConfiguration = Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock {Get-SmbServerConfiguration} -CatchActionFunction $CatchActionFunction -ScriptBlockDescription "Get-SmbServerConfiguration"
    
    <#
    Unknown 0
    Failed to get Install Setting 1
    Install is set to true 2
    Install is set to false 4
    Failed to get Block Setting 8
    SMB1 is not being blocked 16
    SMB1 is being blocked 32
    #>
    
    $smb1Status = 0
    
    try
    {
        $windowsFeature = Get-WindowsFeature "FS-SMB1" -ComputerName $ServerName -ErrorAction Stop
    }
    catch 
    {
        Write-VerboseWriter("Failed to Get-WindowsFeature for FS-SMB1")
        if ($CatchActionFunction -ne $null)
        {
            & $CatchActionFunction
        }
    }
    
    if ($windowsFeature -eq $null)
    {
        $smb1Status += 1
    }
    elseif ($windowsFeature.Installed)
    {
        $smb1Status += 2
    }
    else
    {
        $smb1Status += 4
    }
    
    if ($smbServerConfiguration -eq $null)
    {
        $smb1Status += 8
    }
    elseif ($smbServerConfiguration.EnableSMB1Protocol)
    {
        $smb1Status += 16
    }
    else
    {
        $smb1Status += 32
    }
    
    $smb1ServerSettings = New-Object PSCustomObject
    $smb1ServerSettings | Add-Member -MemberType NoteProperty -Name "SmbServerConfiguration" -Value $smbServerConfiguration
    $smb1ServerSettings | Add-Member -MemberType NoteProperty -Name "WindowsFeature" -Value $windowsFeature
    $smb1ServerSettings | Add-Member -MemberType NoteProperty -Name "Smb1Status" -Value $smb1Status
    
    return $smb1ServerSettings
    
}

#Master Template https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-DotNetDllFileVersions/Get-DotNetDllFileVersions.ps1
Function Get-DotNetDllFileVersions {
    [CmdletBinding()]
    param(
    [string]$ComputerName,
    [array]$FileNames,
    [scriptblock]$CatchActionFunction
    )

    #Function Version 1.1
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
    #>

    Write-VerboseWriter("Calling: Get-DotNetDllFileVersions")

    Function ScriptBlock-GetItem{
    param(
    [string]$FilePath
    )
        $getItem = Get-Item $FilePath

        $returnObject = ([PSCustomObject]@{
            GetItem = $getItem
            LastWriteTimeUtc = $getItem.LastWriteTimeUtc
            VersionInfo = ([PSCustomObject]@{
                FileMajorPart = $getItem.VersionInfo.FileMajorPart
                FileMinorPart = $getItem.VersionInfo.FileMinorPart
                FileBuildPart = $getItem.VersionInfo.FileBuildPart
                FilePrivatePart = $getItem.VersionInfo.FilePrivatePart
            })
        })

        return $returnObject
    }

    $dotNetInstallPath = Invoke-RegistryGetValue -MachineName $ComputerName -SubKey "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -GetValue "InstallPath" -CatchActionFunction $CatchActionFunction

    if ($dotNetInstallPath -eq [string]::Empty)
    {
        Write-VerboseWriter("Failed to determine .NET install path")
        return
    }

    $files = @{}
    foreach($filename in $FileNames)
    {
        Write-VerboseWriter("Query .NET DLL information for machine: {0}" -f $ComputerName)
        $getItem = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock ${Function:ScriptBlock-GetItem} -ArgumentList ("{0}\{1}" -f $dotNetInstallPath, $filename) -CatchActionFunction $CatchActionFunction
        $files.Add($filename, $getItem)
    }

    return $files
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
    Write-VerboseOutput("Exiting: Get-CounterSamples")
    return $counterSamples 
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ServerOperatingSystemVersion/Get-ServerOperatingSystemVersion.ps1
Function Get-ServerOperatingSystemVersion {
    [CmdletBinding()]
    param(
    [string]$OsCaption
    )
    
    #Function Version 1.5
    <#
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    
    if($OsCaption -eq [string]::Empty -or
        $OsCaption -eq $null)
    {
        Write-VerboseWriter("Getting the local machine version build number")
        $OsCaption = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        Write-VerboseWriter("Got '{0}' for the caption" -f $OsCaption)
    }
    else 
    {
        Write-VerboseWriter("Passed - [string]OsCaption : {0}" -f $OsCaption)
    }
    
    $osReturnValue = [string]::Empty

    switch -Wildcard ($OsCaption)
    {
        "*Server 2008 R2*" {$osReturnValue = "Windows2008R2"; break}
        "*Server 2008*" {$osReturnValue = "Windows2008"}
        "*Server 2012 R2*" {$osReturnValue = "Windows2012R2"; break}
        "*Server 2012*" {$osReturnValue = "Windows2012"}
        "*Server 2016*" {$osReturnValue = "Windows2016"}
        "*Server 2019*" {$osReturnValue = "Windows2019"}
        "Microsoft Windows Server Standard" {$osReturnValue = "WindowsCore"}
        "Microsoft Windows Server Datacenter" {$osReturnValue = "WindowsCore"}
        default {$osReturnValue = "Unknown"}
    }
    
    Write-VerboseWriter("Returned: {0}" -f $osReturnValue)
    return [string]$osReturnValue

}

Function Get-PageFileInformation {

    Write-VerboseOutput("Calling: Get-PageFileInformation")

    [HealthChecker.PageFileInformation]$page_obj = New-Object HealthChecker.PageFileInformation
    $pagefile = Get-WmiObjectHandler -ComputerName $Script:Server -Class "Win32_PageFileSetting" -CatchActionFunction ${Function:Invoke-CatchActions}
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

    Write-VerboseOutput("Exiting: Get-PageFileInformation")
    return $page_obj
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-AllNicInformation/Get-AllNicInformation.ps1
Function Get-AllNicInformation {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$false)][string]$ComputerFQDN,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.5
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-WmiObjectHandler/Get-WmiObjectHandler.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
    #>
    Write-VerboseWriter("Calling: Get-AllNicInformation")
    Write-VerboseWriter("Passed [string]ComputerName: {0} | [string]ComputerFQDN: {1}" -f $ComputerName, $ComputerFQDN)
    
    Function Get-NicPnpCapabilitiesSetting {
    [CmdletBinding()]
    param(
    [string]$NicAdapterComponentId
    )
    
    if ($NicAdapterComponentId -eq [string]::Empty)
    {
        throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid NicAdapterDeviceId or NicAdapterComponentId"
    }
    
    $nicAdapterBasicPath = "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"
    Write-VerboseWriter("Probing started to detect NIC adapter registry path")
    [int]$i = 0
    
    do {
        $nicAdapterPnPCapabilitiesProbingKey = "{0}\{1}" -f $nicAdapterBasicPath, ($i.ToString().PadLeft(4,"0"))
        $netCfgInstanceId = Invoke-RegistryGetValue -MachineName $ComputerName -Subkey $nicAdapterPnPCapabilitiesProbingKey -GetValue "NetCfgInstanceId" -CatchActionFunction $CatchActionFunction
    
        if ($netCfgInstanceId -eq $NicAdapterComponentId)
        {
            Write-VerboseWriter("Matching ComponentId found - now checking for PnPCapabilitiesValue")
            $nicAdapterPnPCapabilitiesValue = Invoke-RegistryGetValue -MachineName $ComputerName -SubKey $nicAdapterPnPCapabilitiesProbingKey -GetValue "PnPCapabilities" -CatchActionFunction $CatchActionFunction
            break
        }
        else
        {
            Write-VerboseWriter("No matching ComponentId found")
            $i++
        }
    } while ($null -ne $netCfgInstanceId)
    
    $obj = New-Object PSCustomObject
    $sleepyNicDisabled = $false
    
    if ($nicAdapterPnPCapabilitiesValue -eq 24 -or
        $nicAdapterPnPCapabilitiesValue -eq 280)
    {
        $sleepyNicDisabled = $true
    }
    
    $obj | Add-Member -MemberType NoteProperty -Name "PnPCapabilities" -Value $nicAdapterPnPCapabilitiesValue
    $obj | Add-Member -MemberType NoteProperty -Name "SleepyNicDisabled" -Value $sleepyNicDisabled
    return $obj
    
    }
    
    Function Get-NetworkConfiguration {
    [CmdletBinding()]
    param(
    [string]$ComputerName
    )
        try
        {
            $currentErrors = $Error.Count
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
            $networkIpConfiguration = Get-NetIPConfiguration -CimSession $CimSession -ErrorAction Stop | Where-Object {$_.NetAdapter.MediaConnectionState -eq "Connected"}
    
            if ($CatchActionFunction -ne $null)
            {
                $index = 0
                while ($index -lt ($Error.Count - $currentErrors))
                {
                    & $CatchActionFunction $Error[$index]
                    $index++
                }
            }
    
            return $networkIpConfiguration
        }
        catch
        {
            Write-VerboseWriter("Failed to run Get-NetIPConfiguration. Error {0}." -f $Error[0].Exception)
    
            if ($CatchActionFunction -ne $null)
            {
                & $CatchActionFunction
            }
    
            throw
        }
    }
    
    Function New-NICInformation {
    param(
    [array]$NetworkConfigurations,
    [bool]$WmiObject
    )
        if($NetworkConfigurations -eq $null)
        {
            Write-VerboseWriter("NetworkConfigurations are null in New-NICInformation. Returning a null object.")
            return $null
        }
    
        Function New-IpvAddresses {
            
            $obj = New-Object PSCustomObject
            $obj | Add-Member -MemberType NoteProperty -Name "Address" -Value ([string]::Empty)
            $obj | Add-Member -MemberType NoteProperty -Name "Subnet" -Value ([string]::Empty)
            $obj | Add-Member -MemberType NoteProperty -Name "DefaultGateway" -Value ([string]::Empty)
    
            return $obj
        }
    
        if ($WmiObject)
        {
            $networkAdapterConfigurations = Get-WmiObjectHandler -ComputerName $ComputerName -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled = True" -CatchActionFunction $CatchActionFunction
        }
    
        [array]$nicObjects = @()
        foreach($networkConfig in $NetworkConfigurations)
        {
            $dnsClient = $null
            $rssEnabledValue = 2
            $netAdapterRss = $null
            if (!$WmiObject)
            {
                Write-VerboseWriter("Working on NIC: {0}" -f $networkConfig.InterfaceDescription)
                $adapter = $networkConfig.NetAdapter
                $nicPnpCapabilitiesSetting = Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.DeviceID
    
                try
                {
                    $dnsClient = $adapter | Get-DnsClient
                    Write-VerboseWriter("Got DNS Client information")
                }
                catch
                {
                    Write-VerboseWriter("Failed to get the DNS Client information")
                    if ($CatchActionFunction -ne $null)
                    {
                        & $CatchActionFunction
                    }
                }
    
                try
                {
                    $netAdapterRss = $adapter | Get-NetAdapterRss
                    Write-VerboseWriter("Got Net Adapter RSS information")
                    if ($netAdapterRss -ne $null)
                    {
                        [int]$rssEnabledValue = $netAdapterRss.Enabled
                    }
                }
                catch
                {
                    Write-VerboseWriter("Failed to get RSS Information")
                    if ($CatchActionFunction -ne $null)
                    {
                        & $CatchActionFunction
                    }
                }
            }
            else
            {
                Write-VerboseWriter("Working on NIC: {0}" -f $networkConfig.Description)
                $adapter = $networkConfig
                $nicPnpCapabilitiesSetting = Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.Guid
            }
    
            $nicInformationObj = New-Object PSCustomObject
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "WmiObject" -Value $WmiObject
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Name" -Value ($adapter.Name)
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "LinkSpeed" -Value ((($adapter.Speed)/1000000).ToString() + " Mbps")
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DriverDate" -Value [DateTime]::MaxValue
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "NICObject" -Value $networkConfig
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "NetAdapterRss" -Value $netAdapterRss
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "RssEnabledValue" -Value $rssEnabledValue
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "IPv6Enabled" -Value $false
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Description" -Value $adapter.Description
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DriverVersion" -Value [string]::Empty
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "MTUSize" -Value 0
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "PnPCapabilities" -Value ($nicPnpCapabilitiesSetting.PnPCapabilities)
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "SleepyNicDisabled" -Value ($nicPnpCapabilitiesSetting.SleepyNicDisabled)
    
            if (!$WmiObject)
            {
                $nicInformationObj.MTUSize = $adapter.MtuSize
                $nicInformationObj.DriverDate = $adapter.DriverDate
                $nicInformationObj.DriverVersion = $adapter.DriverVersionString
                $nicInformationObj.Description = $adapter.InterfaceDescription
    
                foreach ($ipAddress in $networkConfig.AllIPAddresses.IPAddress)
                {
                    if ($ipAddress.Contains(":"))
                    {
                        $nicInformationObj.IPv6Enabled = $true
                    }
                }
    
                $ipv4Address = @()
                for ($i = 0; $i -lt $networkConfig.IPv4Address.Count; $i++)
                {
                    $obj = New-IpvAddresses
                    
                    if ($networkConfig.IPv4Address -ne $null -and
                        $i -lt $networkConfig.IPv4Address.Count)
                    {
                        $obj.Address = $networkConfig.IPv4Address[$i].IPAddress
                        $obj.Subnet = $networkConfig.IPv4Address[$i].PrefixLength
                    }
    
                    if ($networkConfig.IPv4DefaultGateway -ne $null -and
                        $i -lt $networkConfig.IPv4DefaultGateway.Count)
                    {
                        $obj.DefaultGateway = $networkConfig.IPv4DefaultGateway[$i].NextHop
                    }
    
                    $ipv4Address += $obj
                }
    
                $ipv6Address = @()
                for ($i = 0; $i -lt $networkConfig.IPv6Address.Count; $i++)
                {
                    $obj = New-IpvAddresses
                    
                    if ($networkConfig.IPv6Address -ne $null -and
                        $i -lt $networkConfig.IPv6Address.Count)
                    {
                        $obj.Address = $networkConfig.IPv6Address[$i].IPAddress
                        $obj.Subnet = $networkConfig.IPv6Address[$i].PrefixLength
                    }
    
                    if ($networkConfig.IPv6DefaultGateway -ne $null -and
                        $i -lt $networkConfig.IPv6DefaultGateway.Count)
                    {
                        $obj.DefaultGateway = $networkConfig.IPv6DefaultGateway[$i].NextHop
                    }
    
                    $ipv6Address += $obj
                }
                
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "IPv4Addresses" -Value $ipv4Address
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Ipv6Addresses" -Value $ipv6Address 
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "RegisteredInDns" -Value $dnsClient.RegisterThisConnectionsAddress
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DnsServer" -Value $networkConfig.DNSServer.ServerAddresses
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DnsClientObject" -Value $dnsClient
            }
            else 
            {
                $stopProcess = $false
                foreach ($adapterConfiguration in $networkAdapterConfigurations)
                {
                    Write-VerboseWriter("Working on '{0}' | SettingID: {1}" -f $adapterConfiguration.Description, ($settingId = $adapterConfiguration.SettingID))
                    if ($settingId -eq $networkConfig.GUID -or
                        $settingId -eq $networkConfig.InterfaceGuid)
                    {
                        foreach ($ipAddress in $adapterConfiguration.IPAddress)
                        {
                            if ($ipAddress.Contains(":"))
                            {
                                $nicInformationObj.IPv6Enabled = $true
                                $stopProcess = $true
                                break
                            }
                        }
                    }
    
                    if ($stopProcess)
                    {
                        break
                    }
                }
            }
    
            $nicObjects += $nicInformationObj 
        }
    
        Write-VerboseWriter("Found {0} active adapters on the computer." -f $nicObjects.Count)
        Write-VerboseWriter("Exiting: Get-AllNicInformation")
        return $nicObjects 
    }
    
    try
    {
        try
        {
            $networkConfiguration = Get-NetworkConfiguration -ComputerName $ComputerName
        }
        catch
        {
            if ($CatchActionFunction -ne $null)
            {
                & $CatchActionFunction
            }
    
            if ($ComputerFQDN -ne [string]::Empty -and
                $ComputerName -ne $null)
            {
                $networkConfiguration = Get-NetworkConfiguration -ComputerName $ComputerFQDN
            }
            else
            {
                $bypassCatchActions = $true
                Write-VerboseWriter("No FQDN was passed, going to rethrow error.")
                throw
            }
        }
    
        return (New-NICInformation -NetworkConfigurations $networkConfiguration)
    }
    catch
    {
        if (!$bypassCatchActions -and
            $CatchActionFunction -ne $null)
        {
            & $CatchActionFunction
        }
    
        $wmiNetworkCards = Get-WmiObjectHandler -ComputerName $ComputerName -Class "Win32_NetworkAdapter" -Filter "NetConnectionStatus ='2'" -CatchActionFunction $CatchActionFunction
        return (New-NICInformation -NetworkConfigurations $wmiNetworkCards -WmiObject $true)
    }
    
}

Function Get-HttpProxySetting {

	$httpProxy32 = [String]::Empty
	$httpProxy64 = [String]::Empty
	Write-VerboseOutput("Calling: Get-HttpProxySetting")
    
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

    $httpProxy32 = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ScriptBlockDescription "Getting 32 Http Proxy Value" -CatchActionFunction ${Function:Invoke-CatchActions}
    $httpProxy64 = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ScriptBlockDescription "Getting 64 Http Proxy Value" -CatchActionFunction ${Function:Invoke-CatchActions}

    Write-VerboseOutput("Http Proxy 32: {0}" -f $httpProxy32)
    Write-VerboseOutput("Http Proxy 64: {0}" -f $httpProxy64)
    Write-VerboseOutput("Exiting: Get-HttpProxySetting")

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

    Write-VerboseOutput("Calling: Get-VisualCRedistributableVersion")

    $installedSoftware = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock {Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*} -ScriptBlockDescription "Quering for software" -CatchActionFunction ${Function:Invoke-CatchActions}
    $softwareInfos = @()
    foreach ($software in $installedSoftware)
    {
        if($software.DisplayName -like "Microsoft Visual C++ *")
        {
            Write-VerboseOutput("Microsoft Visual C++ Redistributable found: {0}" -f $software.DisplayName)
            [HealthChecker.SoftwareInformation]$softwareInfo = New-Object Healthchecker.SoftwareInformation
            $softwareInfo.DisplayName = $software.DisplayName
            $softwareInfo.DisplayVersion = $software.DisplayVersion
            $softwareInfo.InstallDate = $software.InstallDate
            $softwareInfo.VersionIdentifier = $software.Version
            $softwareInfos += $softwareInfo
        }
    }

    Write-VerboseOutput("Exiting: Get-VisualCRedistributableVersion")
    return $softwareInfos
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ServerRebootPending/Get-ServerRebootPending.ps1
Function Get-ServerRebootPending {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ServerName,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
    #>
    Function Get-PendingFileReboot {
        try 
        {
            if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\" -Name PendingFileRenameOperations -ErrorAction Stop))
            {
                return $true 
            }
            else 
            {
                return $false 
            }
        }
        catch 
        {
            throw 
        }
    }
    Function Get-PendingSCCMReboot {
        try 
        {
            $sccmReboot = Invoke-CimMethod -Namespace 'Root\ccm\clientSDK' -ClassName 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction Stop 
            if($sccmReboot -and ($sccmReboot.RebootPending -or $sccmReboot.IsHardRebootPending))
            {
                return $true 
            }
        }
        catch 
        {
            throw 
        }
    }
    Function Get-PathTestingReboot {
    param(
    [string]$TestingPath 
    )
        if(Test-Path $TestingPath)
        {
            return $true 
        }
        else 
        {
            return $false 
        }
    }
    
    Write-VerboseWriter("Calling: Get-ServerRebootPending")
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PendingFileReboot} -ScriptBlockDescription "Get-PendingFileReboot" -CatchActionFunction $CatchActionFunction)
    {
        Write-VerboseWriter("Get-PendingFileReboot Determined Reboot is pending. Registry HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\ item properties of PendingFileRenameOperations.")
        return $true 
    }
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PendingSCCMReboot} -ScriptBlockDescription "Get-PendingSCCMReboot" -CatchActionFunction $CatchActionFunction)
    {
        Write-VerboseWriter("Get-PendingSCCMReboot determined reboot is pending.")
        return $true 
    }
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PathTestingReboot} -ScriptBlockDescription "Get-PendingAutoUpdateReboot" -CatchActionFunction $CatchActionFunction -ArgumentList "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
    {
        Write-VerboseWriter("Get-PathTestingReboot for HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending determined reboot is pending")
        return $true 
    }
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PathTestingReboot} -ScriptBlockDescription "Get-PendingAutoUpdateReboot" -CatchActionFunction $CatchActionFunction -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    {
        Write-VerboseWriter("Get-PathTestingReboot for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired determined reboot is pending")
        return $true 
    }
    Write-VerboseWriter("Passed all reboot checks.")
    return $false 
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-AllTlsSettingsFromRegistry/Get-AllTlsSettingsFromRegistry.ps1
Function Get-AllTlsSettingsFromRegistry {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$MachineName,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
    #>
    
    Write-VerboseWriter("Calling: Get-AllTlsSettingsFromRegistry")
    Write-VerboseWriter("Passed: [string]MachineName: {0}" -f $MachineName)
    
    $registryBase = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS {0}\{1}"
    $tlsVersions = @("1.0","1.1","1.2")
    
    $tlsResults = @{}
    $keyValues = ("Enabled","DisabledByDefault")
    
    Function Set-TLSMemberValue {
    param(
    [Parameter(Mandatory=$true)][string]$GetKeyType,
    [Parameter(Mandatory=$false)][object]$KeyValue,
    [Parameter(Mandatory=$true)][string]$ServerClientType,
    [Parameter(Mandatory=$true)][string]$TlsVersion 
    )
        switch($GetKeyType)
        {
            "Enabled" {
                if($KeyValue -eq $null)
                {
                    Write-VerboseWriter("Failed to get TLS {0} {1} Enabled Key on Server {2}. We are assuming this means it is enabled." -f $TlsVersion, $ServerClientType, $MachineName)
                    return $true
                }
                else 
                {
                    Write-VerboseWriter("{0} Enabled Value '{1}'" -f $ServerClientType, $serverValue)
                    if($KeyValue -eq 1)
                    {
                        return $true 
                    }
                    return $false 
                }
             }
            "DisabledByDefault" {
                if($KeyValue -ne $null)
                {
                    Write-VerboseWriter("Failed to get TLS {0} {1} Disabled By Default Key on Server {2}. Setting to false." -f $TlsVersion, $ServerClientType, $MachineName)
                    return $false 
                }
                else 
                {
                    Write-VerboseWriter("{0} Disabled By Default Value '{1}'" -f $ServerClientType, $serverValue)
                    if($KeyValue -eq 1)
                    {
                        return $true
                    }
                    return $false 
                }
            }
        }
    }
    
    Function Set-NETDefaultTLSValue {
    param(
    [Parameter(Mandatory=$false)][object]$KeyValue,
    [Parameter(Mandatory=$true)][string]$NetVersion,
    [Parameter(Mandatory=$true)][string]$KeyName
    )
        if($KeyValue -eq $null)
        {
            Write-VerboseWriter("Failed to get {0} registry value for .NET {1} version. Setting to false." -f $KeyName, $NetVersion)
            return $false
        }
        else 
        {
            Write-VerboseWriter("{0} value '{1}'" -f $KeyName, $KeyValue)
            if($KeyValue -eq 1)
            {
                return $true 
            }
            return $false 
        }
    }
    
    [hashtable]$allTlsObjects = @{}
    foreach($tlsVersion in $tlsVersions)
    {
        $registryServer = $registryBase -f $tlsVersion, "Server" 
        $registryClient = $registryBase -f $tlsVersion, "Client" 
        $currentTLSObject = New-Object PSCustomObject 
        $currentTLSObject | Add-Member -MemberType NoteProperty -Name "TLSVersion" -Value $tlsVersion
    
        foreach($getKey in $keyValues)
        {
            $memberServerName = "Server{0}" -f $getKey
            $memberClientName = "Client{0}" -f $getKey 
    
            $serverValue = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $MachineName -SubKey $registryServer -GetValue $getKey -CatchActionFunction $CatchActionFunction
            $clientValue = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $MachineName -SubKey $registryClient -GetValue $getKey -CatchActionFunction $CatchActionFunction
    
            $currentTLSObject | Add-Member -MemberType NoteProperty -Name $memberServerName -Value (Set-TLSMemberValue -GetKeyType $getKey -KeyValue $serverValue -ServerClientType "Server" -TlsVersion $tlsVersion)
            $currentTLSObject | Add-Member -MemberType NoteProperty -Name $memberClientName -Value (Set-TLSMemberValue -GetKeyType $getKey -KeyValue $clientValue -ServerClientType "Client" -TlsVersion $tlsVersion)
    
        }
        $allTlsObjects.Add($tlsVersion, $currentTLSObject)
    }
    
    $netVersions = @("v2.0.50727","v4.0.30319")
    $registryBase = "SOFTWARE\{0}\.NETFramework\{1}"
    foreach($netVersion in $netVersions)
    {
        $currentNetTlsDefaultVersionObject = New-Object PSCustomObject 
        $currentNetTlsDefaultVersionObject | Add-Member -MemberType NoteProperty -Name "NetVersion" -Value $netVersion
    
        $SystemDefaultTlsVersions = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $MachineName -SubKey ($registryBase -f "Microsoft", $netVersion) -GetValue "SystemDefaultTlsVersions" -CatchActionFunction $CatchActionFunction
        $WowSystemDefaultTlsVersions = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $MachineName -SubKey ($registryBase -f "Wow6432Node\Microsoft", $netVersion) -GetValue "SystemDefaultTlsVersions" -CatchActionFunction $CatchActionFunction
    
        $currentNetTlsDefaultVersionObject | Add-Member -MemberType NoteProperty -Name "SystemDefaultTlsVersions" -Value (Set-NETDefaultTLSValue -KeyValue $SystemDefaultTlsVersions -NetVersion $netVersion -KeyName "SystemDefaultTlsVersions")
        $currentNetTlsDefaultVersionObject | Add-Member -MemberType NoteProperty -Name "WowSystemDefaultTlsVersions" -Value (Set-NETDefaultTLSValue -KeyValue $WowSystemDefaultTlsVersions -NetVersion $netVersion -KeyName "WowSystemDefaultTlsVersions")
        
        $hashKeyName = "NET{0}" -f ($netVersion.Split(".")[0])
        $allTlsObjects.Add($hashKeyName, $currentNetTlsDefaultVersionObject) 
    }
    
    return $allTlsObjects
}

Function Get-CredentialGuardEnabled {

    Write-VerboseOutput("Calling: Get-CredentialGuardEnabled")

    $registryValue = Invoke-RegistryGetValue -MachineName $Script:Server -SubKey "SYSTEM\CurrentControlSet\Control\LSA" -GetValue "LsaCfgFlags" -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($registryValue -ne $null -and
        $registryValue -ne 0)
    {
        return $true
    }

    return $false
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-TimeZoneInformationRegistrySettings/Get-TimeZoneInformationRegistrySettings.ps1
Function Get-TimeZoneInformationRegistrySettings {
[CmdletBinding()]
param(
[string]$MachineName = $env:COMPUTERNAME,
[scriptblock]$CatchActionFunction
)
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
    #>
    Write-VerboseWriter("Calling: Get-TimeZoneInformationRegistrySettings")
    Write-VerboseWriter("Passed: [string]MachineName: {0}" -f $MachineName)
    $timeZoneInformationSubKey = "SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    $dynamicDaylightTimeDisabled = Invoke-RegistryGetValue -MachineName $MachineName -SubKey $timeZoneInformationSubKey -GetValue "DynamicDaylightTimeDisabled" -CatchActionFunction $CatchActionFunction
    $timeZoneKeyName = Invoke-RegistryGetValue -MachineName $MachineName -Subkey $timeZoneInformationSubKey -GetValue "TimeZoneKeyName" -CatchActionFunction $CatchActionFunction 
    $standardStart = Invoke-RegistryGetValue -MachineName $MachineName -SubKey $timeZoneInformationSubKey -GetValue "StandardStart" -CatchActionFunction $CatchActionFunction
    $daylightStart = Invoke-RegistryGetValue -MachineName $MachineName -SubKey $timeZoneInformationSubKey -GetValue "DaylightStart" -CatchActionFunction $CatchActionFunction
    
    $timeZoneInformationObject = New-Object PSCustomObject 
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "DynamicDaylightTimeDisabled" -Value $dynamicDaylightTimeDisabled 
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "TimeZoneKeyName" -Value $timeZoneKeyName
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "StandardStart" -Value $standardStart
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "DaylightStart" -Value $daylightStart
    
    $actionsToTake = @() 
    if($timeZoneKeyName -eq $null -or 
        [string]::IsNullOrEmpty($timeZoneKeyName))
    {
        Write-VerboseWriter("TimeZoneKeyName is null or empty. Action should be taken to address this.")
        $actionsToTake += "TimeZoneKeyName is blank. Need to switch your current time zone to a different value, then switch it back to have this value populated again."
    }
    foreach($value in $standardStart)
    {
        if($value -ne 0)
        {
            $standardStartNonZeroValue = $true
            break
        }
    }
    foreach($value in $daylightStart)
    {
        if($value -ne 0)
        {
            $daylightStartNonZeroValue = $true
            break
        }
    }
    if($dynamicDaylightTimeDisabled -ne 0 -and (
        $standardStartNonZeroValue -or 
        $daylightStartNonZeroValue
    ))
    {
        Write-VerboseWriter("Determined that there is a chance the settings set could cause a DST issue.")
        $dstIssueDetected = $true 
        $actionsToTake += "High Warning: DynamicDaylightTimeDisabled is set, Windows can not properly detect any DST rule changes in your time zone. `
        It is possible that you could be running into this issue. Set 'Adjust for daylight saving time automatically to on'"
    }
    elseif($dynamicDaylightTimeDisabled -ne 0)
    {
        Write-VerboseWriter("Daylight savings auto adjustment is disabled.")
        $actionsToTake += "Warning: DynamicDaylightTimeDisabled is set, Windows can not properly detect any DST rule changes in your time zone."
    }
    
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "DstIssueDetected" -Value $dstIssueDetected
    $timeZoneInformationObject | Add-Member -MemberType NoteProperty -Name "ActionsToTake" -Value $actionsToTake
    
    return $timeZoneInformationObject 
}

Function Get-OperatingSystemInformation {

    Write-VerboseOutput("Calling: Get-OperatingSystemInformation")

    [HealthChecker.OperatingSystemInformation]$osInformation = New-Object HealthChecker.OperatingSystemInformation
    $win32_OperatingSystem = Get-WmiObjectHandler -ComputerName $Script:Server -Class Win32_OperatingSystem -CatchActionFunction ${Function:Invoke-CatchActions}
    $win32_PowerPlan = Get-WmiObjectHandler -ComputerName $Script:Server -Class Win32_PowerPlan -Namespace 'root\cimv2\power' -Filter "isActive='true'" -CatchActionFunction ${Function:Invoke-CatchActions}
    $currentDateTime = Get-Date
    $lastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($win32_OperatingSystem.lastbootuptime)
    $osInformation.BuildInformation.VersionBuild = $win32_OperatingSystem.Version
    $osInformation.BuildInformation.MajorVersion = (Get-ServerOperatingSystemVersion -OsCaption $win32_OperatingSystem.Caption)
    $osInformation.BuildInformation.FriendlyName = $win32_OperatingSystem.Caption
    $osInformation.BuildInformation.OperatingSystem = $win32_OperatingSystem
    $osInformation.ServerBootUp.Days = ($currentDateTime - $lastBootUpTime).Days
    $osInformation.ServerBootUp.Hours = ($currentDateTime - $lastBootUpTime).Hours
    $osInformation.ServerBootUp.Minutes = ($currentDateTime - $lastBootUpTime).Minutes
    $osInformation.ServerBootUp.Seconds = ($currentDateTime - $lastBootUpTime).Seconds
    
    if($win32_PowerPlan -ne $null)
    {
        if($win32_PowerPlan.InstanceID -eq "Microsoft:PowerPlan\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}")
        {
            Write-VerboseOutput("High Performance Power Plan is set to true")
            $osInformation.PowerPlan.HighPerformanceSet = $true
        }
        else{Write-VerboseOutput("High Performance Power Plan is NOT set to true")}
        $osInformation.PowerPlan.PowerPlanSetting = $win32_PowerPlan.ElementName
    }
    else
    {
        Write-VerboseOutput("Power Plan Information could not be read")
        $osInformation.PowerPlan.PowerPlanSetting = "N/A"
    }
    $osInformation.PowerPlan.PowerPlan = $win32_PowerPlan 
    $osInformation.PageFile = Get-PageFileInformation
    $osInformation.NetworkInformation.NetworkAdapters = (Get-AllNicInformation -ComputerName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions} -ComputerFQDN $Script:ServerFQDN)
    foreach($adapter in $osInformation.NetworkInformation.NetworkAdapters)
    {
        if (!$adapter.IPv6Enabled)
        {
            $osInformation.NetworkInformation.IPv6DisabledOnNICs = $true
            break
        }
    }

    $osInformation.NetworkInformation.IPv6DisabledComponents = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Script:Server -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -GetValue "DisabledComponents" -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.NetworkInformation.TCPKeepAlive = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Script:Server -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -GetValue "KeepAliveTime" -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.NetworkInformation.RpcMinConnectionTimeout = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Script:Server -SubKey "Software\Policies\Microsoft\Windows NT\RPC\" -GetValue "MinimumConnectionTimeout" -CatchActionFunction ${Function:Invoke-CatchActions}
	$osInformation.NetworkInformation.HttpProxy = Get-HttpProxySetting
    $osInformation.InstalledUpdates.HotFixes = (Get-HotFix -ComputerName $Script:Server -ErrorAction SilentlyContinue) #old school check still valid and faster and a failsafe 
    $osInformation.LmCompatibility = Get-LmCompatibilityLevelInformation
    $counterSamples = (Get-CounterSamples -MachineNames $Script:Server -Counters "\Network Interface(*)\Packets Received Discarded")
    if($counterSamples -ne $null)
    {
        $osInformation.NetworkInformation.PacketsReceivedDiscarded = $counterSamples
    }
    $osInformation.ServerPendingReboot = (Get-ServerRebootPending -ServerName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions})
    $timeZoneInformation = Get-TimeZoneInformationRegistrySettings -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.TimeZone.DynamicDaylightTimeDisabled = $timeZoneInformation.DynamicDaylightTimeDisabled
    $osInformation.TimeZone.TimeZoneKeyName = $timeZoneInformation.TimeZoneKeyName
    $osInformation.TimeZone.StandardStart = $timeZoneInformation.StandardStart
    $osInformation.TimeZone.DaylightStart = $timeZoneInformation.DaylightStart
    $osInformation.TimeZone.DstIssueDetected = $timeZoneInformation.DstIssueDetected
    $osInformation.TimeZone.ActionsToTake = $timeZoneInformation.ActionsToTake
    $osInformation.TimeZone.CurrentTimeZone = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock {([System.TimeZone]::CurrentTimeZone).StandardName} -ScriptBlockDescription "Getting Current Time Zone" -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.TLSSettings = Get-AllTlsSettingsFromRegistry -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions} 
    $osInformation.VcRedistributable = Get-VisualCRedistributableVersion
    $osInformation.CredentialGuardEnabled = Get-CredentialGuardEnabled
    $osInformation.RegistryValues.CurrentVersionUbr = Invoke-RegistryGetValue `
        -MachineName $Script:Server `
        -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
        -GetValue "UBR" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $osInformation.RegistryValues.LanManServerDisabledCompression = Invoke-RegistryGetValue `
        -MachineName $Script:Server `
        -SubKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -GetValue "DisableCompression" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $getSmb1ServerSettings = Get-Smb1ServerSettings -ServerName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.Smb1ServerSettings.SmbServerConfiguration = $getSmb1ServerSettings.SmbServerConfiguration
    $osInformation.Smb1ServerSettings.WindowsFeature = $getSmb1ServerSettings.WindowsFeature
    $osInformation.Smb1ServerSettings.Smb1Status = $getSmb1ServerSettings.Smb1Status

    Write-VerboseOutput("Exiting: Get-OperatingSystemInformation")
    return $osInformation
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ServerType/Get-ServerType.ps1
Function Get-ServerType {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ServerType 
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Get-ServerType")
    $returnServerType = [string]::Empty
    if($ServerType -like "VMware*") { $returnServerType = "VMware"}
    elseif($ServerType -like "*Microsoft Corporation*") { $returnServerType = "HyperV" }
    elseif($ServerType.Length -gt 0) {$returnServerType = "Physical"}
    else { $returnServerType = "Unknown" }
    
    Write-VerboseWriter("Returning: {0}" -f $returnServerType)
    return $returnServerType 
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ProcessorInformation/Get-ProcessorInformation.ps1
Function Get-ProcessorInformation {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$MachineName,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-WmiObjectHandler/Get-WmiObjectHandler.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
    #>
    
    Write-VerboseWriter("Calling: Get-ProcessorInformation")
    $wmiObject = Get-WmiObjectHandler -ComputerName $MachineName -Class "Win32_Processor" -CatchActionFunction $CatchActionFunction 
    Write-VerboseWriter("Processor object type: {0}" -f ($wmiObjectType = $wmiObject.GetType().Name))
    $multiProcessorsDetected = $false 
    
    if($wmiObjectType -eq "ManagementObject")
    {
        $processorName = $wmiObject.Name
        $maxClockSpeed = $wmiObject.MaxClockSpeed 
        $multiProcessorsDetected = $true 
    }
    else 
    {
        $processorName = $wmiObject[0].Name 
        $maxClockSpeed = $wmiObject[0].MaxClockSpeed 
    }
    
    Write-VerboseWriter("Getting the total number of cores in the processor(s)")
    $processorIsThrottled = $false 
    $currentClockSpeed = 0
    $previousProcessor = $null 
    $differentProcessorsDetected = $false 
    $differentProcessorCoreCountDetected = $false 
    foreach($processor in $wmiObject)
    {
        $numberOfPhysicalCores += $processor.NumberOfCores 
        $numberOfLogicalCores += $processor.NumberOfLogicalProcessors 
        $numberOfProcessors++ 
    
        if($processor.CurrentClockSpeed -lt $processor.MaxClockSpeed)
        {
            Write-VerboseWriter("Processor is being throttled") 
            $processorIsThrottled = $true 
            $currentClockSpeed = $processor.CurrentClockSpeed 
        }
        if($previousProcessor -ne $null) 
        {
            if($processor.Name -ne $previousProcessor.Name -or 
            $processor.MaxClockSpeed -ne $previousProcessor.MaxMegacyclesPerCore)
            {
                Write-VerboseWriter("Different Processors are detected!!! This is an issue.")
                $differentProcessorsDetected = $true
            }
            if($processor.NumberOfLogicalProcessors -ne $previousProcessor.NumberOfLogicalProcessors)
            {
                Write-VerboseWriter("Different Processor core count per processor socket detected. This is an issue.")
                $differentProcessorCoreCountDetected = $true 
            }
        }
        $previousProcessor = $processor
    }
    Write-VerboseWriter("NumberOfPhysicalCores: {0} | NumberOfLogicalCores: {1} | NumberOfProcessors: {2} | ProcessorIsThrottled: {3} | CurrentClockSpeed: {4} | DifferentProcessorsDetected: {5} | DifferentProcessorCoreCountDetected: {6}" -f $numberOfPhysicalCores,
    $numberOfLogicalCores, $numberOfProcessors, $processorIsThrottled, $currentClockSpeed, $differentProcessorsDetected, $differentProcessorCoreCountDetected)
    
    $presentedProcessorCoreCount = Invoke-ScriptBlockHandler -ComputerName $MachineName -ScriptBlock {[System.Environment]::ProcessorCount} -ScriptBlockDescription "Trying to get the System.Environment ProcessorCount" -CatchActionFunction $CatchActionFunction 
    if($presentedProcessorCoreCount -eq $null) 
    {
        Write-VerboseWriter("Wasn't able to get Presented Processor Core Count on the Server. Setting to -1.")
        $presentedProcessorCoreCount = -1 
    }
    else 
    {
        Write-VerboseWriter("Presented Processor Core Count: {0}" -f $presentedProcessorCoreCount)
    }
    
    $processorInformationObject = New-Object PSCustomObject 
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $processorName
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "NumberOfPhysicalCores" -Value $numberOfPhysicalCores
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "NumberOfLogicalCores" -Value $numberOfLogicalCores
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "NumberOfProcessors" -Value $numberOfProcessors 
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "MaxMegacyclesPerCore" -Value $maxClockSpeed
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "CurrentMegacyclesPerCore" -Value $currentClockSpeed
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "ProcessorIsThrottled" -Value $processorIsThrottled 
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "DifferentProcessorsDetected" -Value $differentProcessorsDetected 
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "DifferentProcessorCoreCountDetected" -Value $differentProcessorCoreCountDetected
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "EnvironmentProcessorCount" -Value $presentedProcessorCoreCount 
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "ProcessorClassObject" -Value $wmiObject 
    
    Write-VerboseWriter("Exiting: Get-ProcessorInformation") 
    return $processorInformationObject 
    
}

Function Get-HardwareInformation {

    Write-VerboseOutput("Calling: Get-HardwareInformation")

    [HealthChecker.HardwareInformation]$hardware_obj = New-Object HealthChecker.HardwareInformation
    $system = Get-WmiObjectHandler -ComputerName $Script:Server -Class "Win32_ComputerSystem" -CatchActionFunction ${Function:Invoke-CatchActions}
    $hardware_obj.Manufacturer = $system.Manufacturer
    $hardware_obj.System = $system
    $hardware_obj.AutoPageFile = $system.AutomaticManagedPagefile
    $hardware_obj.TotalMemory = $system.TotalPhysicalMemory
    $hardware_obj.ServerType = (Get-ServerType -ServerType $system.Manufacturer)
    $processorInformation = Get-ProcessorInformation -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions} 

    #Need to do it this way because of Windows 2012R2
    $processor = New-Object HealthChecker.ProcessorInformation
    $processor.Name = $processorInformation.Name
    $processor.NumberOfPhysicalCores = $processorInformation.NumberOfPhysicalCores
    $processor.NumberOfLogicalCores = $processorInformation.NumberOfLogicalCores
    $processor.NumberOfProcessors = $processorInformation.NumberOfProcessors
    $processor.MaxMegacyclesPerCore = $processorInformation.MaxMegacyclesPerCore
    $processor.CurrentMegacyclesPerCore = $processorInformation.CurrentMegacyclesPerCore
    $processor.ProcessorIsThrottled = $processorInformation.ProcessorIsThrottled
    $processor.DifferentProcessorsDetected = $processorInformation.DifferentProcessorsDetected
    $processor.DifferentProcessorCoreCountDetected = $processorInformation.DifferentProcessorCoreCountDetected
    $processor.EnvironmentProcessorCount = $processorInformation.EnvironmentProcessorCount
    $processor.ProcessorClassObject = $processorInformation.ProcessorClassObject

    $hardware_obj.Processor = $processor
    $hardware_obj.Model = $system.Model 

    Write-VerboseOutput("Exiting: Get-HardwareInformation")
    return $hardware_obj
}

Function Get-ExchangeServerMaintenanceState {
param(
[Parameter(Mandatory=$false)][array]$ComponentsToSkip
)
    Write-VerboseOutput("Calling Function: Get-ExchangeServerMaintenanceState")

    [HealthChecker.ExchangeServerMaintenance]$serverMaintenance = New-Object -TypeName HealthChecker.ExchangeServerMaintenance
    $serverMaintenance.GetServerComponentState = Get-ServerComponentState -Identity $Script:Server -ErrorAction SilentlyContinue

    try
    {
        $serverMaintenance.GetMailboxServer = Get-MailboxServer -Identity $Script:Server -ErrorAction SilentlyContinue
    }
    catch
    {
        Write-VerboseOutput("Failed to run Get-MailboxServer")
        Invoke-CatchActions
    }

    try
    {
        $serverMaintenance.GetClusterNode = Get-ClusterNode -Name $Script:Server -ErrorAction Stop
    }
    catch
    {
        Write-VerboseOutput("Failed to run Get-ClusterNode")
        Invoke-CatchActions
    }

    Write-VerboseOutput("Running ServerComponentStates checks")

    foreach ($component in $serverMaintenance.GetServerComponentState)
    {
        if (($ComponentsToSkip -ne $null -and
            $ComponentsToSkip.Count -ne 0) -and
            $ComponentsToSkip -notcontains $component.Component)
        {
            if ($component.State -ne "Active")
            {
                $latestLocalState = $null
                $latestRemoteState = $null

                if ($component.LocalStates -ne $null)
                {
                    $latestLocalState = ($component.LocalStates | Sort-Object {$_.TimeStamp} -ErrorAction SilentlyContinue)[-1]
                }

                if ($component.RemoteStates -ne $null)
                {
                    $latestRemoteState = ($component.RemoteStates | Sort-Object {$_.TimeStamp} -ErrorAction SilentlyContinue)[-1]
                }

                Write-VerboseOutput("Component: {0} LocalState: '{1}' RemoteState: '{2}'" -f $component.Component, $latestLocalState.State, $latestRemoteState.State)

                if ($latestLocalState.State -eq $latestRemoteState.State)
                {
                    $serverMaintenance.InactiveComponents += "'{0}' is in Maintenance Mode" -f $component.Component
                }
                else
                {
                    if (($latestLocalState -ne $null) -and
                        ($latestLocalState.State -ne "Active"))
                    {
                        $serverMaintenance.InactiveComponents += "'{0}' is in Local Maintenance Mode only" -f $component.Component
                    }

                    if (($latestRemoteState -ne $null) -and
                        ($latestRemoteState.State -ne "Active"))
                    {
                        $serverMaintenance.InactiveComponents += "'{0}' is in Remote Maintenance Mode only" -f $component.Component
                    }
                }
            }
            else
            {
                Write-VerboseOutput("Component '{0}' is Active" -f $component.Component)
            }
        }
        else
        {
            Write-VerboseOutput("Component: {0} will be skipped" -f $component.Component)
        }
    }

    return $serverMaintenance
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-NETFrameworkVersion/Get-NETFrameworkVersion.ps1
Function Get-NETFrameworkVersion {
[CmdletBinding()]
param(
[string]$MachineName = $env:COMPUTERNAME,
[int]$NetVersionKey = -1,
[scriptblock]$CatchActionFunction
)
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
    #>
    
    Write-VerboseWriter("Calling: Get-NETFrameworkVersion")
    if ($NetVersionKey -eq -1)
    {
        [int]$NetVersionKey = Invoke-RegistryGetValue -MachineName $MachineName `
            -SubKey "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" `
            -GetValue "Release" `
            -CatchActionFunction $CatchActionFunction
    }
    
    #Using Minimum Version as per https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed?redirectedfrom=MSDN#minimum-version
    if ($NetVersionKey -lt 378389)
    {
        $friendlyName = "Unknown"
        $minValue = -1
    }
    elseif ($NetVersionKey -lt 378675)
    {
        $friendlyName = "4.5"
        $minValue = 378389
    }
    elseif ($NetVersionKey -lt 379893)
    {
        $friendlyName = "4.5.1"
        $minValue = 378675
    }
    elseif ($NetVersionKey -lt 393295)
    {
        $friendlyName = "4.5.2"
        $minValue = 379893
    }
    elseif ($NetVersionKey -lt 394254)
    {
        $friendlyName = "4.6"
        $minValue = 393295
    }
    elseif ($NetVersionKey -lt 394802)
    {
        $friendlyName = "4.6.1"
        $minValue = 394254
    }
    elseif ($NetVersionKey -lt 460798)
    {
        $friendlyName = "4.6.2"
        $minValue = 394802
    }
    elseif ($NetVersionKey -lt 461308)
    {
        $friendlyName = "4.7"
        $minValue = 460798
    }
    elseif ($NetVersionKey -lt 461808)
    {
        $friendlyName = "4.7.1"
        $minValue = 461308
    }
    elseif ($NetVersionKey -lt 528040)
    {
        $friendlyName = "4.7.2"
        $minValue = 461808
    }
    elseif ($NetVersionKey -ge 528040)
    {
        $friendlyName = "4.8"
        $minValue = 528040
    }
    
    $netObject = New-Object PSCustomObject
    $netObject | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $friendlyName
    $netObject | Add-Member -MemberType NoteProperty -Name "RegistryValue" -Value $NetVersionKey
    $netObject | Add-Member -MemberType NoteProperty -Name "MinimumValue" -Value $minValue
    
    Write-VerboseWriter("Returning FriendlyName: {0} | RegistryValue: {1}" -f $friendlyName, $NetVersionKey)
    
    return $netObject
}

Function Get-ExchangeMajorVersion {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][object]$AdminDisplayVersion 
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Get-ExchangeMajorVersion")
    Write-VerboseWriter("Passed: {0}" -f $AdminDisplayVersion.ToString())
    if($AdminDisplayVersion.GetType().Name -eq "string")
    {
        $split = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).split('.')
        $build = [int]$split[0] + ($split[1] / 10)
    }
    else 
    {
        $build = $AdminDisplayVersion.Major + ($AdminDisplayVersion.Minor / 10)
    }
    Write-VerboseWriter("Determing build based off of: {0}" -f $build)
    $exchangeMajorVersion = [string]::Empty
    switch($build)
    {
        14.3 {$exchangeMajorVersion = "Exchange2010"}
        15 {$exchangeMajorVersion = "Exchange2013"}
        15.1 {$exchangeMajorVersion = "Exchange2016"}
        15.2 {$exchangeMajorVersion = "Exchange2019"}
        default {$exchangeMajorVersion = "Unknown"}
    }
    Write-VerboseWriter("Returned: {0}" -f $exchangeMajorVersion)
    return $exchangeMajorVersion 
}

Function Get-ExchangeAppPoolsInformation {

    Write-VerboseOutput("Calling: Get-ExchangeAppPoolsInformation")

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
            if(!([System.String]::IsNullOrEmpty($config)) -and 
                (Test-Path $config))
            {
                $content = Get-Content $config 
            }
            else 
            {
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
    $exchangeAppPoolsInfo = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-ExchangeAppPoolsScriptBlock} -ScriptBlockDescription "Getting Exchange App Pool information" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Exiting: Get-ExchangeAppPoolsInformation")
    return $exchangeAppPoolsInfo
}

Function Get-ExchangeUpdates {
param(
[Parameter(Mandatory=$true)][HealthChecker.ExchangeMajorVersion]$ExchangeMajorVersion
)
    Write-VerboseOutput("Calling: Get-ExchangeUpdates")
    Write-VerboseOutput("Passed: {0}" -f $ExchangeMajorVersion.ToString())
    $RegLocation = [string]::Empty

    if([HealthChecker.ExchangeMajorVersion]::Exchange2013 -eq $ExchangeMajorVersion)
    {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2013"
    }
    elseif([HealthChecker.ExchangeMajorVersion]::Exchange2016 -eq $ExchangeMajorVersion) 
    {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2016"
    }
    else 
    {
        $RegLocation = "SOFTWARE\Microsoft\Updates\Exchange 2019"
    }

    $RegKey = Invoke-RegistryGetValue -MachineName $Script:Server -SubKey $RegLocation -ReturnAfterOpenSubKey $true -CatchActionFunction ${Function:Invoke-CatchActions}

    if($null -ne $RegKey)
    {
        $IU = $RegKey.GetSubKeyNames()
        if($null -ne $IU)
        {
            Write-VerboseOutput("Detected fixes installed on the server")
            $fixes = @()
            foreach($key in $IU)
            {
                $IUKey = $RegKey.OpenSubKey($key)
                $IUName = $IUKey.GetValue("PackageName")
                Write-VerboseOutput("Found: " + $IUName)
                $fixes += $IUName
            }
            return $fixes
        }
        else
        {
            Write-VerboseOutput("No IUs found in the registry")
        }
    }
    else
    {
        Write-VerboseOutput("No RegKey returned")
    }

    Write-VerboseOutput("Exiting: Get-ExchangeUpdates")
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
        return [HealthChecker.ExchangeServerRole]::MultiRole
    }
    elseif($roles -eq "Mailbox")
    {
        return [HealthChecker.ExchangeServerRole]::Mailbox
    }
    elseif($roles -eq "Edge")
    {
        return [HealthChecker.ExchangeServerRole]::Edge
    }
    elseif($roles -like "*ClientAccess*")
    {
        return [HealthChecker.ExchangeServerRole]::ClientAccess
    }
    else
    {
        return [HealthChecker.ExchangeServerRole]::None
    }
}

Function Get-ExSetupDetails {

    Write-VerboseOutput("Calling: Get-ExSetupDetails")
    $exSetupDetails = [string]::Empty
    Function Get-ExSetupDetailsScriptBlock {
        Get-Command ExSetup | ForEach-Object{$_.FileVersionInfo}
    }

    $exSetupDetails = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-ExSetupDetailsScriptBlock} -ScriptBlockDescription "Getting ExSetup remotely" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Exiting: Get-ExSetupDetails")
    return $exSetupDetails
}

Function Get-ExchangeInformation {
param(
[HealthChecker.OSServerVersion]$OSMajorVersion
)
    Write-VerboseOutput("Calling: Get-ExchangeInformation")
    Write-VerboseOutput("Passed: OSMajorVersion: {0}" -f $OSMajorVersion)
    [HealthChecker.ExchangeInformation]$exchangeInformation = New-Object -TypeName HealthChecker.ExchangeInformation
    $exchangeInformation.GetExchangeServer = (Get-ExchangeServer -Identity $Script:Server)
    $buildInformation = $exchangeInformation.BuildInformation 
    $buildInformation.MajorVersion = ([HealthChecker.ExchangeMajorVersion](Get-ExchangeMajorVersion -AdminDisplayVersion $exchangeInformation.GetExchangeServer.AdminDisplayVersion))
    $buildInformation.ServerRole = (Get-ServerRole -ExchangeServerObj $exchangeInformation.GetExchangeServer)
    $buildInformation.ExchangeSetup = Get-ExSetupDetails
        
    #Exchange 2013 or greater
    if($buildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013)
    {
        $netFrameworkExchange = $exchangeInformation.NETFramework
        $adminDisplayVersion = $exchangeInformation.GetExchangeServer.AdminDisplayVersion
        $revisionNumber = if($adminDisplayVersion.Revision -lt 10) {$adminDisplayVersion.Revision / 10} else {$adminDisplayVersion.Revision / 100 }
        $buildAndRevision = $adminDisplayVersion.Build + $revisionNumber
        Write-VerboseOutput("The build and revision number: {0}" -f $buildAndRevision)
        #Build Numbers: https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
        $buildInformation.BuildNumber = "{0}.{1}.{2}.{3}" -f $adminDisplayVersion.Major, $adminDisplayVersion.Minor, $adminDisplayVersion.Build, $adminDisplayVersion.Revision
        if($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019)
        {
            Write-VerboseOutput("Exchange 2019 is detected. Checking build number...")
            $buildInformation.FriendlyName = "Exchange 2019 "    
            
            #Exchange 2019 Information
            if($buildAndRevision -lt 221.12) { $buildInformation.CU = [HealthChecker.ExchangeCULevel]::Preview; $buildInformation.FriendlyName += "Preview"; $buildInformation.ReleaseDate = "07/24/2018" }
            elseif($buildAndRevision -lt 330.6) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::RTM; $buildInformation.FriendlyName += "RTM"; $buildInformation.ReleaseDate = "10/22/2018" }
            elseif($buildAndRevision -lt 397.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU1; $buildInformation.FriendlyName += "CU1"; $buildInformation.ReleaseDate = "02/12/2019"}
            elseif($buildAndRevision -lt 464.5) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU2; $buildInformation.FriendlyName += "CU2"; $buildInformation.ReleaseDate = "06/18/2019"}
            elseif($buildAndRevision -lt 529.5) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU3; $buildInformation.FriendlyName += "CU3"; $buildInformation.ReleaseDate = "09/17/2019"}
            elseif($buildAndRevision -lt 595.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU4; $buildInformation.FriendlyName += "CU4"; $buildInformation.ReleaseDate = "12/17/2019"}
            elseif($buildAndRevision -lt 659.4) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU5; $buildInformation.FriendlyName += "CU5"; $buildInformation.ReleaseDate = "03/17/2020"}
            elseif($buildAndRevision -lt 721.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU6; $buildInformation.FriendlyName += "CU6"; $buildInformation.ReleaseDate = "06/16/2020"; $buildInformation.SupportedBuild = $true}
            elseif($buildAndRevision -ge 721.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU7; $buildInformation.FriendlyName += "CU7"; $buildInformation.ReleaseDate = "09/15/2020"; $buildInformation.SupportedBuild = $true}
    
            #Exchange 2019 .NET Information
            if($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU2){$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU4){$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8}
            else { $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8 }
    
        }
        elseif($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016)
        {
            Write-VerboseOutput("Exchange 2016 is detected. Checking build number...")
            $buildInformation.FriendlyName = "Exchange 2016 "
    
            #Exchange 2016 Information
            if($buildAndRevision -lt 225.42) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::Preview; $buildInformation.FriendlyName += "Preview"; $buildInformation.ReleaseDate = "07/22/2015"}
            elseif($buildAndRevision -lt 396.30) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::RTM; $buildInformation.FriendlyName += "RTM"; $buildInformation.ReleaseDate = "10/01/2015"}
            elseif($buildAndRevision -lt 466.34) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU1; $buildInformation.FriendlyName += "CU1"; $buildInformation.ReleaseDate = "03/15/2016"}
            elseif($buildAndRevision -lt 544.27) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU2; $buildInformation.FriendlyName += "CU2"; $buildInformation.ReleaseDate = "06/21/2016"}
            elseif($buildAndRevision -lt 669.32) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU3; $buildInformation.FriendlyName += "CU3"; $buildInformation.ReleaseDate = "09/20/2016"}
            elseif($buildAndRevision -lt 845.34) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU4; $buildInformation.FriendlyName += "CU4"; $buildInformation.ReleaseDate = "12/13/2016"}
            elseif($buildAndRevision -lt 1034.26) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU5; $buildInformation.FriendlyName += "CU5"; $buildInformation.ReleaseDate = "03/21/2017"}
            elseif($buildAndRevision -lt 1261.35) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU6; $buildInformation.FriendlyName += "CU6"; $buildInformation.ReleaseDate = "06/24/2017"}
            elseif($buildAndRevision -lt 1415.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU7; $buildInformation.FriendlyName += "CU7"; $buildInformation.ReleaseDate = "09/16/2017"}
            elseif($buildAndRevision -lt 1466.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU8; $buildInformation.FriendlyName += "CU8"; $buildInformation.ReleaseDate = "12/19/2017"}
            elseif($buildAndRevision -lt 1531.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU9; $buildInformation.FriendlyName += "CU9"; $buildInformation.ReleaseDate = "03/20/2018"}
            elseif($buildAndRevision -lt 1591.10) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU10; $buildInformation.FriendlyName += "CU10"; $buildInformation.ReleaseDate = "06/19/2018"}
            elseif($buildAndRevision -lt 1713.5) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU11; $buildInformation.FriendlyName += "CU11"; $buildInformation.ReleaseDate = "10/16/2018"}
            elseif($buildAndRevision -lt 1779.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU12; $buildInformation.FriendlyName += "CU12"; $buildInformation.ReleaseDate = "02/12/2019"}
            elseif($buildAndRevision -lt 1847.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU13; $buildInformation.FriendlyName += "CU13"; $buildInformation.ReleaseDate = "06/18/2019"}
            elseif($buildAndRevision -lt 1913.5) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU14; $buildInformation.FriendlyName += "CU14"; $buildInformation.ReleaseDate = "09/17/2019"}
            elseif($buildAndRevision -lt 1979.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU15; $buildInformation.FriendlyName += "CU15"; $buildInformation.ReleaseDate = "12/17/2019"}
            elseif($buildAndRevision -lt 2044.4) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU16; $buildInformation.FriendlyName += "CU16"; $buildInformation.ReleaseDate = "03/17/2020"}
            elseif($buildAndRevision -lt 2106.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU17; $buildInformation.FriendlyName += "CU17"; $buildInformation.ReleaseDate = "06/16/2020"; $buildInformation.SupportedBuild = $true}
            elseif($buildAndRevision -ge 2106.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU18; $buildInformation.FriendlyName += "CU18"; $buildInformation.ReleaseDate = "09/15/2020"; $buildInformation.SupportedBuild = $true}
    
            #Exchange 2016 .NET Information
            if($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU2){$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix}
            elseif($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU2){$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d1wFix}
            elseif($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU3) 
            {
                if($OSMajorVersion -eq [HealthChecker.OSServerVersion]::Windows2016)
                {
                    $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                    $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                }
                else 
                {
                    $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                    $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d1wFix
                }
            }
            elseif($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU4) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU8) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU11) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU13) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU15) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8}
            else {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8}
        }
        else
        {
            Write-VerboseOutput("Exchange 2013 is detected. Checking build number...")
            $buildInformation.FriendlyName = "Exchange 2013 "
    
            #Exchange 2013 Information
            if($buildAndRevision -lt 620.29) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::RTM; $buildInformation.FriendlyName += "RTM"; $buildInformation.ReleaseDate = "12/03/2012"}
            elseif($buildAndRevision -lt 712.24) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU1; $buildInformation.FriendlyName += "CU1"; $buildInformation.ReleaseDate = "04/02/2013"}
            elseif($buildAndRevision -lt 775.38) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU2; $buildInformation.FriendlyName += "CU2"; $buildInformation.ReleaseDate = "07/09/2013"}
            elseif($buildAndRevision -lt 847.32) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU3; $buildInformation.FriendlyName += "CU3"; $buildInformation.ReleaseDate = "11/25/2013"}
            elseif($buildAndRevision -lt 913.22) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU4; $buildInformation.FriendlyName += "CU4"; $buildInformation.ReleaseDate = "02/25/2014"}
            elseif($buildAndRevision -lt 995.29) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU5; $buildInformation.FriendlyName += "CU5"; $buildInformation.ReleaseDate = "05/27/2014"}
            elseif($buildAndRevision -lt 1044.25) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU6; $buildInformation.FriendlyName += "CU6"; $buildInformation.ReleaseDate = "08/26/2014"}
            elseif($buildAndRevision -lt 1076.9) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU7; $buildInformation.FriendlyName += "CU7"; $buildInformation.ReleaseDate = "12/09/2014"}
            elseif($buildAndRevision -lt 1104.5) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU8; $buildInformation.FriendlyName += "CU8"; $buildInformation.ReleaseDate = "03/17/2015"}
            elseif($buildAndRevision -lt 1130.7) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU9; $buildInformation.FriendlyName += "CU9"; $buildInformation.ReleaseDate = "06/17/2015"}
            elseif($buildAndRevision -lt 1156.6) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU10; $buildInformation.FriendlyName += "CU10"; $buildInformation.ReleaseDate = "09/15/2015"}
            elseif($buildAndRevision -lt 1178.4) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU11; $buildInformation.FriendlyName += "CU11"; $buildInformation.ReleaseDate = "12/15/2015"}
            elseif($buildAndRevision -lt 1210.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU12; $buildInformation.FriendlyName += "CU12"; $buildInformation.ReleaseDate = "03/15/2016"}
            elseif($buildAndRevision -lt 1236.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU13; $buildInformation.FriendlyName += "CU13"; $buildInformation.ReleaseDate = "06/21/2016"}
            elseif($buildAndRevision -lt 1263.5) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU14; $buildInformation.FriendlyName += "CU14"; $buildInformation.ReleaseDate = "09/20/2016"}
            elseif($buildAndRevision -lt 1293.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU15; $buildInformation.FriendlyName += "CU15"; $buildInformation.ReleaseDate = "12/13/2016"}
            elseif($buildAndRevision -lt 1320.4) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU16; $buildInformation.FriendlyName += "CU16"; $buildInformation.ReleaseDate = "03/21/2017"}
            elseif($buildAndRevision -lt 1347.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU17; $buildInformation.FriendlyName += "CU17"; $buildInformation.ReleaseDate = "06/24/2017"}
            elseif($buildAndRevision -lt 1365.1) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU18; $buildInformation.FriendlyName += "CU18"; $buildInformation.ReleaseDate = "09/16/2017"}
            elseif($buildAndRevision -lt 1367.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU19; $buildInformation.FriendlyName += "CU19"; $buildInformation.ReleaseDate = "12/19/2017"}
            elseif($buildAndRevision -lt 1395.4) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU20; $buildInformation.FriendlyName += "CU20"; $buildInformation.ReleaseDate = "03/20/2018"}
            elseif($buildAndRevision -lt 1473.3) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU21; $buildInformation.FriendlyName += "CU21"; $buildInformation.ReleaseDate = "06/19/2018"}
            elseif($buildAndRevision -lt 1497.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU22; $buildInformation.FriendlyName += "CU22"; $buildInformation.ReleaseDate = "02/12/2019"}
            elseif($buildAndRevision -ge 1497.2) {$buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU23; $buildInformation.FriendlyName += "CU23"; $buildInformation.ReleaseDate = "06/18/2019"; $buildInformation.SupportedBuild = $true}
    
            #Exchange 2013 .NET Information
            if($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU12){$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU15) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d1wFix}
            elseif($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU15) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU19) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2}
            elseif($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU21) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1}
            elseif($buildInformation.CU -le [HealthChecker.ExchangeCULevel]::CU22) {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2}
            else {$netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2; $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8}
        }
    
        $exchangeInformation.MapiHttpEnabled = (Get-OrganizationConfig).MapiHttpEnabled

        if ($buildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge)
        {
            $exchangeInformation.ApplicationPools = Get-ExchangeAppPoolsInformation
        }

        $buildInformation.KBsInstalled = Get-ExchangeUpdates -ExchangeMajorVersion $buildInformation.MajorVersion
        $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage = Invoke-RegistryGetValue -MachineName $Script:Server -SubKey "SOFTWARE\Microsoft\ExchangeServer\v15\Search\SystemParameters" -GetValue "CtsProcessorAffinityPercentage" -CatchActionFunction ${Function:Invoke-CatchActions}
        $exchangeInformation.ServerMaintenance = Get-ExchangeServerMaintenanceState -ComponentsToSkip "ForwardSyncDaemon","ProvisioningRps"
        if($buildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::ClientAccess)
        {
            $exchangeInformation.ExchangeServicesNotRunning = Test-ServiceHealth -Server $Script:Server | %{$_.ServicesNotRunning}
        }
    }
    elseif($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2010)
    {
        Write-VerboseOutput("Exchange 2010 detected.")
        $buildInformation.FriendlyName = "Exchange 2010"
        $buildInformation.BuildNumber = $exchangeInformation.GetExchangeServer.AdminDisplayVersion.ToString()
    }
    
    Write-VerboseOutput("Exiting: Get-ExchangeInformation")
    return $exchangeInformation
}

Function Get-HealthCheckerExchangeServer {

    Write-VerboseOutput("Calling: Get-HealthCheckerExchangeServer")

    [HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj = New-Object -TypeName HealthChecker.HealthCheckerExchangeServer 
    $HealthExSvrObj.ServerName = $Script:Server 
    $HealthExSvrObj.HardwareInformation = Get-HardwareInformation
    $HealthExSvrObj.OSInformation = Get-OperatingSystemInformation
    $HealthExSvrObj.ExchangeInformation = Get-ExchangeInformation -OSMajorVersion $HealthExSvrObj.OSInformation.BuildInformation.MajorVersion
    if($HealthExSvrObj.ExchangeInformation.BuildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013)
    {
        $netFrameworkVersion = Get-NETFrameworkVersion -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $HealthExSvrObj.OSInformation.NETFramework.FriendlyName = $netFrameworkVersion.FriendlyName
        $HealthExSvrObj.OSInformation.NETFramework.RegistryValue = $netFrameworkVersion.RegistryValue
        $HealthExSvrObj.OSInformation.NETFramework.NetMajorVersion = $netFrameworkVersion.MinimumValue
        $HealthExSvrObj.OSInformation.NETFramework.FileInformation = Get-DotNetDllFileVersions -ComputerName $Script:Server -FileNames @("System.Data.dll","System.Configuration.dll") -CatchActionFunction ${Function:Invoke-CatchActions}

        if ($netFrameworkVersion.MinimumValue -eq $HealthExSvrObj.ExchangeInformation.NETFramework.MaxSupportedVersion)
        {
            $HealthExSvrObj.ExchangeInformation.NETFramework.OnRecommendedVersion = $true
        }
    }
    $HealthExSvrObj.HealthCheckerVersion = $healthCheckerVersion
    Write-VerboseOutput("Finished building health Exchange Server Object for server: " + $Script:Server)
    return $HealthExSvrObj
}

Function Get-MailboxDatabaseAndMailboxStatistics {

    Write-VerboseOutput("Calling: Get-MailboxDatabaseAndMailboxStatistics")

    $AllDBs = Get-MailboxDatabaseCopyStatus -server $Script:Server -ErrorAction SilentlyContinue 
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
        Write-Grey("`tTotal Active Mailboxes on server " + $Script:Server + ": " + ($TotalActiveUserMailboxCount + $TotalActivePublicFolderMailboxCount).ToString())
    }
    else
    {
        Write-Grey("`tNo Active Mailbox Databases found on server " + $Script:Server + ".")
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
        Write-Grey("`tNo Passive Mailboxes found on server " + $Script:Server + ".")
    }
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
		Write-Grey("Site filtering ON.  Only Exchange 2013/2016 CAS servers in {0} will be used in the report." -f $SiteName)
		$CASServers = Get-ExchangeServer | Where-Object{($_.IsClientAccessServer -eq $true) -and ($_.AdminDisplayVersion -Match "^Version 15") -and ($_.Site.Name -eq $SiteName)}
	}
    else
    {
		Write-Grey("Site filtering OFF.  All Exchange 2013/2016 CAS servers will be used in the report.")
        $CASServers = Get-ExchangeServer | Where-Object{($_.IsClientAccessServer -eq $true) -and ($_.AdminDisplayVersion -Match "^Version 15")}
    }

	if($CASServers.Count -eq 0)
	{
		Write-Red("Error: No CAS servers found using the specified search criteria.")
		Exit
	}
    
    #Request stats from perfmon for all CAS
    $PerformanceCounters = @()
    $PerformanceCounters += "\Web Service(Default Web Site)\Current Connections"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Autodiscover)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_EWS)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_mapi)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Microsoft-Server-ActiveSync)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_owa)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Rpc)\Requests Executing"

    try
    {
        $AllCounterResults = Get-Counter -ComputerName $CASServers -Counter $PerformanceCounters
    }
    catch 
    {
        Invoke-CatchActions
        Write-VerboseOutput("Failed to get counter samples")
    }

    ForEach($Result in $AllCounterResults.CounterSamples)
    {
        $CasName = ($Result.Path).Split("\\",[System.StringSplitOptions]::RemoveEmptyEntries)[0]
        $ResultCookedValue = $Result.CookedValue

        if($Result.Path -like "*{0}*{1}" -f $CasName,$PerformanceCounters[0])
        {
            #Total connections
            $CASConnectionStats.Add($CasName,$ResultCookedValue)
            $TotalCASConnectionCount += $ResultCookedValue
        }
        elseif($Result.Path -like "*{0}*{1}" -f $CasName,$PerformanceCounters[1])
        {
            #AutoD requests
            $AutoDStats.Add($CasName,$ResultCookedValue)
            $TotalAutoDRequests += $ResultCookedValue
        }
        elseif($Result.Path -like "*{0}*{1}" -f $CasName,$PerformanceCounters[2])
        {
            #EWS requests
            $EWSStats.Add($CasName,$ResultCookedValue)
            $TotalEWSRequests += $ResultCookedValue
        }
        elseif($Result.Path -like "*{0}*{1}" -f $CasName,$PerformanceCounters[3])
        {
            #MapiHttp requests
            $MapiHttpStats.Add($CasName,$ResultCookedValue)
            $TotalMapiHttpRequests += $ResultCookedValue
        }
        elseif($Result.Path -like "*{0}*{1}" -f $CasName,$PerformanceCounters[4])
        {
            #EAS requests
            $EASStats.Add($CasName,$ResultCookedValue)
            $TotalEASRequests += $ResultCookedValue
        }
        elseif($Result.Path -like "*{0}*{1}" -f $CasName,$PerformanceCounters[5])
        {
            #OWA requests
            $OWAStats.Add($CasName,$ResultCookedValue)
            $TotalOWARequests += $ResultCookedValue
        }
        elseif($Result.Path -like "*{0}*{1}" -f $CasName,$PerformanceCounters[6])
        {
            #RPCHTTP requests
            $RpcHttpStats.Add($CasName,$ResultCookedValue)
            $TotalRpcHttpRequests += $ResultCookedValue
        }
    }


    #Report the results for connection count
    Write-Grey("")
    Write-Grey("Connection Load Distribution Per Server")
    Write-Grey("Total Connections: {0}" -f $TotalCASConnectionCount)
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
        Write-Grey("Total Requests: {0}" -f $TotalAutoDRequests)
        $AutoDStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalAutoDRequests)*100)) + "% Distribution")
        }
    }

    #EWS
    if($TotalEWSRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current EWS Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalEWSRequests)
        $EWSStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalEWSRequests)*100)) + "% Distribution")
        }
    }

    #MapiHttp
    if($TotalMapiHttpRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current MapiHttp Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalMapiHttpRequests)
        $MapiHttpStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalMapiHttpRequests)*100)) + "% Distribution")
        }
    }

    #EAS
    if($TotalEASRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current EAS Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalEASRequests)
        $EASStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalEASRequests)*100)) + "% Distribution")
        }
    }

    #OWA
    if($TotalOWARequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current OWA Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalOWARequests)
        $OWAStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalOWARequests)*100)) + "% Distribution")
        }
    }

    #RpcHttp
    if($TotalRpcHttpRequests -gt 0)
    {
        Write-Grey("")
        Write-Grey("Current RpcHttp Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalRpcHttpRequests)
        $RpcHttpStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value/$TotalRpcHttpRequests)*100)) + "% Distribution")
        }
    }
    Write-Grey("")
}

Function Get-LmCompatibilityLevelInformation {

    Write-VerboseOutput("Calling: Get-LmCompatibilityLevelInformation")

    [HealthChecker.LmCompatibilityLevelInformation]$ServerLmCompatObject = New-Object -TypeName HealthChecker.LmCompatibilityLevelInformation
    $ServerLmCompatObject.RegistryValue = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Script:Server -SubKey "SYSTEM\CurrentControlSet\Control\Lsa" -GetValue "LmCompatibilityLevel" -CatchActionFunction ${Function:Invoke-CatchActions} -DefaultValue 3
    Switch ($ServerLmCompatObject.RegistryValue)
    {
        0 {$ServerLmCompatObject.Description = "Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        1 {$ServerLmCompatObject.Description = "Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        2 {$ServerLmCompatObject.Description = "Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication." }
        3 {$ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        4 {$ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2." }
        5 {$ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2." }
    }

    Write-VerboseOutput("Exiting: Get-LmCompatibilityLevelInformation")
    Return $ServerLmCompatObject
}

Function New-DisplayResultsGroupingKey {
param(
[string]$Name,
[bool]$DisplayGroupName = $true,
[int]$DisplayOrder,
[int]$DefaultTabNumber = 1
)
    $obj = New-Object HealthChecker.DisplayResultsGroupingKey
    $obj.Name = $Name
    $obj.DisplayGroupName = $DisplayGroupName
    $obj.DisplayOrder = $DisplayOrder
    $obj.DefaultTabNumber = $DefaultTabNumber
    return $obj
}

Function Add-AnalyzedResultInformation {
param(
[object]$Details,
[string]$Name,
[string]$HtmlName,
[object]$DisplayGroupingKey,
[int]$DisplayCustomTabNumber = -1,
[object]$DisplayTestingValue,
[string]$DisplayWriteType = "Grey",
[bool]$AddDisplayResultsLineInfo = $true,
[bool]$AddHtmlDetailRow = $true,
[string]$HtmlDetailsCustomValue = "",
[bool]$AddHtmlOverviewValues = $false,
[bool]$AddHtmlActionRow = $false,
[string]$ActionSettingClass = "",
[string]$ActionSettingValue,
[string]$ActionRecommendedDetailsClass = "",
[string]$ActionRecommendedDetailsValue,
[string]$ActionMoreInformationClass = "",
[string]$ActionMoreInformationValue,
[HealthChecker.AnalyzedInformation]$AnalyzedInformation
)

    Write-VerboseOutput("Calling Add-AnalyzedResultInformation: {0}" -f $name)

    if ($AddDisplayResultsLineInfo)
    {
        if (!($AnalyzedInformation.DisplayResults.ContainsKey($DisplayGroupingKey)))
        {
            Write-VerboseOutput("Adding Display Grouping Key: {0}" -f $DisplayGroupingKey.Name)
            [System.Collections.Generic.List[HealthChecker.DisplayResultsLineInfo]]$list = New-Object System.Collections.Generic.List[HealthChecker.DisplayResultsLineInfo]
            $AnalyzedInformation.DisplayResults.Add($DisplayGroupingKey, $list)
        }

        $lineInfo = New-Object HealthChecker.DisplayResultsLineInfo
        $lineInfo.DisplayValue = $Details
        $lineInfo.Name = $Name

        if ($DisplayCustomTabNumber -ne -1)
        {
            $lineInfo.TabNumber = $DisplayCustomTabNumber
        }
        else
        {
            $lineInfo.TabNumber = $DisplayGroupingKey.DefaultTabNumber
        }

        if ($DisplayTestingValue -ne $null)
        {
            $lineInfo.TestingValue = $DisplayTestingValue
        }
        else
        {
            $lineInfo.TestingValue = $Details
        }

        $lineInfo.WriteType = $DisplayWriteType
        $AnalyzedInformation.DisplayResults[$DisplayGroupingKey].Add($lineInfo)
    }

    if ($AddHtmlDetailRow)
    {
        if (!($analyzedResults.HtmlServerValues.ContainsKey("ServerDetails")))
        {
            [System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]]$list = New-Object System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]
            $AnalyzedInformation.HtmlServerValues.Add("ServerDetails", $list)
        }

        $detailRow = New-Object HealthChecker.HtmlServerInformationRow

        if ($displayWriteType -ne "Grey")
        {
            $detailRow.Class = $displayWriteType
        }

        if ([string]::IsNullOrEmpty($HtmlName))
        {
            $detailRow.Name = $Name
        }
        else
        {
            $detailRow.Name = $HtmlName
        }

        if ([string]::IsNullOrEmpty($HtmlDetailsCustomValue))
        {
            $detailRow.DetailValue = $Details
        }
        else
        {
            $detailRow.DetailValue = $HtmlDetailsCustomValue
        }

        $AnalyzedInformation.HtmlServerValues["ServerDetails"].Add($detailRow)
    }

    if ($AddHtmlOverviewValues)
    {
        if (!($analyzedResults.HtmlServerValues.ContainsKey("OverviewValues")))
        {
            [System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]]$list = New-Object System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]
            $AnalyzedInformation.HtmlServerValues.Add("OverviewValues", $list)
        }

        $overviewValue = New-Object HealthChecker.HtmlServerInformationRow

        if ($displayWriteType -ne "Grey")
        {
            $overviewValue.Class = $displayWriteType
        }

        if ([string]::IsNullOrEmpty($HtmlName))
        {
            $overviewValue.Name = $Name
        }
        else
        {
            $overviewValue.Name = $HtmlName
        }
        
        if ([string]::IsNullOrEmpty($HtmlDetailsCustomValue))
        {
            $overviewValue.DetailValue = $Details
        }
        else
        {
            $overviewValue.DetailValue = $HtmlDetailsCustomValue
        }

        $AnalyzedInformation.HtmlServerValues["OverviewValues"].Add($overviewValue)
    }

    if ($AddHtmlActionRow)
    {
        #TODO
    }

    return $AnalyzedInformation
}

Function Start-AnalyzerEngine {
param(
[HealthChecker.HealthCheckerExchangeServer]$HealthServerObject
)
    Write-VerboseOutput("Calling: Start-AnalyzerEngine")

    $analyzedResults = New-Object HealthChecker.AnalyzedInformation
    $analyzedResults.HealthCheckerExchangeServer = $HealthServerObject

    #Display Grouping Keys
    $order = 0
    $keyBeginningInfo = New-DisplayResultsGroupingKey -Name "BeginningInfo" -DisplayGroupName $false -DisplayOrder ($order++) -DefaultTabNumber 0
    $keyExchangeInformation = New-DisplayResultsGroupingKey -Name "Exchange Information"  -DisplayOrder ($order++)
    $keyOSInformation = New-DisplayResultsGroupingKey -Name "Operating System Information" -DisplayOrder ($order++)
    $keyHardwareInformation = New-DisplayResultsGroupingKey -Name "Processor/Hardware Information" -DisplayOrder ($order++)
    $keyNICSettings = New-DisplayResultsGroupingKey -Name "NIC Settings Per Active Adapter" -DisplayOrder ($order++) -DefaultTabNumber 2
    $keyFrequentConfigIssues = New-DisplayResultsGroupingKey -Name "Frequent Configuration Issues" -DisplayOrder ($order++)
    $keySecuritySettings = New-DisplayResultsGroupingKey -Name "Security Settings" -DisplayOrder ($order++)
    $keyWebApps = New-DisplayResultsGroupingKey -Name "Exchange Web App Pools" -DisplayOrder ($order++)

    #Set short cut variables
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation

    if (!$Script:DisplayedScriptVersionAlready)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Exchange Health Checker Version" -Details $Script:healthCheckerVersion `
            -DisplayGroupingKey $keyBeginningInfo `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ($HealthServerObject.HardwareInformation.ServerType -eq [HealthChecker.ServerType]::VMWare -or
        $HealthServerObject.HardwareInformation.ServerType -eq [HealthChecker.ServerType]::HyperV)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Details $VirtualizationWarning -DisplayWriteType "Yellow" `
            -DisplayGroupingKey $keyBeginningInfo `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    #########################
    # Exchange Information
    #########################
    Write-VerboseOutput("Working on Exchange Information")

    $analyzedResults = Add-AnalyzedResultInformation -Name "Name" -Details ($HealthServerObject.ServerName) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Server Name" `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Version" -Details ($exchangeInformation.BuildInformation.FriendlyName) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Exchange Version" `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Build Number" -Details ($exchangeInformation.BuildInformation.BuildNumber) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AnalyzedInformation $analyzedResults

    if ($exchangeInformation.BuildInformation.SupportedBuild -eq $false)
    {
        $daysOld = ($date - ([System.Convert]::ToDateTime([DateTime]$exchangeInformation.BuildInformation.ReleaseDate))).Days

        $analyzedResults = Add-AnalyzedResultInformation -Name "Error" -Details ("Out of date Cumulative Update. Please upgrade to one of the two most recently released Cumulative Updates. Currently running on a build that is {0} days old." -f $daysOld) `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Red" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ($exchangeInformation.BuildInformation.KBsInstalled -ne $null)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Details ("Exchange IU or Security Hotfix Detected.") `
            -DisplayGroupingKey $keyExchangeInformation `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults

        foreach ($kb in $exchangeInformation.BuildInformation.KBsInstalled)
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details $kb `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Server Role" -Details ($exchangeInformation.BuildInformation.ServerRole) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "MAPI/HTTP Enabled" -Details ($exchangeInformation.MapiHttpEnabled) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AnalyzedInformation $analyzedResults

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013 -and
        $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge)
    {
        $content = [xml]$exchangeInformation.ApplicationPools["MSExchangeMapiFrontEndAppPool"].Content
        [bool]$enabled = $content.Configuration.Runtime.gcServer.Enabled -eq "true"
        [bool]$unknown = $content.Configuration.Runtime.gcServer.Enabled -ne "true" -and $content.Configuration.Runtime.gcServer.Enabled -ne "false"
        $warning = [string]::Empty
        $displayWriteType = "Green"
        $displayValue = "Server"

        if ($hardwareInformation.TotalMemory -ge 21474836480 -and
            $enabled -eq $false)
        {
            $displayWriteType = "Red"
            $displayValue = "Workstation --- Error"
            $warning = "To Fix this issue go into the file MSExchangeMapiFrontEndAppPool_CLRConfig.config in the Exchange Bin directory and change the GCServer to true and recycle the MAPI Front End App Pool"
        }
        elseif ($unknown)
        {
            $displayValue = "Unknown --- Warning"
            $displayWriteType = "Yellow"
        }
        elseif (!($enabled))
        {
            $displayWriteType = "Yellow"
            $displayValue = "Workstation --- Warning"
            $warning = "You could be seeing some GC issues within the Mapi Front End App Pool. However, you don't have enough memory installed on the system to recommend switching the GC mode by default without consulting a support professional."
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "MAPI Front End App Pool GC Mode" -Details $displayValue `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType $displayWriteType `
            -AnalyzedInformation $analyzedResults

        if ($warning -ne [string]::Empty)
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details $warning `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    ##############################
    # Exchange Server Maintenance
    ##############################
    Write-VerboseOutput("Working on Exchange Server Maintenance")
    $serverMaintenance = $exchangeInformation.ServerMaintenance

    if (($serverMaintenance.InactiveComponents).Count -eq 0 -and
        ($serverMaintenance.GetClusterNode -eq $null -or
            $serverMaintenance.GetClusterNode.State -eq "Up") -and
        ($serverMaintenance.GetMailboxServer -eq $null -or
            ($serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -eq $false -and
            $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy -eq "Unrestricted")))
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Exchange Server Maintenace" -Details "Server is not in Maintenance Mode" `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Green" `
            -AnalyzedInformation $analyzedResults
    }
    else
    {
        $analyzedResults = Add-AnalyzedResultInformation -Details "Exchange Server Maintenace" `
            -DisplayGroupingKey $keyExchangeInformation `
            -AnalyzedInformation $analyzedResults

        if (($serverMaintenance.InactiveComponents).Count -ne 0)
        {
            foreach ($inactiveComponent in $serverMaintenance.InactiveComponents)
            {
                $analyzedResults = Add-AnalyzedResultInformation -Name "Component" -Details $inactiveComponent `
                    -DisplayGroupingKey $keyExchangeInformation `
                    -DisplayCustomTabNumber 2  `
                    -DisplayWriteType "Yellow" `
                    -AnalyzedInformation $analyzedResults
            }
        }

        if ($serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -or
            $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy -eq "Blocked")
        {
            $displayValue = "`r`n`t`tDatabaseCopyActivationDisabledAndMoveNow: {0} --- should be 'false'`r`n`t`tDatabaseCopyAutoActivationPolicy: {1} --- should be 'unrestricted'" -f `
                $serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow,
                $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy

            $analyzedResults = Add-AnalyzedResultInformation -Name "Database Copy Maintenance" -Details $displayValue `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }

        if ($serverMaintenance.GetClusterNode -ne $null -and $serverMaintenance.GetClusterNode.State -ne "Up")
        {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Cluster Node" -Details ("'{0}' --- should be 'Up'" -f $serverMaintenance.GetClusterNode.State) `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }
    }

    #########################
    # Operating System
    #########################
    Write-VerboseOutput("Working on Operating System")

    $analyzedResults = Add-AnalyzedResultInformation -Name "Version" -Details ($osInformation.BuildInformation.FriendlyName) `
        -DisplayGroupingKey $keyOSInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "OS Version" `
        -AnalyzedInformation $analyzedResults

    $upTime = "{0} day(s) {1} hour(s) {2} minute(s) {3} second(s)" -f $osInformation.ServerBootUp.Days,
        $osInformation.ServerBootUp.Hours,
        $osInformation.ServerBootUp.Minutes,
        $osInformation.ServerBootUp.Seconds

    $analyzedResults = Add-AnalyzedResultInformation -Name "System Up Time" -Details $upTime `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayTestingValue ($osInformation.ServerBootUp) `
        -AddHtmlDetailRow $false `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Time Zone" -Details ($osInformation.TimeZone.CurrentTimeZone) `
        -DisplayGroupingKey $keyOSInformation `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    $writeValue = $false
    $warning = @("Windows can not properly detect any DST rule changes in your time zone. Set 'Adjust for daylight saving time automatically to on'")

    if ($osInformation.TimeZone.DstIssueDetected)
    {
        $writeType = "Red"
    }
    elseif ($osInformation.TimeZone.DynamicDaylightTimeDisabled -ne 0)
    {
        $writeType = "Yellow"
    }
    else 
    {
        $warning = [string]::Empty
        $writeValue = $true
        $writeType = "Grey"
    }
    
    $analyzedResults = Add-AnalyzedResultInformation -Name "Dynamic Daylight Time Enabled" -Details $writeValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $writeType `
        -AnalyzedInformation $analyzedResults

    if ($warning -ne [string]::Empty)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Details $warning `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ([string]::IsNullOrEmpty($osInformation.TimeZone.TimeZoneKeyName))
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Time Zone Key Name" -Details "Empty --- Warning Need to switch your current time zone to a different value, then switch it back to have this value populated again." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -AnalyzedInformation $analyzedResults
    }

    if ($exchangeInformation.NETFramework.OnRecommendedVersion)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name ".NET Framework" -Details ($osInformation.NETFramework.FriendlyName) `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Green" `
            -AddHtmlOverviewValues $true `
            -AnalyzedInformation $analyzedResults
    }
    else
    {
        $testObject = New-Object PSCustomObject
        $testObject | Add-Member -MemberType NoteProperty -Name "CurrentValue" -Value ($osInformation.NETFramework.FriendlyName)
        $testObject | Add-Member -MemberType NoteProperty -Name "MaxSupportedVersion" -Value ($exchangeInformation.NETFramework.MaxSupportedVersion)
        $displayFriendly = Get-NETFrameworkVersion -NetVersionKey $exchangeInformation.NETFramework.MaxSupportedVersion
        $displayValue = "{0} - Warning Recommended .NET Version is {1}" -f $osInformation.NETFramework.FriendlyName, $displayFriendly.FriendlyName
        $analyzedResults = Add-AnalyzedResultInformation -Name ".NET Framework" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayTestingValue $testObject `
            -HtmlDetailsCustomValue ($osInformation.NETFramework.FriendlyName) `
            -AddHtmlOverviewValues $true `
            -AnalyzedInformation $analyzedResults
    }

    $displayValue = [string]::Empty
    $displayWriteType = "Yellow"
    Write-VerboseOutput("Total Memory: {0}" -f ($totalPhysicalMemory = $hardwareInformation.TotalMemory))
    Write-VerboseOutput("Page File: {0}" -f ($maxPageSize = $osInformation.PageFile.MaxPageSize))
    $testingValue = New-Object PSCustomObject
    $testingValue | Add-Member -MemberType NoteProperty -Name "TotalPhysicalMemory" -Value $totalPhysicalMemory
    $testingValue | Add-Member -MemberType NoteProperty -Name "MaxPageSize" -Value $maxPageSize
    $testingValue | Add-Member -MemberType NoteProperty -Name "MultiPageFile" -Value ($osInformation.PageFile.PageFile.Count -gt 1)
    $testingValue | Add-Member -MemberType NoteProperty -Name "RecommendedPageFile" -Value 0
    if ($maxPageSize -eq 0)
    {
        $displayValue = "Error: System is set to automatically manage the pagefile size."
        $displayWriteType = "Red"
    }
    elseif ($osInformation.PageFile.PageFile.Count -gt 1)
    {
        $displayValue = "Multiple page files detected. `r`n`t`tError: This has been know to cause performance issues please address this."
        $displayWriteType = "Red"
    }
    elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019)
    {
        $testingValue.RecommendedPageFile = ($recommendedPageFileSize = [Math]::Truncate(($totalPhysicalMemory / 1MB) / 4))
        Write-VerboseOutput("Recommended Page File Size: {0}" -f $recommendedPageFileSize)
        if ($recommendedPageFileSize -ne $maxPageSize)
        {
            $displayValue = "{0}MB `r`n`t`tWarning: Page File is not set to 25% of the Total System Memory which is {1}MB. Recommended is {2}MB" -f $maxPageSize, ([Math]::Truncate($totalPhysicalMemory / 1MB)), $recommendedPageFileSize
        }
        else
        {
            $displayValue = "{0}MB" -f $recommendedPageFileSize
            $displayWriteType = "Grey"
        }
    }
    #32GB = 1024 * 1024 * 1024 * 32 = 34,359,738,368 
    elseif ($totalPhysicalMemory -ge 34359738368)
    {
        if ($maxPageSize -eq 32778)
        {
            $displayValue = "{0}MB" -f $maxPageSize
            $displayValue = "Grey"
        }
        else
        {
            $displayValue = "{0}MB `r`n`t`tWarning: Pagefile should be capped at 32778MB for 32GB plus 10MB - Article: https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#pagefile" -f $maxPageSize
        }
    }
    else
    {
        $testingValue.RecommendedPageFile = ($recommendedPageFileSize = [Math]::Round(($totalPhysicalMemory / 1MB) + 10))
        if ($recommendedPageFileSize -ne $maxPageSize)
        {
            $displayValue = "{0}MB `r`n`t`tWarning: Page File is not set to Total System Memory plus 10MB which should be {1}MB" -f $maxPageSize, $recommendedPageFileSize
        }
        else
        {
            $displayValue = "{0}MB" -f $maxPageSize
            $displayWriteType = "Grey"
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Page File Size" -Details $displayValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $testingValue `
        -AnalyzedInformation $analyzedResults

    if ($osInformation.PowerPlan.HighPerformanceSet)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Power Plan" -Details ($osInformation.PowerPlan.PowerPlanSetting) `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Green" `
            -AnalyzedInformation $analyzedResults
    }
    else
    {
        $displayValue = "{0} --- Error" -f $osInformation.PowerPlan.PowerPlanSetting
        $analyzedResults = Add-AnalyzedResultInformation -Name "Power Plan" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Red" `
            -AnalyzedInformation $analyzedResults
    }

    if ($osInformation.NetworkInformation.HttpProxy -eq "<None>")
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Http Proxy Setting" -Details ($osInformation.NetworkInformation.HttpProxy) `
            -DisplayGroupingKey $keyOSInformation `
            -HtmlDetailsCustomValue "None" `
            -AnalyzedInformation $analyzedResults
    }
    else
    {
        $displayValue = "{0} --- Warning this can cause client connectivity issues." -f $osInformation.NetworkInformation.HttpProxy
        $analyzedResults = Add-AnalyzedResultInformation -Name "Http Proxy Setting" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayTestingValue ($osInformation.NetworkInformation.HttpProxy) `
            -AnalyzedInformation $analyzedResults
    }

    $displayWriteType2012 = "Yellow"
    $displayWriteType2013 = "Yellow"
    $displayValue2012 = "Unknown"
    $displayValue2013 = "Unknown"

    if ($osInformation.VcRedistributable -ne $null)
    {
        Write-VerboseOutput("VCRedist2012 Testing value: {0}" -f [HealthChecker.VCRedistVersion]::VCRedist2012.value__)
        Write-VerboseOutput("VCRedist2013 Testing value: {0}" -f [HealthChecker.VCRedistVersion]::VCRedist2013.value__)
        $vc2013Required = $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge
        $displayValue2012 = "Redistributable is outdated"
        $displayValue2013 = "Redistributable is outdated"

        foreach ($detectedVisualRedistVersion in $osInformation.VcRedistributable)
        {
            Write-VerboseOutput("Testing {0} version id '{1}'" -f $detectedVisualRedistVersion.DisplayName, $detectedVisualRedistVersion.VersionIdentifier)

            if ($detectedVisualRedistVersion.VersionIdentifier -eq [HealthChecker.VCRedistVersion]::VCRedist2012)
            {
                $displayValue2012 = "{0} Version is current" -f $detectedVisualRedistVersion.DisplayVersion
                $displayWriteType2012 = "Green"
            }
            elseif ($vc2013Required -and
                $detectedVisualRedistVersion.VersionIdentifier -eq [HealthChecker.VCRedistVersion]::VCRedist2013)
            {
                $displayWriteType2013 = "Green"
                $displayValue2013 = "{0} Version is current" -f $detectedVisualRedistVersion.DisplayVersion
            }
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Visual C++ 2012" -Details $displayValue2012 `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType2012 `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Visual C++ 2013" -Details $displayValue2013 `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType2013 `
        -AnalyzedInformation $analyzedResults

    if ($osInformation.VcRedistributable -ne $null -and
        ($displayWriteType2012 -eq "Yellow" -or
        $displayWriteType2013 -eq "Yellow"))
    {
        $analyzedResults = Add-AnalyzedResultInformation -Details "Note: For more information about the latest C++ Redistributeable please visit: https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads`r`n`t`tThis is not a requirement to upgrade, only a notification to bring to your attention." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Yellow" `
            -AnalyzedInformation $analyzedResults
    }

    $displayValue = "False"
    $writeType = "Grey"

    if ($osInformation.ServerPendingReboot)
    {
        $displayValue = "True --- Warning a reboot is pending and can cause issues on the server."
        $writeType = "Yellow"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Server Pending Reboot" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType $writeType `
            -DisplayTestingValue ($osInformation.ServerPendingReboot) `
            -AnalyzedInformation $analyzedResults

    ################################
    # Processor/Hardware Information
    ################################
    Write-VerboseOutput("Working on Processor/Hardware Information")

    $analyzedResults = Add-AnalyzedResultInformation -Name "Type" -Details ($hardwareInformation.ServerType) `
        -DisplayGroupingKey $keyHardwareInformation `
        -AddHtmlOverviewValues $true `
        -Htmlname "Hardware Type" `
        -AnalyzedInformation $analyzedResults

    if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
        $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Manufacturer" -Details ($hardwareInformation.Manufacturer) `
            -DisplayGroupingKey $keyHardwareInformation `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Model" -Details ($hardwareInformation.Model) `
            -DisplayGroupingKey $keyHardwareInformation `
            -AnalyzedInformation $analyzedResults
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Processor" -Details ($hardwareInformation.Processor.Name) `
        -DisplayGroupingKey $keyHardwareInformation `
        -AnalyzedInformation $analyzedResults

    $value = $hardwareInformation.Processor.NumberOfProcessors
    $processorName = "Number of Processors"

    if ($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::Physical)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name $processorName -Details $value `
            -DisplayGroupingKey $keyHardwareInformation `
            -AnalyzedInformation $analyzedResults

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::VMWare)
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details "Note: Please make sure you are following VMware's performance recommendation to get the most out of your guest machine. VMware blog 'Does corespersocket Affect Performance?' https://blogs.vmware.com/vsphere/2013/10/does-corespersocket-affect-performance.html" `
                -DisplayGroupingKey $keyHardwareInformation `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }
    }
    elseif ($value -gt 2)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name $processorName -Details ("{0} - Error: Recommended to only have 2 Processors" -f $value) `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $value `
            -HtmlDetailsCustomValue $value `
            -AnalyzedInformation $analyzedResults
    }
    else
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name $processorName -Details $value `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Green" `
            -AnalyzedInformation $analyzedResults
    }

    $physicalValue = $hardwareInformation.Processor.NumberOfPhysicalCores
    $logicalValue = $hardwareInformation.Processor.NumberOfLogicalCores

    $displayWriteType = "Green"

    if (($logicalValue -gt 24 -and
        $exchangeInformation.BuildInformation.MajorVersion -lt [HealthChecker.ExchangeMajorVersion]::Exchange2019) -or
        $logicalValue -gt 48)
    {
        $displayWriteType = "Yellow"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Number of Physical Cores" -Details $physicalValue `
    -DisplayGroupingKey $keyHardwareInformation `
    -DisplayWriteType $displayWriteType `
    -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Number of Logical Cores" -Details $logicalValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    if ($logicalValue -gt $physicalValue)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Hyper-Threading" -Details "Enabled --- Error: Having Hyper-Threading enabled goes against best practices and can cause performance issues. Please disable as soon as possible." `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $true `
            -AnalyzedInformation $analyzedResults

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details "Error: For high-performance computing (HPC) application, like Exchange, Amazon recommends that you have Hyper-Threading Technology disabled in their service. More informaiton: https://aws.amazon.com/blogs/compute/disabling-intel-hyper-threading-technology-on-amazon-ec2-windows-instances/" `
                -DisplayGroupingKey $keyHardwareInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }

        if ($hardwareInformation.Processor.Name.StartsWith("AMD"))
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details "This script may incorrectly report that Hyper-Threading is enabled on certain AMD processors. Check with the manufacturer to see if your mondel supports SMT." `
                -DisplayGroupingKey $keyHardwareInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }
    else
    {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Hyper-Threading" -Details "Disabled" `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Green" `
            -DisplayTestingValue $false `
            -AnalyzedInformation $analyzedResults
    }

    #NUMA BIOS CHECK - AKA check to see if we can properly see all of our cores on the box
    $displayWriteType = "Yellow"
    $testingValue = "Unknown"
    $displayValue = [string]::Empty
    if ($hardwareInformation.Model.Contains("ProLiant"))
    {
        $name = "NUMA Group Size Optimization"
        if ($hardwareInformation.Processor.EnvironmentProcessorCount -eq -1)
        {
            $displayValue = "Unknown `r`n`t`tWarning: If this is set to Clustered, this can cause multiple types of issues on the server"
        }
        elseif ($hardwareInformation.Processor.EnvironmentProcessorCount -ne $logicalValue)
        {
            $displayValue = "Clustered `r`n`t`tError: This setting should be set to Flat. By having this set to Clustered, we will see multiple different types of issues."
            $testingValue = "Clustered"
            $displayWriteType = "Red"
        }
        else
        {
            $displayValue = "Flat"
            $testingValue = "Flat"
            $displayWriteType = "Green"
        }
    }
    else
    {
        $name = "All Processor Cores Visible"
        if ($hardwareInformation.Processor.EnvironmentProcessorCount -eq -1)
        {
            $displayValue = "Unknown `r`n`t`tWarning: If we aren't able to see all processor cores from Exchange, we could see performance related issues."
        }
        elseif ($hardwareInformation.Processor.EnvironmentProcessorCount -ne $logicalValue)
        {
            $displayValue = "Failed `r`n`t`tError: Not all Processor Cores are visible to Exchange and this will cause a performance impact"
            $displayWriteType = "Red"
            $testingValue = "Failed"
        }
        else
        {
            $displayWriteType = "Green"
            $displayValue = "Passed"
            $testingValue = "Passed"
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name $name -Details $displayValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $testingValue `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Max Processor Speed" -Details ($hardwareInformation.Processor.MaxMegacyclesPerCore) `
        -DisplayGroupingKey $keyHardwareInformation `
        -AnalyzedInformation $analyzedResults

    if ($hardwareInformation.Processor.ProcessorIsThrottled)
    {
        $currentSpeed = $hardwareInformation.Processor.CurrentMegacyclesPerCore
        $analyzedResults = Add-AnalyzedResultInformation -Name "Current Processor Speed" -Details ("{0} --- Error: Processor appears to be throttled." -f $currentSpeed) `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $currentSpeed `
            -AnalyzedInformation $analyzedResults

        $displayValue = "Error: Power Plan is NOT set to `"High Performance`". This change doesn't require a reboot and takes affect right away. Re-run script after doing so"

        if ($osInformation.PowerPlan.HighPerformanceSet)
        {
            $displayValue = "Error: Power Plan is set to `"High Performance`", so it is likely that we are throttling in the BIOS of the computer settings."
        }

        $analyzedResults = Add-AnalyzedResultInformation -Details $displayValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType "Red" `
        -AddHtmlDetailRow $false `
        -AnalyzedInformation $analyzedResults
    }

    $totalPhysicalMemory = [System.Math]::Round($hardwareInformation.TotalMemory / 1024 / 1024 / 1024)
    $displayWriteType = "Yellow"
    $displayDetails = [string]::Empty

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019)
    {
        if ($totalPhysicalMemory -gt 256)
        {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 256 GB of Memory" -f $totalPhysicalMemory
        }
        elseif ($totalPhysicalMemory -lt 64 -and
            $exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::Edge)
        {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 64GB of RAM installed on the machine." -f $totalPhysicalMemory
        }
        elseif ($totalPhysicalMemory -lt 128)
        {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 128GB of RAM installed on the machine." -f $totalPhysicalMemory
        }
        else
        {
            $displayDetails = "{0} GB" -f $totalPhysicalMemory
            $displayWriteType = "Grey"
        }
    }
    elseif ($totalPhysicalMemory -gt 128 -and
        $exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016)
    {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 192 GB of Memory." -f $totalPhysicalMemory
    }
    elseif ($totalPhysicalMemory -gt 96)
    {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 96GB of Memory." -f $totalPhysicalMemory
    }
    else
    {
        $displayDetails = "{0} GB" -f $totalPhysicalMemory
        $displayWriteType = "Grey"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Physical Memory" -Details $displayDetails `
        -DisplayGroupingKey $keyHardwareInformation `
        -DipslayTestingValue $totalPhysicalMemory `
        -DisplayWriteType $displayWriteType `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    ################################
    #NIC Settings Per Active Adapter
    ################################
    Write-VerboseOutput("Working on NIC Settings Per Active Adapter Information")

    foreach ($adapter in $osInformation.NetworkInformation.NetworkAdapters)
    {
        if ($adapter.Description -eq "Remote NDIS Compatible Device")
        {
            Write-VerboseOutput("Remote NDSI Compatible Device found. Ignoring NIC.")
            continue
        }

        $value = "{0} [{1}]" -f $adapter.Description, $adapter.Name
        $analyzedResults = Add-AnalyzedResultInformation -Name "Interface Description" -Details $value `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults

        if ($osInformation.BuildInformation.MajorVersion -ge [HealthChecker.OSServerVersion]::Windows2012R2)
        {
            Write-VerboseOutput("On Windows 2012 R2 or new. Can provide more details on the NICs")

            $driverDate = $adapter.DriverDate
            $detailsValue = $driverDate

            if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
                $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
            {
                if ($driverDate -eq $null -or
                    $driverDate -eq [DateTime]::MaxValue)
                {
                    $detailsValue = "Unknown"
                }
                elseif ((New-TimeSpan -Start $date -End $driverDate).Days -lt [int]-365)
                {
                    $analyzedResults = Add-AnalyzedResultInformation -Details "Warning: NIC driver is over 1 year old. Verify you are at the latest version." `
                        -DisplayGroupingKey $keyNICSettings `
                        -DisplayWriteType "Yellow" `
                        -AddHtmlDetailRow $false `
                        -AnalyzedInformation $analyzedResults
                }
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Driver Date" -Details $detailsValue `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Name "Driver Version" -Details ($adapter.DriverVersion) `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Name "MTU Size" -Details ($adapter.MTUSize) `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $writeType = "Yellow"
            $testingValue = $null

            if ($adapter.RssEnabledValue -eq 0)
            {
                $detailsValue = "False --- Warning: Enabling RSS is recommended."
                $testingValue = $false
            }
            elseif ($adapter.RssEnabledValue -eq 1)
            {
                $detailsValue = "True"
                $testingValue = $true
                $writeType = "Green"
            }
            else
            {
                $detailsValue = "No RSS Feature Detected."
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "RSS Enabled" -Details $detailsValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType $writeType `
                -DisplayTestingValue $testingValue `
                -AnalyzedInformation $analyzedResults
        }
        else
        {
            Write-VerboseOutput("On Windows 2012 or older and can't get advanced NIC settings")
        }

        $linkSpeed = $adapter.LinkSpeed
        $displayValue = "{0} --- This may not be accurate due to virtualized hardware" -f $linkSpeed

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or 
                $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
        {
            $displayValue = $linkSpeed
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Link Speed" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayTestingValue $linkSpeed `
            -AnalyzedInformation $analyzedResults

        $displayValue = "{0}" -f $adapter.IPv6Enabled
        $displayWriteType = "Grey"
        $testingValue = $adapter.IPv6Enabled

        if ($osInformation.NetworkInformation.IPv6DisabledComponents -ne 255 -and
            $adapter.IPv6Enabled -eq $false)
        {
            $displayValue = "{0} --- Warning" -f $adapter.IPv6Enabled
            $displayWriteType = "Yellow"
            $testingValue = $false
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "IPv6 Enabled" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayWriteType $displayWriteType `
            -DisplayTestingValue $TestingValue `
            -AnalyzedInformation $analyzedResults
        
        $analyzedResults = Add-AnalyzedResultInformation -Name "IPv4 Address" `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults
        
        foreach ($address in $adapter.IPv4Addresses)
        {
            $displayValue = "{0}\{1}" -f $address.Address, $address.Subnet
            
            if ($address.DefaultGateway -ne [string]::Empty)
            {
                $displayValue += " Gateway: {0}" -f $address.DefaultGateway
            }        

            $analyzedResults = Add-AnalyzedResultInformation -Name "Address" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayCustomTabNumber 3 `
                -AnalyzedInformation $analyzedResults
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "IPv6 Address" `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults

        foreach ($address in $adapter.IPv6Addresses)
        {
            $displayValue = "{0}\{1}" -f $address.Address, $address.Subnet
            
            if ($address.DefaultGateway -ne [string]::Empty)
            {
                $displayValue += " Gateway: {0}" -f $address.DefaultGateway
            }        

            $analyzedResults = Add-AnalyzedResultInformation -Name "Address" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayCustomTabNumber 3 `
                -AnalyzedInformation $analyzedResults
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "DNS Server" -Details $adapter.DnsServer `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Registered In DNS" -Details $adapter.RegisteredInDns `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults

        #Assuming that all versions of Hyper-V doesn't allow sleepy NICs
        if ($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::HyperV)
        {
            $displayWriteType = "Grey"
            $displayValue = $adapter.SleepyNicDisabled

            if (!$adapter.SleepyNicDisabled)
            {
                $displayWriteType = "Yellow"
                $displayValue = "False --- Warning: It's recommended to disable NIC power saving options`r`n`t`t`tMore Information: http://support.microsoft.com/kb/2740020"
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Sleepy NIC Disabled" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType $displayWriteType `
                -DisplayTestingValue $adapter.SleepyNicDisabled `
                -AnalyzedInformation $analyzedResults
        }

        $adapterDescription = $adapter.Description
        $cookedValue = 0
        $foundCounter = $false

        if ($osInformation.NetworkInformation.PacketsReceivedDiscarded -eq $null)
        {
            Write-VerboseOutput("PacketsReceivedDiscarded is null")
            continue
        }

        foreach ($prdInstance in $osInformation.NetworkInformation.PacketsReceivedDiscarded)
        {
            $instancePath = $prdInstance.Path
            $startIndex = $instancePath.IndexOf("(") + 1
            $charLength = $instancePath.Substring($startIndex, ($instancePath.IndexOf(")") - $startIndex)).Length
            $instanceName = $instancePath.Substring($startIndex, $charLength)
            $possibleInstanceName = $adapterDescription.Replace("#","_")

            if ($instanceName -eq $adapterDescription -or
                $instanceName -eq $possibleInstanceName)
            {
                $cookedValue = $prdInstance.CookedValue
                $foundCounter = $true
                break
            }
        }

        $displayWriteType = "Yellow"
        $displayValue = $cookedValue
        $baseDisplayValue = "{0} --- {1}: This value should be at 0."
        $knownIssue = $false

        if ($foundCounter)
        {
            if ($cookedValue -eq 0)
            {
                $displayWriteType = "Green"
            }
            elseif ($cookedValue -lt 1000)
            {
                $displayValue = $baseDisplayValue -f $cookedValue, "Warning"
            }
            else
            {
                $displayWriteType = "Red"
                $displayValue = [string]::Concat(($baseDisplayValue -f $cookedValue, "Error"), "We are also seeing this value being rather high so this can cause a performance impacted on a system.")
            }

            if ($adapterDescription -like "*vmxnet3*" -and
                $cookedValue -gt 0)
            {
                $knownIssue = $true
            }
        }
        else
        {
            $displayValue = "Couldn't find value for the counter."
            $cookedValue = $null
            $displayWriteType = "Grey"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Packets Received Discarded" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayTestingValue $cookedValue `
            -DisplayWriteType $displayWriteType `
            -AnalyzedInformation $analyzedResults

        if ($knownIssue)
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details "Known Issue with vmxnet3: 'Large packet loss at the guest operating system level on the VMXNET3 vNIC in ESXi (2039495)' - https://kb.vmware.com/s/article/2039495" `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 3 `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    if ($osInformation.NetworkInformation.NetworkAdapters.Count -gt 1)
    {
        $analyzedResults = Add-AnalyzedResultInformation -Details "Multiple active network adapters detected. Exchange 2013 or greater may not need separate adapters for MAPI and replication traffic.  For details please refer to https://docs.microsoft.com/en-us/exchange/planning-for-high-availability-and-site-resilience-exchange-2013-help#NR" `
            -DisplayGroupingKey $keyNICSettings `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ($osInformation.NetworkInformation.IPv6DisabledOnNICs)
    {
        $displayWriteType = "Grey"
        $displayValue = "True"
        $testingValue = $true
        if ($osInformation.NetworkInformation.IPv6DisabledComponents -ne 255)
        {
            $displayWriteType = "Red"
            $testingValue = $false
            $displayValue = "False `r`n`t`tError: IPv6 is disabled on some NIC level settings but not fully disabled. DisabledComponents registry key currently set to '{0}'. For details please refer to the following articles: `r`n`t`thttps://docs.microsoft.com/en-us/archive/blogs/rmilne/disabling-ipv6-and-exchange-going-all-the-way `r`n`t`thttps://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users" -f $osInformation.NetworkInformation.DisabledComponents
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Disable IPv6 Correctly" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayWriteType $displayWriteType `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults
    }

    ################
    #TCP/IP Settings
    ################
    Write-VerboseOutput("Working on TCP/IP Settings")

    $tcpKeepAlive = $osInformation.NetworkInformation.TCPKeepAlive

    if ($tcpKeepAlive -eq 0)
    {
        $displayValue = "Not Set `r`n`t`tError: Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration. `r`n`t`tMore details: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792"
        $displayWriteType = "Red"
    }
    elseif ($tcpKeepAlive -lt 900000 -or
        $tcpKeepAlive -gt 1800000)
    {
        $displayValue = "{0} `r`n`t`tWarning: Not configured optimally, recommended value between 15 to 30 minutes (900000 and 1800000 decimal). `r`n`t`tMore details: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792" -f $tcpKeepAlive
        $displayWriteType = "Yellow"
    }
    else
    {
        $displayValue = $tcpKeepAlive
        $displayWriteType = "Green"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "TCP/IP Settings" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $tcpKeepAlive `
        -HtmlName "TCPKeepAlive" `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "RPC Min Connection Timeout" -Details ("{0} `r`n`t`tMore Information: https://blogs.technet.microsoft.com/messaging_with_communications/2012/06/06/outlook-anywhere-network-timeout-issue/" -f $osInformation.NetworkInformation.RpcMinConnectionTimeout) `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -HtmlName "RPC Minimum Connection Timeout" `
        -AnalyzedInformation $analyzedResults

    $displayValue = $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    $displayWriteType = "Green"

    if ($exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage -ne 0)
    {
        $displayWriteType = "Red"
        $displayValue = "{0} `r`n`t`tError: This can cause an impact to the server's search performance. This should only be used a temporary fix if no other options are available vs a long term solution." -f $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "CTS Processor Affinity Percentage" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue ($exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage) `
        -HtmlName "CtsProcessorAffinityPercentage" `
        -AnalyzedInformation $analyzedResults

    $displayValue = $osInformation.CredentialGuardEnabled
    $displayWriteType = "Grey"

    if($osInformation.CredentialGuardEnabled)
    {
        $displayValue = "{0} `r`n`t`tError: Credential Guard is not supported on an Exchange Server. This can cause a performance hit on the server." -f $osInformation.CredentialGuardEnabled
        $displayWriteType = "Red"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Credential Guard Enabled" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "LmCompatibilityLevel Settings" -Details ($osInformation.LmCompatibility.RegistryValue) `
        -DisplayGroupingKey $keySecuritySettings `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Description" -Details ($osInformation.LmCompatibility.Description) `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayCustomTabNumber 2 `
        -AddHtmlDetailRow $false `
        -AnalyzedInformation $analyzedResults

    ##############
    # TLS Settings
    ##############
    Write-VerboseOutput("Working on TLS Settings")

    $tlsVersions = @("1.0","1.1","1.2")
    $currentNetVersion = $osInformation.TLSSettings["NETv4"]

    foreach ($tlsKey in $tlsVersions)
    {
        $currentTlsVersion = $osInformation.TLSSettings[$tlsKey]

        $analyzedResults = Add-AnalyzedResultInformation -Details ("TLS {0}" -f $tlsKey) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Server Enabled") -Details ($currentTlsVersion.ServerEnabled) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Server Disabled By Default") -Details ($currentTlsVersion.ServerDisabledByDefault) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Client Enabled") -Details ($currentTlsVersion.ClientEnabled) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Client Disabled By Default") -Details ($currentTlsVersion.ClientDisabledByDefault) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        if ($currentTlsVersion.ServerEnabled -ne $currentTlsVersion.ClientEnabled)
        {
            $detectedTlsMismatch = $true
            $analyzedResults = Add-AnalyzedResultInformation -Details ("Error: Mismatch in TLS version for client and server. Exchange can be both client and a server. This can cause issues within Exchange for communication.") `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }

        if (($tlsKey -eq "1.0" -or
            $tlsKey -eq "1.1") -and (
            $currentTlsVersion.ServerEnabled -eq $false -or
            $currentTlsVersion.ClientEnabled -eq $false -or
            $currentTlsVersion.ServerDisabledByDefault -or
            $currentTlsVersion.ClientDisabledByDefault) -and
            ($currentNetVersion.SystemDefaultTlsVersions -eq $false -or
            $currentNetVersion.WowSystemDefaultTlsVersions -eq $false))
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details ("Error: Failed to set .NET SystemDefaultTlsVersions. Please visit on how to properly enable TLS 1.2 https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761") `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }
    }

    if ($detectedTlsMismatch)
    {
        $displayValues = @("Exchange Server TLS guidance Part 1: Getting Ready for TLS 1.2: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-part-1-Getting-Ready-for-TLS-1-2/ba-p/607649",
        "Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761",
        "Exchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-3-Turning-Off-TLS-1-0-1-1/ba-p/607898")

        $analyzedResults = Add-AnalyzedResultInformation -Details "For More Information on how to properly set TLS follow these blog posts:" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Yellow" `
            -AnalyzedInformation $analyzedResults

        foreach ($displayValue in $displayValues)
        {
            $analyzedResults = Add-AnalyzedResultInformation -Details $displayValue `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 3 `
                -AnalyzedInformation $analyzedResults
        }
    }

    $additionalDisplayValue = [string]::Empty
    $smb1Status = $osInformation.Smb1ServerSettings.Smb1Status

    if ($osInformation.BuildInformation.MajorVersion -gt [HealthChecker.OSServerVersion]::Windows2012)
    {
        $displayValue = "False"
        $writeType = "Green"

        if ($smb1Status -band 1)
        {
            $displayValue = "Failed to get install status"
            $writeType = "Yellow"
        }
        elseif ($smb1Status -band 2)
        {
            $displayValue = "True"
            $writeType = "Red"
            $additionalDisplayValue = "SMB1 should be uninstalled"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "SMB1 Installed" -Details $displayValue `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType $writeType `
            -AnalyzedInformation $analyzedResults
    }

    $writeType = "Green"
    $displayValue = "True"

    if ($smb1Status -band 8)
    {
        $displayValue = "Failed to get block status"
        $writeType = "Yellow"
    }
    elseif ($smb1Status -band 16)
    {
        $displayValue = "False"
        $writeType = "Red"
        $additionalDisplayValue += " SMB1 should be blocked" 
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "SMB1 Blocked" -Details $displayValue `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayWriteType $writeType `
        -AnalyzedInformation $analyzedResults
    
    if ($additionalDisplayValue -ne [string]::Empty)
    {
        $additionalDisplayValue += "`r`n`t`tMore Information: https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-and-smbv1/ba-p/1165615"

        $analyzedResults = Add-AnalyzedResultInformation -Details $additionalDisplayValue.Trim() `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Yellow" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    ##########################
    #Exchange Web App GC Mode#
    ##########################
    if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge)
    {
        Write-VerboseOutput("Working on Exchange Web App GC Mode")

        $analyzedResults = Add-AnalyzedResultInformation -Name "Web App Pool" -Details "GC Server Mode Enabled | Status" `
            -DisplayGroupingKey $keyWebApps `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults

        foreach ($webAppKey in $exchangeInformation.ApplicationPools.Keys)
        {
            $xmlData = [xml]$exchangeInformation.ApplicationPools[$webAppKey].Content
            $testingValue = New-Object PSCustomObject
            $testingValue | Add-Member -MemberType NoteProperty -Name "GCMode" -Value ($enabled = $xmlData.Configuration.Runtime.gcServer.Enabled -eq 'true')
            $testingValue | Add-Member -MemberType NoteProperty -Name "Status" -Value ($status = $exchangeInformation.ApplicationPools[$webAppKey].Status)

            $analyzedResults = Add-AnalyzedResultInformation -Name $webAppKey -Details ("{0} | {1}" -f $enabled, $status) `
                -DisplayGroupingKey $keyWebApps `
                -DisplayTestingValue $testingValue `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    ######################
    # Vulnerability Checks
    ######################

    Function Test-VulnerabilitiesByBuildNumbersForDisplay {
    param(
    [Parameter(Mandatory=$true)][string]$ExchangeBuildRevision,
    [Parameter(Mandatory=$true)][array]$SecurityFixedBuilds,
    [Parameter(Mandatory=$true)][array]$CVENames
    )
        [int]$fileBuildPart = ($split = $ExchangeBuildRevision.Split("."))[0]
        [int]$filePrivatePart = $split[1]

        foreach ($securityFixedBuild in $SecurityFixedBuilds)
        {
            [int]$securityFixedBuildPart = ($split = $securityFixedBuild.Split("."))[0]
            [int]$securityFixedPrivatePart = $split[1]

            if (($fileBuildPart -lt $securityFixedBuildPart) -or
                ($fileBuildPart -eq $securityFixedBuildPart -and
                $filePrivatePart -lt $securityFixedPrivatePart))
            {
                foreach ($cveName in $CVENames)
                {
                    $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerability" -Details ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0} for more information." -f $cveName) `
                        -DisplayGroupingKey $keySecuritySettings `
                        -DisplayTestingValue $cveName `
                        -DisplayWriteType "Red" `
                        -AddHtmlDetailRow $false `
                        -AnalyzedInformation $Script:AnalyzedInformation
                }

                $Script:AllVulnerabilitiesPassed = $false
                break
            }
        }
    }

    $Script:AllVulnerabilitiesPassed = $true
    $Script:AnalyzedInformation = $analyzedResults
    [string]$buildRevision = ("{0}.{1}" -f $exchangeInformation.BuildInformation.ExchangeSetup.FileBuildPart, $exchangeInformation.BuildInformation.ExchangeSetup.FilePrivatePart)

    Write-VerboseOutput("Exchange Build Revision: {0}" -f $buildRevision)
    Write-VerboseOutput("Exchange CU: {0}" -f ($exchangeCU = $exchangeInformation.BuildInformation.CU))

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013)
    {
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU19)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1347.5","1365.3" -CVENames "CVE-2018-0924","CVE-2018-0940"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU20)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1365.7","1367.6" -CVENames "CVE-2018-8151","CVE-2018-8154","CVE-2018-8159"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU21)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1367.9","1395.7" -CVENames "CVE-2018-8302"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1395.8" -CVENames "CVE-2018-8265","CVE-2018-8448"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1395.10" -CVENames "CVE-2019-0586","CVE-2019-0588"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU22)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1473.3" -CVENames "CVE-2019-0686","CVE-2019-0724"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1473.4" -CVENames "CVE-2019-0817","CVE-2019-0858"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1473.5" -CVENames "ADV190018"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU23)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.3" -CVENames "CVE-2019-1084","CVE-2019-1136","CVE-2019-1137"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.4" -CVENames "CVE-2019-1373"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.6" -CVENames "CVE-2020-0688","CVE-2020-0692"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.7" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.8" -CVENames "CVE-2020-17083","CVE-2020-17084","CVE-2020-17085"
        }
    }
    elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016)
    {
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU8)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1261.39","1415.4" -CVENames "CVE-2018-0924","CVE-2018-0940","CVE-2018-0941"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU9)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1415.7","1466.8" -CVENames "CVE-2018-8151","CVE-2018-8152","CVE-2018-8153","CVE-2018-8154","CVE-2018-8159"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU10)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1466.9","1531.6" -CVENames "CVE-2018-8374","CVE-2018-8302"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1531.8" -CVENames "CVE-2018-8265","CVE-2018-8448"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU11)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1531.8","1591.11" -CVENames "CVE-2018-8604"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1531.10","1591.13" -CVENames "CVE-2019-0586","CVE-2019-0588"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU12)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1591.16","1713.6" -CVENames "CVE-2019-0817","CVE-2018-0858"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1591.17","1713.7" -CVENames "ADV190018"
	        Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1713.5" -CVENames "CVE-2019-0686","CVE-2019-0724"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU13)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1713.8","1779.4" -CVENames "CVE-2019-1084","CVE-2019-1136","CVE-2019-1137"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1713.9","1779.5" -CVENames "CVE-2019-1233","CVE-2019-1266"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU14)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1779.7","1847.5" -CVENames "CVE-2019-1373"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU15)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1847.7","1913.7" -CVENames "CVE-2020-0688","CVE-2020-0692"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1847.10","1913.10" -CVENames "CVE-2020-0903"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU17)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1979.6","2044.6" -CVENames "CVE-2020-16875"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU18)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.7","2106.3" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.8","2106.4" -CVENames "CVE-2020-17083","CVE-2020-17084","CVE-2020-17085"
        }
    }
    elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019)
    {
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU1)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "221.14" -CVENames "CVE-2019-0586","CVE-2019-0588"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "221.16","330.7" -CVENames "CVE-2019-0817","CVE-2019-0858"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "221.17","330.8" -CVENames "ADV190018"
	        Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "330.6" -CVENames "CVE-2019-0686","CVE-2019-0724"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU2)
        {
	        Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "330.9","397.5" -CVENames "CVE-2019-1084","CVE-2019-1137"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "397.6","330.10" -CVENames "CVE-2019-1233","CVE-2019-1266"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU3)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "397.9","464.7" -CVENames "CVE-2019-1373"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU4)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "464.11","529.8" -CVENames "CVE-2020-0688","CVE-2020-0692"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "464.14","529.11" -CVENames "CVE-2020-0903"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU6)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "595.6","659.6" -CVENames "CVE-2020-16875"
        }
        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU7)
        {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.7","721.3" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.8","721.4" -CVENames "CVE-2020-17083","CVE-2020-17084","CVE-2020-17085"
        }
    }
    else
    {
        Write-VerboseOutput("Unknown Version of Exchange")
        $Script:AllVulnerabilitiesPassed = $false
    }

    #Description: Check for CVE-2020-0796 SMBv3 vulnerability
    #Affected OS versions: Windows 10 build 1903 and 1909
    #Fix: KB4551762
    #Workaround: Disable SMBv3 compression

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019)
    {
        Write-VerboseOutput("Testing CVE: CVE-2020-0796")
        $buildNumber = $osInformation.BuildInformation.VersionBuild.Split(".")[2]

        if (($buildNumber -eq 18362 -or
            $buildNumber -eq 18363) -and
            ($osInformation.RegistryValues.CurrentVersionUbr -lt 720))
        {
            Write-VerboseOutput("Build vulnerable to CVE-2020-0796. Checking if workaround is in place.")
            $writeType = "Red"
            $writeValue = "System Vulnerable"

            if ($osInformation.RegistryValues.LanManServerDisabledCompression -eq 1)
            {
                Write-VerboseOutput("Workaround to disable affected SMBv3 compression is in place.")
                $writeType = "Yellow"
                $writeValue = "Workaround is in place"
            }
            else
            {
                Write-VerboseOutput("Workaround to disable affected SMBv3 compression is NOT in place.")
                $Script:AllVulnerabilitiesPassed = $false
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "CVE-2020-0796" -Details ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0796 for more information." -f $writeValue) `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType $writeType `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
        else
        {
            Write-VerboseOutput("System NOT vulnerable to CVE-2020-0796. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0796")
        }
    }
    else
    {
        Write-VerboseOutput("Operating System NOT vulnerable to CVE-2020-0796.")
    }

    #Description: Check for CVE-2020-1147
    #Affected OS versions: Every OS supporting .NET Core 2.1 and 3.1 and .NET Framework 2.0 SP2 or above
    #Fix: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1147
    #Workaround: N/A
    $dllFileBuildPartToCheckAgainst = 3630

    if ($osInformation.NETFramework.NetMajorVersion -eq [HealthChecker.NetMajorVersion]::Net4d8)
    {
        $dllFileBuildPartToCheckAgainst = 4190
    }

    Write-VerboseOutput("System.Data.dll FileBuildPart: {0} | LastWriteTimeUtc: {1}" -f ($systemDataDll = $osInformation.NETFramework.FileInformation["System.Data.dll"]).VersionInfo.FileBuildPart, `
        $systemDataDll.LastWriteTimeUtc)
    Write-VerboseOutput("System.Configuration.dll FileBuildPart: {0} | LastWriteTimeUtc: {1}" -f ($systemConfigurationDll = $osInformation.NETFramework.FileInformation["System.Configuration.dll"]).VersionInfo.FileBuildPart, `
        $systemConfigurationDll.LastWriteTimeUtc)

    if($systemDataDll.VersionInfo.FileBuildPart -ge $dllFileBuildPartToCheckAgainst -and
        $systemConfigurationDll.VersionInfo.FileBuildPart -ge $dllFileBuildPartToCheckAgainst -and
        $systemDataDll.LastWriteTimeUtc -ge ([System.Convert]::ToDateTime("06/05/2020", [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) -and
        $systemConfigurationDll.LastWriteTimeUtc -ge ([System.Convert]::ToDateTime("06/05/2020", [System.Globalization.DateTimeFormatInfo]::InvariantInfo)))
    {
        Write-VerboseOutput("System NOT vulnerable to {0}. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0}" -f "CVE-2020-1147")
    }
    else
    {
        $Script:AllVulnerabilitiesPassed = $false
        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerability" -Details ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0} for more information." -f "CVE-2020-1147") `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Red" `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $Script:AnalyzedInformation
    }

    if ($Script:AllVulnerabilitiesPassed)
    {
        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Details "All known security issues in this version of the script passed." `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Green" `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $Script:AnalyzedInformation
    }

    Write-Debug("End of Analyzer Engine")
    return $Script:AnalyzedInformation
}

Function Write-ResultsToScreen {
param(
[Hashtable]$ResultsToWrite
)
    Write-VerboseOutput("Calling: Write-ResultsToScreen")
    $indexOrderGroupingToKey = @{}

    foreach ($keyGrouping in $ResultsToWrite.Keys)
    {
        $indexOrderGroupingToKey[$keyGrouping.DisplayOrder] = $keyGrouping
    }

    $sortedIndexOrderGroupingToKey = $indexOrderGroupingToKey.Keys | Sort-Object

    foreach ($key in $sortedIndexOrderGroupingToKey)
    {
        Write-VerboseOutput("Working on Key: {0}" -f $key)
        $keyGrouping = $indexOrderGroupingToKey[$key]
        Write-VerboseOutput("Working on Key Group: {0}" -f $keyGrouping.Name)
        Write-VerboseOutput("Total lines to write: {0}" -f ($ResultsToWrite[$keyGrouping].Count))

        if ($keyGrouping.DisplayGroupName)
        {
            Write-Grey($keyGrouping.Name)
            $dashes = [string]::empty
            1..($keyGrouping.Name.Length) | %{$dashes = $dashes + "-"}
            Write-Grey($dashes)
        }

        foreach ($line in $ResultsToWrite[$keyGrouping])
        {
            $tab = [string]::Empty

            if ($line.TabNumber -ne 0)
            {
                1..($line.TabNumber) | %{$tab = $tab + "`t"}
            }

            $writeValue = "{0}{1}" -f $tab, $line.Line
            switch ($line.WriteType)
            {
                "Grey" {Write-Grey($writeValue)}
                "Yellow" {Write-Yellow($writeValue)}
                "Green" {Write-Green($writeValue)}
                "Red" {Write-Red($writeValue)}
            }
        }

        Write-Grey("")
    }
}

Function Create-HtmlServerReport {
param(
[Parameter(Mandatory=$true)][array]$AnalyzedHtmlServerValues
)
    Write-VerboseOutput("Calling: Create-HtmlServerReport")

    $htmlHeader = "<html>
        <style>
        BODY{font-family: Arial; font-size: 8pt;}
        H1{font-size: 16px;}
        H2{font-size: 14px;}
        H3{font-size: 12px;}
        TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
        TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
        TD{border: 1px solid black; padding: 5px; }
        td.Green{background: #7FFF00;}
        td.Yellow{background: #FFE600;}
        td.Red{background: #FF0000; color: #ffffff;}
        td.Info{background: #85D4FF;}
        </style>
        <body>
        <h1 align=""center"">Exchange Health Checker v$($Script:healthCheckerVersion)</h1><br>
        <h2>Servers Overview</h2>"

    [array]$htmlOverviewTable += "<p>
        <table>
        <tr>"
    foreach ($tableHeaderName in $AnalyzedHtmlServerValues[0]["OverviewValues"].Name)
    {
        $htmlOverviewTable += "<th>{0}</th>" -f $tableHeaderName
    }

    $htmlOverviewTable += "</tr>"

    foreach ($serverHtmlServerValues in $AnalyzedHtmlServerValues)
    {
        $htmlTableRow = @()
        [array]$htmlTableRow += "<tr>"
        foreach ($htmlTableDataRow in $serverHtmlServerValues["OverviewValues"])
        {
            $htmlTableRow += "<td class=`"{0}`">{1}</td>" -f $htmlTableDataRow.Class, `
                $htmlTableDataRow.DetailValue
        }
        $htmlTableRow += "</tr>"
        $htmlOverviewTable += $htmlTableRow
    }

    $htmlOverviewTable += "</table></p>"

    [array]$htmlServerDetails += "<p><h2>Server Details</h2><table>"

    foreach ($serverHtmlServerValues in $AnalyzedHtmlServerValues)
    {
        foreach ($htmlTableDataRow in $serverHtmlServerValues["ServerDetails"])
        {
            if ($htmlTableDataRow.Name -eq "Server Name")
            {
                $htmlServerDetails += "<tr><th>{0}</th><th>{1}</th><tr>" -f $htmlTableDataRow.Name, `
                    $htmlTableDataRow.DetailValue
            }
            else
            {
                $htmlServerDetails += "<tr><td class=`"{0}`">{1}</td><td class=`"{0}`">{2}</td><tr>" -f $htmlTableDataRow.Class, `
                    $htmlTableDataRow.Name, `
                    $htmlTableDataRow.DetailValue
            }
        }
    }
    $htmlServerDetails += "</table></p>"

    $htmlReport = $htmlHeader + $htmlOverviewTable + $htmlServerDetails + "</body></html>"

    $htmlReport | Out-File $HtmlReportFile -Encoding UTF8

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
        else 
        {
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
    try 
    {
        $wmi_obj_processor = Get-WmiObjectHandler -ComputerName $Machine_Name -Class "Win32_Processor" -CatchActionFunction ${Function:Invoke-CatchActions}

        foreach($processor in $wmi_obj_processor)
        {
            $returnObj.NumberOfCores +=$processor.NumberOfCores
        }
        
        Write-Grey("Server {0} Cores: {1}" -f $Machine_Name, $returnObj.NumberOfCores)
    }
    catch 
    {
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
    if($AnalyzeDataOnly -or
        $BuildHtmlServersReport)
    {
        return
    }

    $byPassLocalExchangeServerTest = $false
    
    if ($Script:Server -ne $env:COMPUTERNAME)
    {
        $byPassLocalExchangeServerTest = $true
    }

    if(!(Confirm-ExchangeShell `
    -ByPassLocalExchangeServerTest $byPassLocalExchangeServerTest `
    -CatchActionFunction ${Function:Invoke-CatchActions} ))
    {
        Write-Yellow("Failed to load Exchange Shell... stopping script")
        exit
    }
}

Function Get-ErrorsThatOccurred {

    if($Error.Count -gt $Script:ErrorStartCount)
    {
        Write-Grey(" "); Write-Grey(" ")
        Function Write-Errors {
            $index = 0; 
            "`r`n`r`nErrors that occurred that wasn't handled" | Out-File ($Script:OutputFullPath) -Append
            $Script:Logger.WriteToFileOnly("`r`n`r`nErrors that occurred that wasn't handled")
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
                    $Script:Logger.WriteToFileOnly($Error[$index])
                    $Error[$index] | Out-File ($Script:OutputFullPath) -Append
                }
                $index++
            }
            Write-Grey(" "); Write-Grey(" ")
            "Errors that were handled" | Out-File ($Script:OutputFullPath) -Append
            $Script:Logger.WriteToFileOnly("`r`n`r`nErrors that were handled")
            foreach($okayErrors in $Script:ErrorsExcluded)
            {
                $okayErrors | Out-File ($Script:OutputFullPath) -Append
                $Script:Logger.WriteToFileOnly($okayErrors)
            }
        }

        if(($Error.Count - $Script:ErrorStartCount) -ne $Script:ErrorsExcludedCount)
        {
            Write-Red("There appears to have been some errors in the script. To assist with debugging of the script, please send the HealthChecker-Debug_*.txt and .xml file to ExToolsFeedback@microsoft.com.")
	        $Script:Logger.PreventLogCleanup = $true
            Write-Errors
        }
        elseif($Script:VerboseEnabled -or 
            $SaveDebugLog)
        {
            Write-VerboseOutput("All errors that occurred were in try catch blocks and was handled correctly.")
	        $Script:Logger.PreventLogCleanup = $true
            Write-Errors
        }
    }
    else 
    {
        Write-VerboseOutput("No errors occurred in the script.")
    }
}

Function Write-HealthCheckerVersion {
    
    $currentVersion = Test-ScriptVersion -ApiUri "api.github.com" -RepoOwner "dpaulson45" `
        -RepoName "HealthChecker" `
        -CurrentVersion $healthCheckerVersion `
        -DaysOldLimit 90 `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $Script:DisplayedScriptVersionAlready = $true

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
    Write-Break
    Write-Break

}
Function HealthCheckerMain {

    Set-ScriptLogFileLocation -FileName "HealthCheck" -IncludeServerName $true
    Test-RequiresServerFqdn
    Write-HealthCheckerVersion
    [HealthChecker.HealthCheckerExchangeServer]$HealthObject = Get-HealthCheckerExchangeServer
    $analyzedResults = Start-AnalyzerEngine -HealthServerObject $HealthObject
    Write-ResultsToScreen -ResultsToWrite $analyzedResults.DisplayResults
    $analyzedResults | Export-Clixml -Path $OutXmlFullPath -Encoding UTF8 -Depth 6
    Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
    Write-Grey("Exported Data Object Written to {0} " -f $Script:OutXmlFullPath)
}
Function Main {
    
    if(-not (Is-Admin) -and
        (-not $AnalyzeDataOnly -and
        -not $BuildHtmlServersReport))
	{
        Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
        $Script:ErrorStartCount = $Error.Count
		Start-Sleep -Seconds 2;
		exit
    }

    if ($Error.Count -gt 175)
    {
        Write-Verbose("Clearing Error to avoid script issues")
        $Error.Clear()
    }

    $Script:ErrorStartCount = $Error.Count #useful for debugging 
    $Script:ErrorsExcludedCount = 0 #this is a way to determine if the only errors occurred were in try catch blocks. If there is a combination of errors in and out, then i will just dump it all out to avoid complex issues. 
    $Script:ErrorsExcluded = @() 
    $Script:date = (Get-Date)
    $Script:dateTimeStringFormat = $date.ToString("yyyyMMddHHmmss")
    
    if($BuildHtmlServersReport)
    {
        Set-ScriptLogFileLocation -FileName "HealthChecker-HTMLServerReport"
        $files = Get-HealthCheckFilesItemsFromLocation
        $fullPaths = Get-OnlyRecentUniqueServersXMLs $files
        $importData = Import-MyData -FilePaths $fullPaths
        Create-HtmlServerReport -AnalyzedHtmlServerValues $importData.HtmlServerValues
        sleep 2;
        return
    }

    if((Test-Path $OutputFilePath) -eq $false)
    {
        Write-Host "Invalid value specified for -OutputFilePath." -ForegroundColor Red
        return 
    }

    if($LoadBalancingReport)
    {
        LoadBalancingMain
        return
    }

    if($DCCoreRatio)
    {
        $oldErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        try 
        {
            Get-ExchangeDCCoreRatio
            return
        }
        finally
        {
            $ErrorActionPreference = $oldErrorAction
        }
    }

	if($MailboxReport)
	{
        Set-ScriptLogFileLocation -FileName "HealthCheck-MailboxReport" -IncludeServerName $true 
        Get-MailboxDatabaseAndMailboxStatistics
        Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
        return
    }

    if ($AnalyzeDataOnly)
    {
        Set-ScriptLogFileLocation -FileName "HealthChecker-Analyzer"
        $files = Get-HealthCheckFilesItemsFromLocation
        $fullPaths = Get-OnlyRecentUniqueServersXMLs $files
        $importData = Import-MyData -FilePaths $fullPaths

        $analyzedResults = @()
        foreach ($serverData in $importData)
        {
            $analyzedServerResults = Start-AnalyzerEngine -HealthServerObject $serverData.HealthCheckerExchangeServer
            Write-ResultsToScreen -ResultsToWrite $analyzedServerResults.DisplayResults
            $analyzedResults += $analyzedServerResults
        }

        Create-HtmlServerReport -AnalyzedHtmlServerValues $analyzedResults.HtmlServerValues
        return
    }

	HealthCheckerMain
}

try 
{
    Main
}
finally 
{
    Get-ErrorsThatOccurred
    if($Script:VerboseEnabled)
    {
        $Host.PrivateData.VerboseForegroundColor = $VerboseForeground
    }
    $Script:Logger.RemoveLatestLogFile()
    if($Script:Logger.PreventLogCleanup)
    {
        Write-Host("Output Debug file written to {0}" -f $Script:Logger.FullPath)
    }
}
