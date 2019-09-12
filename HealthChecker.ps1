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

$healthCheckerVersion = "3.0.0"
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
        public class HealthCheckerExchangeServer
        {
            public string ServerName;        //String of the server that we are working with 
            public HardwareInformation HardwareInfo;  // Hardware Object Information 
            public OperatingSystemInformation  OSVersion; // OS Version Object Information 
            public NetVersionInformation NetVersionInfo; //.net Framework object information 
            public ExchangeInformation ExchangeInformation; //Detailed Exchange Information 
            public string HealthCheckerVersion; //To determine the version of the script on the object.
        }

        public class ExchangeInformation 
        {
            public ServerRole ExServerRole;          // Roles that are currently installed - Exchange 2013 makes a note if both roles aren't installed 
            public ExchangeVersion ExchangeVersion;  //Exchange Version (Exchange 2010/2013/2016)
            public string ExchangeFriendlyName;       // Friendly Name is provided 
            public string ExchangeBuildNumber;       //Exchange Build number 
            public string BuildReleaseDate;           //Provides the release date for which the CU they are currently on 
            public object ExchangeServerObject;      //Stores the Get-ExchangeServer Object 
            public bool SupportedExchangeBuild;      //Deteremines if we are within the correct build of Exchange 
            public bool InbetweenCUs;                //bool to provide if we are between main releases of CUs. Hotfixes/IUs. 
            public bool RecommendedNetVersion; //RecommendedNetVersion Info includes all the factors. Windows Version & CU. 
            public ExchangeBuildObject ExchangeBuildObject; //Store the build object
            public System.Array KBsInstalled;         //Stored object for IU or Security KB fixes 
            public bool MapiHttpEnabled; //Stored from ogranzation config 
            public string MapiFEAppGCEnabled; //to determine if we were able to get information regarding GC mode being enabled or not
            public string ExchangeServicesNotRunning; //Contains the Exchange services not running by Test-ServiceHealth 
            public Hashtable ExchangeAppPools; 
            public object ExchangeSetup;                  //Stores the Get-Command ExSetup object 
           
        }

        //TODO: V3.0 See if we can remove this class https://github.com/dpaulson45/HealthChecker/issues/165
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
            CU22,
            CU23

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
        
        public class NetVersionInformation 
        {
            public NetVersion NetVersion; //NetVersion value 
            public string FriendlyName;  //string of the friendly name 
            public bool SupportedVersion; //bool to determine if the .net framework is on a supported build for the version of Exchange that we are running 
            public string DisplayWording; //used to display what is going on
            public int NetRegValue; //store the registry value 
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
            Net4d7d2 = 461814,
            Net4d8 = 528049
        }

        //enum for the dword values of the latest supported VC++ redistributable releases
        //https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads
        public enum VCRedistVersion
        {
            Unknown = 0,
            VCRedist2012 = 184610406,
            VCRedist2013 = 201367256
        }

        public class VCRedistInformation
        {
            public string DisplayName;
            public string DisplayVersion;
            public string InstallDate;
            public int VersionIdentifier;
        }

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

        public class OperatingSystemInformation 
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
            public PageFileInformation PageFile;
            public ServerLmCompatibilityLevelInformation LmCompat;
            public bool ServerPendingReboot; //bool to determine if a server is pending a reboot to properly apply fixes
            public object PacketsReceivedDiscarded; //object to hold all packets received discarded on the server
            public double DisabledComponents; //value stored in the registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents 
            public bool IPv6DisabledOnNICs; //value that determines if we have IPv6 disabled on some NICs or not. 
            public string TimeZone; //value to stores the current timezone of the server. 
            public Hashtable TLSSettings;
	        public string BootUpTimeInDays;
            public string BootUpTimeInHours;
            public string BootUpTimeInMinutes;
            public string BootUpTimeInSeconds;
        }

        public class HotfixInformation
        {
            public string KBName; //KB that we are using to check against 
            public System.Array FileInformation; //store FileVersion information
            public bool ValidFileLevelCheck;  
        }

        public class NICInformation 
        {
            public string Description;  //Friendly name of the adapter 
            public string LinkSpeed;    //speed of the adapter 
            public System.DateTime DriverDate;   // date of the driver that is currently installed on the server 
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

        public class PageFileInformation 
        {
            public object PageFile;  //object to store the information that we got for the page file 
            public double MaxPageSize; //value to hold the information of what our page file is set to 
        }

        public class ServerLmCompatibilityLevelInformation
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

############################################################
############################################################

Function Invoke-CatchActions{

    Write-VerboseOutput("Calling: Invoke-CatchActions")
    $Script:ErrorsExcludedCount++
    $Script:ErrorsExcluded += $Error[0]

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
    [Parameter(Mandatory=$true)][string]$GetValue,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    
    #Function Version 1.0
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
        Write-VerboseWriter("Attempting to get the value '{0}'" -f $GetValue)
        $returnGetValue = $RegKey.GetValue($GetValue)
        Write-VerboseWriter("Exiting: Invoke-RegistryGetValue | Returning: {0}" -f $returnGetValue)
        return $returnGetValue
    }
    catch 
    {
        if($CatchActionFunction -ne $null)
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
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.0
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
            if($ArgumentList -ne $null) 
            {
                Write-VerboseWriter("Running Invoke-Command with argument list.")
                $invokeReturn = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop 
            }
            else 
            {
                Write-VerboseWriter("Running Invoke-Command without argument list.")
                $invokeReturn = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop 
            }
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
    $installedSoftware = Invoke-ScriptBlockHandler -ComputerName $MachineName -ScriptBlock {Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*} -ScriptBlockDescription "Quering for software" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Exiting: Get-InstalledSoftware")
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
    Write-VerboseOutput("Exiting: Get-CounterSamples")
    return $counterSamples 
}

#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ServerOperatingSystemVersion/Get-ServerOperatingSystemVersion.ps1
Function Get-ServerOperatingSystemVersion {
    [CmdletBinding()]
    param(
    [string]$OSBuildNumberVersion
    )
    
    #Function Version 1.4
    <#
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    
    if($OSBuildNumberVersion -eq [string]::Empty -or $OSBuildNumberVersion -eq $null)
    {
        Write-VerboseWriter("Getting the local machine version build number")
        $OSBuildNumberVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
        Write-VerboseWriter("Got {0} for the version build number" -f $OSBuildNumberVersion)
    }
    else 
    {
        Write-VerboseWriter("Passed - [string]OSBuildNumberVersion : {0}" -f $OSBuildNumberVersion)
    }
    
    [string]$osReturnValue = ""
    switch ($OSBuildNumberVersion) 
    {
        "6.0.6000" {$osReturnValue = "Windows2008"}
        "6.1.7600" {$osReturnValue = "Windows2008R2"}
        "6.1.7601" {$osReturnValue = "Windows2008R2"}
        "6.2.9200" {$osReturnValue = "Windows2012"}
        "6.3.9600" {$osReturnValue = "Windows2012R2"}
        "10.0.14393" {$osReturnValue = "Windows2016"}
        "10.0.17713" {$osReturnValue = "Windows2019"}
        default {$osReturnValue = "Unknown"}
    }
    
    Write-VerboseWriter("Returned: {0}" -f $osReturnValue)
    return [string]$osReturnValue
}

Function Get-PageFileInformation {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-PageFileInformation")
    Write-Verbose("Passed: $Machine_Name")
    [HealthChecker.PageFileInformation]$page_obj = New-Object HealthChecker.PageFileInformation
    $pagefile = Get-WmiObjectHandler -ComputerName $Machine_Name -Class "Win32_PageFileSetting" -CatchActionFunction ${Function:Invoke-CatchActions}
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
    [Parameter(Mandatory=$false)][bool]$Windows2012R2AndAbove = $true,
    [Parameter(Mandatory=$false)][string]$ComputerFQDN,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-WmiObjectHandler/Get-WmiObjectHandler.ps1
    #>
    Write-VerboseWriter("Calling: Get-AllNicInformation")
    Write-VerboseWriter("Passed [string]ComputerName: {0} | [bool]Windows2012R2AndAbove: {1} | [string]ComputerFQDN: {2}" -f $ComputerName, $Windows2012R2AndAbove, $ComputerFQDN)
    
    Function Get-NetworkCards {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ComputerName
    )
        try 
        {
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop 
            $networkCards = Get-NetAdapter -CimSession $cimSession | Where-Object{$_.MediaConnectionState -eq "Connected"} -ErrorAction Stop
            return $networkCards
        }
        catch 
        {
            Write-VerboseWriter("Failed to attempt to get Windows2012R2 or greater advanced NIC settings in Get-NetworkCards. Error {0}." -f $Error[0].Exception)
            throw 
        }
    }
    
    Function Get-WmiNetworkCards {
        return (Get-WmiObjectHandler -ComputerName $ComputerName -Class "Win32_NetworkAdapter" -Filter "NetConnectionStatus ='2'" -CatchActionFunction $CatchActionFunction)
    }
    
    Function New-NICInformation {
    param(
    [array]$Adapters,
    [bool]$Windows2012R2AndAbove = $true
    )
        if($Adapters -eq $null)
        {
            Write-VerboseWriter("Adapters are null in New-NICInformation. Returning a null object.")
            return $null
        }
        [array]$nicObjects = @()
        foreach($adapter in $Adapters)
        {
            if($Windows2012R2AndAbove){$descritpion = $adapter.InterfaceDescription}else {$descritpion = $adapter.Description}
            if($Windows2012R2AndAbove){$driverVersion = $adapter.DriverVersionString}else {$driverVersion = [string]::Empty}
            if($Windows2012R2AndAbove){$driverDate = $adapter.DriverDate}else{$driverDate = [DateTime]::MaxValue}
            if($Windows2012R2AndAbove){$mtuSize = $adapter.MtuSize}else{$mtuSize = 0}
            $nicInformationObj = New-Object PSCustomObject
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Name" -Value ($adapter.Name)
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "LinkSpeed" -Value ((($adapter.Speed)/1000000).ToString() + " Mbps")
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DriverDate" -Value $driverDate
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "NICObject" -Value $adapter
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "IPv6Enabled" -Value $false
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Description" -Value $descritpion 
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DriverVersion" -Value $driverVersion
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "MTUSize" -Value $mtuSize
            $nicObjects += $nicInformationObj 
        }
        Write-VerboseWriter("Found {0} active adapters on the computer." -f $nicObjects.Count)
        Write-VerboseWriter("Exiting: Get-AllNicInformation")
        return $nicObjects 
    }
    
    if($Windows2012R2AndAbove)
    {
        Write-VerboseWriter("Windows OS Version greater than or equal to Windows 2012R2. Going to run Get-NetAdapter")
        try 
        {
            try 
            {
                $networkCards = Get-NetworkCards -ComputerName $ComputerName -ErrorAction Stop 
            }
            catch 
            {
                
                if($CatchActionFunction -ne $null) {& $CatchActionFunction }
                if($ComputerFQDN -ne $null -and $ComputerFQDN -ne [string]::Empty)
                {
                    Write-VerboseWriter("Going to attempt FQDN")
                    $networkCards = Get-NetworkCards -ComputerName $ComputerFQDN
                }
                else {$bypassCatchAction = $true; Write-VerboseWriter("No FQDN was passed, going to rethrow error."); throw}
                
            }
            return (New-NICInformation -Adapters $networkCards)
        }
        catch 
        {
            Write-VerboseWriter("Failed to get Windows2012R2 or greater advanced NIC settings. Error {0}." -f $Error[0].Exception)
            Write-VerboseWriter("Going to attempt to get WMI Object Win32_NetworkAdapter on this machine instead")
            Write-VerboseWriter("NOTE: This means we aren't able to provide the driver date")
            if(!$bypassCatchAction -and $CatchActionFunction -ne $null) {& $CatchActionFunction }
            $wmiNetCards = Get-WmiNetworkCards -ComputerName $ComputerName 
            return (New-NICInformation -Adapters $wmiNetCards -Windows2012R2AndAbove $false)
        }
    }
    else 
    {
        Write-VerboseWriter("Windows OS Version is less than Windows 2012R2. Going to run Get-WmiObject.")
        $wmiNetCards = Get-WmiNetworkCards -ComputerName $ComputerName
        return (New-NICInformation -Adapters $wmiNetCards -Windows2012R2AndAbove $false)
    }
    
}

Function Get-HttpProxySetting {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
	$httpProxy32 = [String]::Empty
	$httpProxy64 = [String]::Empty
	Write-VerboseOutput("Calling: Get-HttpProxySetting")
	Write-VerboseOutput("Passed: {0}" -f $Machine_Name)
    
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

    $httpProxy32 = Invoke-ScriptBlockHandler -ComputerName $Machine_Name -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ScriptBlockDescription "Getting 32 Http Proxy Value" -CatchActionFunction ${Function:Invoke-CatchActions}
    $httpProxy64 = Invoke-ScriptBlockHandler -ComputerName $Machine_Name -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ScriptBlockDescription "Getting 64 Http Proxy Value" -CatchActionFunction ${Function:Invoke-CatchActions}

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
param(
[Parameter(Mandatory=$true)][string]$MachineName
)
    Write-VerboseOutput("Calling: Get-VisualCRedistributableVersion")
    $Software_objs = @()
    $InstalledSoftware = Get-InstalledSoftware -MachineName $MachineName

    ForEach($Software in $InstalledSoftware)
    {
        if($Software.DisplayName -like "Microsoft Visual C++ *")
        {
            Write-VerboseOutput("Microsoft Visual C++ Redistributable found: {0}" -f $Software.DisplayName)
            [HealthChecker.VCRedistInformation]$Software_obj = New-Object Healthchecker.VCRedistInformation
            $Software_obj.DisplayName = $Software.DisplayName
            $Software_obj.DisplayVersion = $Software.DisplayVersion
            $Software_obj.InstallDate = $Software.InstallDate
            $Software_obj.VersionIdentifier = $Software.Version
            $Software_objs += $Software_obj
        }
    }

    Write-VerboseOutput("Exiting: Get-VisualCRedistributableVersion")
    return $Software_objs
}

Function Confirm-VisualCRedistributableVersion {
param(
[Parameter(Mandatory=$true)][object]$ExchangeServerObj
)
    Write-VerboseOutput("Calling: Confirm-VisualCRedistributableVersion")

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

    Write-VerboseOutput("Exiting: Confirm-VisualCRedistributableVersion")
    return $Return
}

Function New-FileLevelHotfixInformation {
param(
[parameter(Mandatory=$true)][string]$FriendlyName,
[parameter(Mandatory=$true)][string]$FullFilePath, 
[Parameter(Mandatory=$true)][string]$BuildVersion
)
    #TODO: V3.0 see why this was commented out and see if we should add it back. https://github.com/dpaulson45/HealthChecker/issues/167
    #Write-VerboseOutput("Calling Function: New-FileLevelHotfixInformation")
    #Write-VerboseOutput("Passed - FriendlyName: {0} FullFilePath: {1} BuldVersion: {2}" -f $FriendlyName, $FullFilePath, $BuildVersion)
    $FileVersion = New-Object PSCustomObject 
    $FileVersion | Add-Member -MemberType NoteProperty -Name FriendlyFileName -Value $FriendlyName 
    $FileVersion | Add-Member -MemberType NoteProperty -Name FullPath -Value $FullFilePath 
    $FileVersion | Add-Member -MemberType NoteProperty -Name BuildVersion -Value $BuildVersion 
    
    return $FileVersion
}

Function Get-HotFixListInfo{
param(
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OS_Version
)
    Write-VerboseOutput("Calling: Confirm-VisualCRedistributableVersion")
    $hotfix_objs = @()
    switch ($OS_Version)
    {
        ([HealthChecker.OSVersionName]::Windows2008R2)
        {
            [HealthChecker.HotfixInformation]$hotfix_obj = New-Object HealthChecker.HotfixInformation
            $hotfix_obj.KBName = "KB3004383"
            $hotfix_obj.ValidFileLevelCheck = $true
            $hotfix_obj.FileInformation += (New-FileLevelHotfixInformation -FriendlyName "Appidapi.dll" -FullFilePath "C:\Windows\SysWOW64\Appidapi.dll" -BuildVersion "6.1.7601.22823")
            #For this check, we are only going to check for one file, because there are a ridiculous amount in this KB. Hopefully we don't see many false positives 
            $hotfix_objs += $hotfix_obj
            return $hotfix_objs
        }
        ([HealthChecker.OSVersionName]::Windows2012R2)
        {
            [HealthChecker.HotfixInformation]$hotfix_obj = New-Object HealthChecker.HotfixInformation
            $hotfix_obj.KBName = "KB3041832"
            $hotfix_obj.ValidFileLevelCheck = $true
            $hotfix_obj.FileInformation += (New-FileLevelHotfixInformation -FriendlyName "Hwebcore.dll" -FullFilePath "C:\Windows\SysWOW64\inetsrv\Hwebcore.dll" -BuildVersion "8.5.9600.17708")
            $hotfix_obj.FileInformation += (New-FileLevelHotfixInformation -FriendlyName "Iiscore.dll" -FullFilePath "C:\Windows\SysWOW64\inetsrv\Iiscore.dll" -BuildVersion "8.5.9600.17708")
            $hotfix_obj.FileInformation += (New-FileLevelHotfixInformation -FriendlyName "W3dt.dll" -FullFilePath "C:\Windows\SysWOW64\inetsrv\W3dt.dll" -BuildVersion "8.5.9600.17708")
            $hotfix_objs += $hotfix_obj
            
            return $hotfix_objs
        }
        ([HealthChecker.OSVersionName]::Windows2016)
        {
            [HealthChecker.HotfixInformation]$hotfix_obj = New-Object HealthChecker.HotfixInformation
            $hotfix_obj.KBName = "KB3206632"
            $hotfix_obj.ValidFileLevelCheck = $false
            $hotfix_obj.FileInformation += (New-FileLevelHotfixInformation -FriendlyName "clusport.sys" -FullFilePath "C:\Windows\System32\drivers\clusport.sys" -BuildVersion "10.0.14393.576")
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
    Write-VerboseOutput("Calling: Remote-GetFileVersionInfo")
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

    Write-VerboseOutput("Exiting: Remote-GetFileVersionInfo")
    return $ReturnList
}

Function Get-RemoteHotFixInformation {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OS_Version
)
    Write-VerboseOutput("Calling: Get-RemoteHotFixInformation")
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
            
            $results = Invoke-ScriptBlockHandler -ComputerName $Machine_Name -ScriptBlock ${Function:Remote-GetFileVersionInfo} -ArgumentList $argList -ScriptBlockDescription "Calling Remote-GetFileVersionInfo" -CatchActionFunction ${Function:Invoke-CatchActions}
            return $results
        }
        catch 
        {
            Invoke-CatchActions
        }
        finally
        {
            Write-VerboseOutput("Exiting: Get-RemoteHotFixInformation")
            $ErrorActionPreference = $oldErrorAction
        }
    }
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

Function Get-OperatingSystemInformation {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-OperatingSystemInformation")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.OperatingSystemInformation]$os_obj = New-Object HealthChecker.OperatingSystemInformation
    $os = Get-WmiObjectHandler -ComputerName $Machine_Name -Class Win32_OperatingSystem -CatchActionFunction ${Function:Invoke-CatchActions}
    $plan = Get-WmiObjectHandler -ComputerName $Machine_Name -Class Win32_PowerPlan -Namespace 'root\cimv2\power' -Filter "isActive='true'" -CatchActionFunction ${Function:Invoke-CatchActions}
    $temp_currentdate = Get-Date
    $temp_uptime = [Management.ManagementDateTimeConverter]::ToDateTime($os.lastbootuptime)
    $os_obj.OSVersionBuild = $os.Version
    $os_obj.OSVersion = (Get-ServerOperatingSystemVersion -OSBuildNumberVersion $os_obj.OSVersionBuild)
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
    $os_obj.PageFile = (Get-PageFileInformation -Machine_Name $Machine_Name)
    $os_obj.NetworkAdaptersConfiguration = Get-WmiObjectHandler -ComputerName $Machine_Name -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled = True" -CatchActionFunction ${Function:Invoke-CatchActions}
    if($os_obj.OSVersion -lt [HealthChecker.OSVersionName]::Windows2012R2){$isWindows2012R2OrNewer = $false}else{$isWindows2012R2OrNewer = $true}
    $os_obj.NetworkAdapters = (Get-AllNicInformation -ComputerName $Machine_Name -Windows2012R2AndAbove $isWindows2012R2OrNewer -CatchActionFunction ${Function:Invoke-CatchActions} -ComputerFQDN ((Get-ExchangeServer $Machine_Name -ErrorAction SilentlyContinue).FQDN))
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

    $os_obj.DisabledComponents = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -GetValue "DisabledComponents" -CatchActionFunction ${Function:Invoke-CatchActions}
    $os_obj.TCPKeepAlive = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -GetValue "KeepAliveTime" -CatchActionFunction ${Function:Invoke-CatchActions}
    $os_obj.MinimumConnectionTimeout = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "Software\Policies\Microsoft\Windows NT\RPC\" -GetValue "MinimumConnectionTimeout" -CatchActionFunction ${Function:Invoke-CatchActions}
	$os_obj.HttpProxy = Get-HttpProxySetting -Machine_Name $Machine_Name
    $os_obj.HotFixes = (Get-HotFix -ComputerName $Machine_Name -ErrorAction SilentlyContinue) #old school check still valid and faster and a failsafe 
    $os_obj.HotFixInfo = Get-RemoteHotFixInformation -Machine_Name $Machine_Name -OS_Version $os_obj.OSVersion 
    $os_obj.LmCompat = (Get-LmCompatibilityLevelInformation -Machine_Name $Machine_Name)
    $counterSamples = (Get-CounterSamples -MachineNames $Machine_Name -Counters "\Network Interface(*)\Packets Received Discarded")
    if($counterSamples -ne $null)
    {
        $os_obj.PacketsReceivedDiscarded = $counterSamples
    }
    $os_obj.ServerPendingReboot = (Get-ServerRebootPending -ServerName $Machine_Name -CatchActionFunction ${Function:Invoke-CatchActions})
    $os_obj.TimeZone = ([System.TimeZone]::CurrentTimeZone).StandardName
    $os_obj.TLSSettings = Get-AllTlsSettingsFromRegistry -MachineName $Machine_Name -CatchActionFunction ${Function:Invoke-CatchActions} 

    Write-VerboseOutput("Exiting: Get-OperatingSystemInformation")
    return $os_obj
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
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-HardwareInformation")
    Write-VerboseOutput("Passed: $Machine_Name")
    [HealthChecker.HardwareInformation]$hardware_obj = New-Object HealthChecker.HardwareInformation
    $system = Get-WmiObjectHandler -ComputerName $Machine_Name -Class "Win32_ComputerSystem" -CatchActionFunction ${Function:Invoke-CatchActions}
    $hardware_obj.Manufacturer = $system.Manufacturer
    $hardware_obj.System = $system
    $hardware_obj.AutoPageFile = $system.AutomaticManagedPagefile
    $hardware_obj.TotalMemory = $system.TotalPhysicalMemory
    $hardware_obj.ServerType = (Get-ServerType -ServerType $system.Manufacturer)
    $processorInformation = Get-ProcessorInformation -MachineName $Machine_Name -CatchActionFunction ${Function:Invoke-CatchActions} 
    $hardware_obj.Processor = $processorInformation
    $hardware_obj.Processor.ProcessorClassObject = $processorInformation.ProcessorClassObject #Need to do it this way otherwise the ProcessorClassObject will be empty for some reason.
    $hardware_obj.Model = $system.Model 

    Write-VerboseOutput("Exiting: Get-HardwareInformation")
    return $hardware_obj
}


Function Get-NetFrameworkVersionFriendlyInfo {
param(
[Parameter(Mandatory=$true)][int]$NetVersionKey,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OSVersionName 
)
    Write-VerboseOutput("Calling: Get-NetFrameworkVersionFriendlyInfo")
    Write-VerboseOutput("Passed: " + $NetVersionKey.ToString())
    Write-VerboseOutput("Passed: " + $OSVersionName.ToString())
    [HealthChecker.NetVersionInformation]$versionObject = New-Object -TypeName HealthChecker.NetVersionInformation
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
    elseif($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d7d2 -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d8))
    {
        $versionObject.FriendlyName = "4.7.2"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d7d2
    }
    elseif($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d8)
    {
        $versionObject.FriendlyName = "4.8"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d8
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
Function Get-NetFrameWorkVersionObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name,
[Parameter(Mandatory=$true)][HealthChecker.OSVersionName]$OSVersionName
)
    Write-VerboseOutput("Calling: Get-NetFrameWorkVersionObject")
    Write-VerboseOutput("Passed: $Machine_Name")
    Write-VerboseOutput("Passed: $OSVersionName")
    [int]$NetVersionKey = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -GetValue "Release" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Got {0} from the registry" -f $NetVersionKey)
    [HealthChecker.NetVersionInformation]$versionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $NetVersionKey -OSVersionName $OSVersionName
    Write-VerboseOutput("Exiting: Get-NetFrameWorkVersionObject")
    return $versionObject
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
    $exchangeVersion = [string]::Empty
    switch($build)
    {
        14.3 {$exchangeVersion = "Exchange2010"}
        15 {$exchangeVersion = "Exchange2013"}
        15.1 {$exchangeVersion = "Exchange2016"}
        15.2 {$exchangeVersion = "Exchange2019"}
        default {$exchangeVersion = "Unknown"}
    }
    Write-VerboseWriter("Returned: {0}" -f $exchangeVersion)
    return $exchangeVersion 
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
        elseif($buildRevision -lt 397.3){if($buildRevision -gt 330.6){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU1}
        elseif($buildRevision -ge 397.3){if($buildRevision -gt 397.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU2}
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
        elseif($buildRevision -lt 1779.2) {if($buildRevision -gt 1713.5){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU12}
        elseif($buildRevision -ge 1779.2) {if($buildRevision -gt 1779.2){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU13}

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
        elseif($buildRevision -lt 1497.2) {if($buildRevision -gt 1473.3){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU22}
        elseif($buildRevision -ge 1497.2) {if($buildRevision -gt 1497.2){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU23}
    }
    else
    {
        Write-Red "Error: Didn't know how to process the Admin Display Version Provided"
        
    }

    Write-VerboseOutput("Exiting: Get-ExchangeBuildObject")
    return $exBuildObj
}

#New Release Update 
Function Get-ExchangeBuildInformation {
param(
[Parameter(Mandatory=$true)][object]$AdminDisplayVersion
)
    Write-VerboseOutput("Calling: Get-ExchangeBuildInformation")
    Write-VerboseOutput("Passed: " + $AdminDisplayVersion.ToString())

    $tempObject = New-Object PSCustomObject 
    $tempObject | Add-Member -MemberType NoteProperty -Name FriendlyName -Value ([string]::Empty)
    $tempObject | Add-Member -MemberType NoteProperty -Name Error -Value $false 
    $tempObject | Add-Member -MemberType NoteProperty -Name ExchangeBuildNumber -Value ([string]::Empty)
    $tempObject | Add-Member -MemberType NoteProperty -Name ReleaseDate -Value ([string]::Empty)
    $tempObject | Add-Member -MemberType NoteProperty -Name SupportedCU -Value $false 
    $tempObject | Add-Member -MemberType NoteProperty -Name InbetweenCUs -Value $false #TODO: V3.0 Remove Me
    $tempObject | Add-Member -MemberType NoteProperty -Name ExchangeBuildObject -Value $null 
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
                    ([HealthChecker.ExchangeCULevel]::RTM) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2019 RTM"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "10/22/2018"; break}
                    ([HealthChecker.ExchangeCULevel]::CU1) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2019 CU1"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "02/12/2019"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU2) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2019 CU2"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "06/18/2019"; $tempObject.SupportedCU = $true; break}
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
                    ([HealthChecker.ExchangeCULevel]::CU11) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU11"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "10/16/2018"; break}
                    ([HealthChecker.ExchangeCULevel]::CU12) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU12"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "02/12/2019"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU13) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU13"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "06/18/2019"; $tempObject.SupportedCU = $true; break}
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
                    ([HealthChecker.ExchangeCULevel]::CU21) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU21"; $tempObject.ReleaseDate = "06/19/2018"; break}
                    ([HealthChecker.ExchangeCULevel]::CU22) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU22"; $tempObject.ReleaseDate = "02/12/2019"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU23) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU23"; $tempObject.ReleaseDate = "06/18/2019"; $tempObject.SupportedCU = $true; break}
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

    Write-VerboseOutput("Exiting: Get-ExchangeBuildInformation")
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
        $NetCheckObj = New-Object PSCustomObject 
        $NetCheckObj | Add-Member -MemberType NoteProperty -Name Error -Value $false 
        $NetCheckObj | Add-Member -MemberType NoteProperty -Name Supported -Value $false 
        $NetCheckObj | Add-Member -MemberType NoteProperty -Name RecommendedNetVersion -Value $true 
        $NetCheckObj | Add-Member -MemberType NoteProperty -Name DisplayWording -Value ([string]::Empty)

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
            [HealthChecker.NetVersionInformation]$RecommendedNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET 4.6 and this is an unsupported build of .NET for Exchange. Only .NET 4.6.1 with the hotfix and greater are supported. Please upgrade to " + $RecommendedNetVersionInformation.FriendlyName + " as soon as possible to get into a supported state."
        }
		elseif($CurrentNetVersion -eq [HealthChecker.NetVersion]::Net4d6d1 -and $RecommendedNetVersion -ge [HealthChecker.NetVersion]::Net4d6d1wFix)
		{
			Write-VerboseOutput("Current version of .NET equals 4.6.1 while the recommended version of .NET is equal to or greater than 4.6.1 with hotfix. This means that we are on an unsupported version because we never supported just 4.6.1 without the hotfix")
			$NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false
			[HealthChecker.NetVersionInformation]$RecommendedNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
			$NetCheckObj.DisplayWording = "On .NET 4.6.1 and this is an unsupported build of .NET for Exchange. Only .NET 4.6.1 with the hotfix and greater are supported. Please upgrade to " + $RecommendedNetVersionInformation.FriendlyName + " as soon as possible to get into a supported state."
		}

        #this catch is for when you are on a version of exchange where we can be on let's say 4.5.2 without fix, but there isn't a better option available.
        elseif($CurrentNetVersion -lt $MinSupportNetVersion -and $MinSupportNetVersion -eq $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version of .NET is less than Min Supported Version. Need to upgrade to this version as soon as possible")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionInformation]$currentNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionInformation]$MinSupportNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $MinSupportNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionInformation.FriendlyName + " and the minimum supported version is " + $MinSupportNetVersionInformation.FriendlyName + ". Upgrade to this version as soon as possible."
        }
        #here we are assuming that we are able to get to a much better version of .NET then the min 
        elseif($CurrentNetVersion -lt $MinSupportNetVersion)
        {
            Write-VerboseOutput("Current Version of .NET is less than Min Supported Version. However, the recommended version is the one we want to upgrade to")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false
            [HealthChecker.NetVersionInformation]$currentNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionInformation]$MinSupportNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $MinSupportNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionInformation]$RecommendedNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionInformation.FriendlyName + " and the minimum supported version is " + $MinSupportNetVersionInformation.FriendlyName + ", but the recommended version is " + $RecommendedNetVersionInformation.FriendlyName + ". upgrade to this version as soon as possible." 
        }
        elseif($CurrentNetVersion -lt $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version is less than the recommended version, but we are at or higher than the Min Supported level. Should upgrade to the recommended version as soon as possible.")
            $NetCheckObj.Supported = $true
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionInformation]$currentNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionInformation]$RecommendedNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionInformation.FriendlyName + " and the recommended version of .NET for this build of Exchange is " + $RecommendedNetVersionInformation.FriendlyName + ". Upgrade to this version as soon as possible." 
        }
        elseif($CurrentNetVersion -gt $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version is greater than the recommended version. This is an unsupported state.")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionInformation]$currentNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ -OSVersionName $OSVersionName
            [HealthChecker.NetVersionInformation]$RecommendedNetVersionInformation = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__ -OSVersionName $OSVersionName
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionInformation.FriendlyName + " and the max recommended version of .NET for this build of Exchange is " + $RecommendedNetVersionInformation.FriendlyName + ". Correctly remove the .NET version that you are on and reinstall the recommended max value. Generic catch message for current .NET version being greater than Max .NET version, so ask or lookup on the correct steps to address this issue."
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
                elseif($exBuildObj.CU -le ([HealthChecker.ExchangeCULevel]::CU22))
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d1 -RecommendedNetVersion Net4d7d2
                    $NetCheckObj.DisplayWording = $NetCheckObj.DisplayWording + " NOTE: Starting with CU23 we will require .NET 4.7.2 before you can install this version of Exchange."
                }
                else
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d2 -RecommendedNetVersion Net4d8
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
                elseif($exBuildObj.CU -le [HealthChecker.ExchangeCULevel]::CU12)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d1 -RecommendedNetVersion Net4d7d2
                    $NetCheckObj.DisplayWording = $NetCheckObj.DisplayWording + " NOTE: Starting with CU13 we will require .NET 4.7.2 before you can install this version of Exchange."
                }
                else
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d2 -RecommendedNetVersion Net4d8
                }
                break;
            }
        ([HealthChecker.ExchangeVersion]::Exchange2019)
            {
                Write-VerboseOutput("Exchange 2019 detected...checking .NET version")
                if($exBuildObj.CU -lt [HealthChecker.ExchangeCULevel]::CU2)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d2 -RecommendedNetVersion Net4d7d2
                }
                else
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d7d2 -RecommendedNetVersion Net4d8
                }
            }
        default {$NetCheckObj.Error = $true; Write-VerboseOutput("Error trying to determine major version of Exchange for .NET fix level")}
    }

    Write-VerboseOutput("Exiting: Check-DotNetFrameworkSupportedLevel")
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
        Write-VerboseOutput("Calling: Get-ExchangeAppPoolsScriptBlock")
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
                Write-VerboseOutput("Failed to find config file setting in app pool '{0}'" -f $appPool)
                $content = $null     
            }
            $statusObj = New-Object pscustomobject 
            $statusObj | Add-Member -MemberType NoteProperty -Name "Status" -Value $status
            $statusObj | Add-Member -MemberType NoteProperty -Name "ConfigPath" -Value $config
            $statusObj | Add-Member -MemberType NoteProperty -Name "Content" -Value $content 

            $exchAppPools.Add($appPool, $statusObj)
        }
        Write-VerboseOutput("Exiting: Get-ExchangeAppPoolsScriptBlock")
        return $exchAppPools
    }
    $exchangeAppPoolsInfo = Invoke-ScriptBlockHandler -ComputerName $Machine_Name -ScriptBlock ${Function:Get-ExchangeAppPoolsScriptBlock} -ScriptBlockDescription "Getting Exchange App Pool information" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Exiting: Get-ExchangeAppPoolsInformation")
    return $exchangeAppPoolsInfo
}

#TODO V3.0: https://github.com/dpaulson45/HealthChecker/issues/179
Function Get-MapiFEAppPoolGCMode{
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-MapiFEAppPoolGCMode")
    Write-VerboseOutput("Passed: {0}" -f $Machine_Name)
    $installPath = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\ExchangeServer\v15\Setup\" -GetValue "MsiInstallPath" -CatchActionFunction ${Function:Invoke-CatchActions}
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

    $mapiGCMode = Invoke-ScriptBlockHandler -ComputerName $Machine_Name -ScriptBlock ${Function:Get-MapiConfigGCSetting} -ScriptBlockDescription "Getting Get-MapiConfigGCSetting" -ArgumentList $MapiConfig -CatchActionFunction ${Function:Invoke-CatchActions}
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

    $exSetupDetails = Invoke-ScriptBlockHandler -ComputerName $Machine_Name -ScriptBlock ${Function:Get-ExSetupDetailsScriptBlock} -ScriptBlockDescription "Getting ExSetup remotely" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Exiting: Get-ExSetupDetails")
    return $exSetupDetails
}

#If this function changes update https://github.com/dpaulson45/HealthChecker/issues/163 #TODO: V3.0 remove line 
Function Get-ExchangeInformation {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj
)
    $Machine_Name = $HealthExSvrObj.ServerName
    $OSVersionName = $HealthExSvrObj.OSVersion.OSVersion
    Write-VerboseOutput("Calling: Get-ExchangeInformation")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.ExchangeInformation]$exchInfoObject = New-Object -TypeName HealthChecker.ExchangeInformation
    $exchInfoObject.ExchangeServerObject = (Get-ExchangeServer -Identity $Machine_Name)
    $exchInfoObject.ExchangeVersion = (Get-ExchangeMajorVersion -AdminDisplayVersion $exchInfoObject.ExchangeServerObject.AdminDisplayVersion) 
    $exchInfoObject.ExServerRole = (Get-ServerRole -ExchangeServerObj $exchInfoObject.ExchangeServerObject)
    $exchInfoObject.ExchangeSetup = (Get-ExSetupDetails -Machine_Name $Machine_Name) 

    #Exchange 2013 and 2016 things to check 
    if($exchInfoObject.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013) 
    {
        Write-VerboseOutput("Exchange 2013 or greater detected")
        $HealthExSvrObj.NetVersionInfo = Get-NetFrameWorkVersionObject -Machine_Name $Machine_Name -OSVersionName $OSVersionName
        $versionObject =  $HealthExSvrObj.NetVersionInfo 
        $tempObject = Get-ExchangeBuildInformation -AdminDisplayVersion $exchInfoObject.ExchangeServerObject.AdminDisplayVersion
        if($tempObject.Error -ne $true) 
        {
            Write-VerboseOutput("No error detected when getting temp information")
            $exchInfoObject.BuildReleaseDate = $tempObject.ReleaseDate
            $exchInfoObject.ExchangeBuildNumber = $tempObject.ExchangeBuildNumber
            $exchInfoObject.ExchangeFriendlyName = $tempObject.FriendlyName
            $exchInfoObject.InbetweenCUs = $tempObject.InbetweenCUs
            $exchInfoObject.SupportedExchangeBuild = $tempObject.SupportedCU
            $exchInfoObject.ExchangeBuildObject = $tempObject.ExchangeBuildObject 
            #TODO: V3.0 https://github.com/dpaulson45/HealthChecker/issues/166
            $NetCheckObj = Check-DotNetFrameworkSupportedLevel -exBuildObj $exchInfoObject.ExchangeBuildObject -OSVersionName $OSVersionName -NetVersion $versionObject.NetVersion
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
    Write-VerboseOutput("Exiting: Get-ExchangeInformation")
    return $HealthExSvrObj
}

Function Get-HealthCheckerExchangeServer {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)

    Write-VerboseOutput("Calling: Get-HealthCheckerExchangeServer")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj = New-Object -TypeName HealthChecker.HealthCheckerExchangeServer 
    $HealthExSvrObj.ServerName = $Machine_Name 
    $HealthExSvrObj.HardwareInfo = Get-HardwareInformation -Machine_Name $Machine_Name 
    $HealthExSvrObj.OSVersion = Get-OperatingSystemInformation -Machine_Name $Machine_Name  
    $HealthExSvrObj = Get-ExchangeInformation -HealthExSvrObj $HealthExSvrObj
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
Write-VerboseOutput("Calling: Get-BuildLevelVersionCheck")
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

    Write-VerboseOutput("Exiting: Get-BuildLevelVersionCheck")
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

Function Verify-Pagefile25PercentOfTotalMemory {
param(
[Parameter(Mandatory=$true)][HealthChecker.PageFileInformation]$PageFileObj,
[Parameter(Mandatory=$true)][HealthChecker.HardwareInformation]$HardwareObj
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

    Write-VerboseOutput("Exiting: Verify-Pagefile25PercentOfTotalMemory")
    return $returnString
}

Function Verify-PagefileEqualMemoryPlus10 {
param(
[Parameter(Mandatory=$true)][HealthChecker.PageFileInformation]$page_obj,
[Parameter(Mandatory=$true)][HealthChecker.HardwareInformation]$hardware_obj
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

    Write-VerboseOutput("Exiting: Verify-PagefileEqualMemoryPlus10 ")
    return $sReturnString
}

Function Get-LmCompatibilityLevel {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    #LSA Reg Location "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    #Check if valuename LmCompatibilityLevel exists, if not, then value is 3
    $RegValue = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Control\Lsa" -GetValue "LmCompatibilityLevel" -CatchActionFunction ${Function:Invoke-CatchActions}
    If ($RegValue)
    {
        Return $RegValue
    }
    Else
    {
        Return 3
    }

}

Function Get-LmCompatibilityLevelInformation {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)

    Write-VerboseOutput("Calling: Get-LmCompatibilityLevelInformation")
    Write-VerboseOutput("Passed: $Machine_Name")

    [HealthChecker.ServerLmCompatibilityLevelInformation]$ServerLmCompatObject = New-Object -TypeName HealthChecker.ServerLmCompatibilityLevelInformation
    
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

    Write-VerboseOutput("Exiting: Get-LmCompatibilityLevelInformation")
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
    [Parameter(Mandatory=$true)][array]$CVEName
    )
        ForEach($CVEItem in $CVEName)
        {
            Write-VerboseOutput("Testing CVE: {0} | Security Fix Build: {1}" -f $CVEItem, $SecurityFixedBuild)
            if($ExchangeBuildRevision -lt $SecurityFixedBuild)
            {
                Write-Red("System vulnerable to {0}.`r`n`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{1} for more information." -f $CVEItem, $CVEItem)
                $Script:AllVulnerabilitiesPassed = $false 
            }
            else 
            {
                Write-VerboseOutput("System NOT vulnerable to {0}. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{1}" -f $CVEItem, $CVEItem)
            }
        }
    }
    
    $Script:AllVulnerabilitiesPassed = $true 
    Write-Grey("`r`nVulnerability Check:`r`n")

    #Check for CVE-2018-8581 vulnerability
    #LSA Reg Location "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    #Check if valuename DisableLoopbackCheck exists
    $RegValue = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SYSTEM\CurrentControlSet\Control\Lsa" -GetValue "DisableLoopbackCheck" -CatchActionFunction ${Function:Invoke-CatchActions}
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
    
    $KB2565063_RegValue = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1D8E6291-B0D5-35EC-8441-6616F567A0F7}" -GetValue "DisplayVersion" -CatchActionFunction ${Function:Invoke-CatchActions}
    $KB2565063_RegValueInstallDate = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1D8E6291-B0D5-35EC-8441-6616F567A0F7}" -GetValue "InstallDate" -CatchActionFunction ${Function:Invoke-CatchActions}

    If ($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        If ([System.Convert]::ToDateTime([DateTime]$HealthExSvrObj.ExchangeInformation.BuildReleaseDate) -lt ([System.Convert]::ToDateTime([DateTime]"1 Oct 2018")))
        {
            Write-VerboseOutput("Your Exchange server build is prior to October 2018")

            If (($KB2565063_RegValue -ne $null) -and ($KB2565063_RegValue -match "10.0.40219"))
            {

                $E15_RegValueInstallData = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{CD981244-E9B8-405A-9026-6AEB9DCEF1F1}" -GetValue "InstallDate" -CatchActionFunction ${Function:Invoke-CatchActions}

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

            $E2010_RegValueInstallDate = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Machine_Name -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{4934D1EA-BE46-48B1-8847-F1AF20E892C1}" -GetValue "InstallDate" -CatchActionFunction ${Function:Invoke-CatchActions}

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
	    #ADV190018 affects E2010 but we cannot check for them
        #CVE-2019-1084 affects E2010 but we cannot check for them
        #CVE-2019-1136 affects E2010 but we cannot check for them
        #could do get the build number of exsetup, but not really needed with Exchange 2010 as it is going out of support soon. 
        Write-Yellow("`nWe cannot check for more vulnerabilities for Exchange 2010.")
        Write-Yellow("You should make sure that your Exchange 2010 Servers are up to date with all security patches.")
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        #Need to know which CU we are on, as that would be the best to break up the security patches 
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU18)
        {
            #CVE-2018-0924, CVE-2018-0940
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1347.5 -CVEName "CVE-2018-0924","CVE-2018-0940"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU19)
        {
            #to avoid duplicates only do these ones if we are equal to the current CU as they would have been caught on the previous CU if we are at a less CU
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU19)
            {
                #CVE-2018-0924, CVE-2018-0940
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1365.3 -CVEName "CVE-2018-0924","CVE-2018-0940"
            }
            #CVE-2018-8151,CVE-2018-8154,CVE-2018-8159
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1365.7 -CVEName "CVE-2018-8151","CVE-2018-8154","CVE-2018-8159"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU20)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU20)
            {
                #CVE-2018-8151,CVE-2018-8154,CVE-2018-8159 
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1367.6 -CVEName "CVE-2018-8151","CVE-2018-8154","CVE-2018-8159"
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
            #CVE-2018-8265,CVE-2018-8448
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1395.8 -CVEName "CVE-2018-8265","CVE-2018-8448"
            #CVE-2019-0586,CVE-2019-0588
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1395.10 -CVEName "CVE-2019-0586","CVE-2019-0588"
        }
	    if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU22)
	    {
            #Do to supportability changes, we don't have security updates for both CU22 and CU21 so there is no need to check for this version
	        #CVE-2019-0686,CVE-2019-0724
	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1473.3 -CVEName "CVE-2019-0686","CVE-2019-0724"
            #CVE-2019-0817,CVE-2019-0858
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1473.4 -CVEName "CVE-2019-0817","CVE-2019-0858"
	        #ADV190018
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1473.5 -CVEName "ADV190018"
	    }
	    if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU23)
	    {
            #CVE-2019-1084,CVE-2019-1136,CVE-2019-1137
	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1497.3 -CVEName "CVE-2019-1084","CVE-2019-1136","CVE-2019-1137"
	    }
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2016)
    {
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU7)
        {
            #CVE-2018-0924,CVE-2018-0940,CVE-2018-0941
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1261.39 -CVEName "CVE-2018-0924","CVE-2018-0940","CVE-2018-0941"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU8)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU8)
            {
                #CVE-2018-0924,CVE-2018-0940,CVE-2018-0941
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.4 -CVEName "CVE-2018-0924","CVE-2018-0940","CVE-2018-0941"
            }
            #CVE-2018-8151,CVE-2018-8152,CVE-2018-8153,CVE-2018-8154,CVE-2018-8159
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1415.7 -CVEName "CVE-2018-8151","CVE-2018-8152","CVE-2018-8153","CVE-2018-8154","CVE-2018-8159"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU9)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU9)
            {
                #CVE-2018-8151,CVE-2018-8152,CVE-2018-8153,CVE-2018-8154,CVE-2018-8159
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.8 -CVEName "CVE-2018-8151","CVE-2018-8152","CVE-2018-8153","CVE-2018-8154","CVE-2018-8159"
            }
            #CVE-2018-8374,CVE-2018-8302
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1466.9 -CVEName "CVE-2018-8374","CVE-2018-8302"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU10)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU10)
            {
                #CVE-2018-8374,CVE-2018-8302
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.6 -CVEName "CVE-2018-8374","CVE-2018-8302"
            }
            #CVE-2018-8265,CVE-2018-8448,CVE-2018-8604
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.8 -CVEName "CVE-2018-8265","CVE-2018-8448","CVE-2018-8604"
            #CVE-2019-0586,CVE-2019-0588
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1531.10 -CVEName "CVE-2019-0586","CVE-2019-0588"
        }
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU11)
        {
            if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU11)
            {
                #CVE-2018-8604
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.11 -CVEName "CVE-2018-8604"
                #CVE-2019-0586,CVE-2019-0588
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.13 -CVEName "CVE-2019-0586","CVE-2019-0588"
                #CVE-2019-0817,CVE-2018-0858
        	    Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.16 -CVEName "CVE-2019-0817","CVE-2019-0858"
		        #ADV190018
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1591.17 -CVEName "ADV190018"
            }
        }
	    if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU12)
	    {
	        if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU12)
	        {
	            #CVE-2019-0817,CVE-2018-0858
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.6 -CVEName "CVE-2019-0817","CVE-2019-0858"
	            #ADV190018
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.7 -CVEName "ADV190018"
	        }
	        #CVE-2019-0686,CVE-2019-0724
	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.5 -CVEName "CVE-2019-0686","CVE-2019-0724"
            #CVE-2019-1084,CVE-2019-1136,CVE-2019-1137
	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.8 -CVEName "CVE-2019-1084","CVE-2019-1136","CVE-2019-1137"
            #CVE-2019-1233,CVE-2019-1266
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1713.9 -CVEName "CVE-2019-1233","CVE-2019-1266"
	    }
	    if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU13)
	    {
	        if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU13)
	        {
                #CVE-2019-1084,CVE-2019-1136,CVE-2019-1137
	            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1779.4 -CVEName "CVE-2019-1084","CVE-2019-1136","CVE-2019-1137"
                #CVE-2019-1233,CVE-2019-1266
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 1779.5 -CVEName "CVE-2019-1233","CVE-2019-1266"
	        }
	    }
    }
    elseif($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2019)
    {
        if($exchangeCU -le [HealthChecker.ExchangeCULevel]::RTM)
        {
            #CVE-2019-0586,CVE-2019-0588
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 221.14 -CVEName "CVE-2019-0586","CVE-2019-0588"
            #CVE-2019-0817,CVE-2018-0858
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 221.16 -CVEName "CVE-2019-0817","CVE-2019-0858"
	        #ADV190018
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 221.17 -CVEName "ADV190018"
        }
	    if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU1)
	    {
	        if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU1)
	        {
                #CVE-2019-0817,CVE-2018-0858
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.7 -CVEName "CVE-2019-0817","CVE-2019-0858"
	            #ADV190018
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.8 -CVEName "ADV190018"
	        }
	        #CVE-2019-0686,CVE-2019-0724
	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.6 -CVEName "CVE-2019-0686","CVE-2019-0724"
            #CVE-2019-1084,CVE-2019-1137
	        Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.9 -CVEName "CVE-2019-1084","CVE-2019-1137"
            #CVE-2019-1233,CVE-2019-1266
            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 330.10 -CVEName "CVE-2019-1233","CVE-2019-1266"
	    }
	    if($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU2)
	    {
	        if($exchangeCU -eq [HealthChecker.ExchangeCULevel]::CU2)
	        {
                #CVE-2019-1084,CVE-2019-1137
	            Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 397.5 -CVEName "CVE-2019-1084","CVE-2019-1137"
                #CVE-2019-1233,CVE-2019-1266
                Test-VulnerabilitiesByBuildNumbersAndDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuild 397.6 -CVEName "CVE-2019-1233","CVE-2019-1266"
	        }
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
    Write-VerboseOutput("Exiting: Display-MSExchangeVulnerabilities")
}

Function Display-KBHotfixCheckFailSafe {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj
)
    Write-VerboseOutput("Calling: Display-KBHotfixCheckFailSafe")
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
  Write-VerboseOutput("Exiting: Display-KBHotfixCheckFailSafe")
}

Function Get-BuildVersionObjectFromString {
param(
[Parameter(Mandatory=$true)][string]$BuildString 
)
    Write-VerboseOutput("Calling: Get-BuildVersionObjectFromString")
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
Function Display-KBHotFixCompareIssues {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj
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
    Write-VerboseOutput("Exiting: Display-KBHotFixCompareIssues")
}

Function Display-KBHotfixCheck {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj
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
    Write-VerboseOutput("Exiting: Display-KBHotfixCheck")
}

Function Display-ResultsToScreen {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj
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
    if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical -or 
        $HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
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
            if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical -or 
                $HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
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
            if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical -or 
                $HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
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
    Write-Grey("`tProcessor Type: " + $HealthExSvrObj.HardwareInfo.Processor.Name)
    Function Check-MaxCoresCount {
    param(
    [Parameter(Mandatory=$true)][HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj
    )
        if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2019 -and 
        $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt 48)
        {
            Write-Red("`tError: More than 48 cores detected, this goes against best practices. For details see `r`n`thttps://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-2019-Public-Preview/ba-p/608158")
        }
        elseif(($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -or 
        $HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2016) -and 
        $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt 24)
        {
            Write-Red("`tError: More than 24 cores detected, this goes against best practices. For details see `r`n`thttps://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Ask-the-Perf-Guy-How-big-is-too-BIG/ba-p/603855")
        }
    }

    #First, see if we are hyperthreading
    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
    {
        #Hyperthreading enabled 
        Write-Red("`tHyper-Threading Enabled: Yes --- Error: Having Hyper-Threading enabled goes against best practices. Please disable as soon as possible.")
        if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::AmazonEC2)
        {
            Write-Red("`t`tError: For high-performance computing (HPC) application, like Exchange, Amazon recommends that you have Hyper-Threading Technology disabled in their service. More informaiton: https://aws.amazon.com/blogs/compute/disabling-intel-hyper-threading-technology-on-amazon-ec2-windows-instances/")
        }
        #AMD might not have the correct logic here. Throwing warning about this. 
        if($HealthExSvrObj.HardwareInfo.Processor.Name.StartsWith("AMD"))
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
    if(($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt 24 -and 
    $HealthExSvrObj.ExchangeInformation.ExchangeVersion -lt [HealthChecker.ExchangeVersion]::Exchange2019) -or 
    ($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt 48))
    {
        Write-Yellow("`tNumber of Physical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        Write-Yellow("`tNumber of Logical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores)
    }
    else
    {
        Write-Green("`tNumber of Physical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        Write-Green("`tNumber of Logical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores)
    }

    #NUMA BIOS CHECK - AKA check to see if we can properly see all of our cores on the box. 
	if($HealthExSvrObj.HardwareInfo.Model -like "*ProLiant*")
	{
		if($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -eq -1)
		{
			Write-Yellow("`tNUMA Group Size Optimization: Unable to determine --- Warning: If this is set to Clustered, this can cause multiple types of issues on the server")
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores)
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
		if($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -eq -1)
		{
			Write-Yellow("`tAll Processor Cores Visible: Unable to determine --- Warning: If we aren't able to see all processor cores from Exchange, we could see performance related issues.")
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores)
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
    $tlsVersions = @("1.0","1.1","1.2")
    foreach($tlsKey in $tlsVersions)
    {
        $netKey = "NETv4"
        if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2010)
        {
            $netKey = "NETv2"
        }
        $currentTlsVersion = $HealthExSvrObj.OSVersion.TLSSettings[$tlsKey]
        $currentNetVersion = $HealthExSvrObj.OSVersion.TLSSettings[$netKey]
        Write-Grey("`tTLS {0}" -f $tlsKey)
        Write-Grey("`tServer Enabled: {0}" -f $currentTlsVersion.ServerEnabled)
        Write-Grey("`tServer Disabled By Default: {0}" -f $currentTlsVersion.ServerDisabledByDefault)
        Write-Grey("`tClient Enabled: {0}" -f $currentTlsVersion.ClientEnabled)
        Write-Grey("`tClient Disabled By Default: {0}" -f $currentTlsVersion.ClientDisabledByDefault)
        if($currentTlsVersion.ServerEnabled -ne $currentTlsVersion.ClientEnabled)
        {
            Write-Red("`t`tError: Mismatch in TLS version for client and server. Exchange can be both client and a server. This can cause issues within Exchange for communication.")
            $detectedTLSMismatch = $true 
        }
        if(($tlsKey -eq "1.0" -or $tlsKey -eq "1.1") -and 
            ($currentTlsVersion.ServerEnabled -eq $false -or 
            $currentTlsVersion.ClientEnabled -eq $false -or 
            $currentTlsVersion.ServerDisabledByDefault -or 
            $currentTlsVersion.ClientDisabledByDefault) -and 
            ($currentNetVersion.SystemDefaultTlsVersions -eq $false -or
            $currentNetVersion.WowSystemDefaultTlsVersions -eq $false))
            {
                Write-Red("`t`tError: Failed to set .NET SystemDefaultTlsVersions. Please visit on how to properly enable TLS 1.2 https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761")
            }
    }
    if($detectedTLSMismatch)
    {
        Write-Yellow("`tFor More Information on how to properly set TLS follow these blog posts:")
        Write-Yellow("`t`tExchange Server TLS guidance, part 1: Getting Ready for TLS 1.2: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-part-1-Getting-Ready-for-TLS-1-2/ba-p/607649")
        Write-Yellow("`t`tExchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761")
        Write-Yellow("`t`tExchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-3-Turning-Off-TLS-1-0-1-1/ba-p/607898")
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
    Write-VerboseOutput("Exiting: Display-ResultsToScreen")
}

Function Get-HealthCheckerExchangeServerHtmlInformation
{
    param(
    [Parameter(Mandatory=$true)][HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj
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
    $ServerObject | Add-Member –MemberType NoteProperty –Name ProcessorName -Value $HealthExSvrObj.HardwareInfo.Processor.Name
    #Recommendation by PG is no more than 24 cores (this should include logical with Hyper Threading
    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt 24 -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name HyperThreading -Value "Enabled"
        }
        else
        {
            $ServerObject | Add-Member –MemberType NoteProperty –Name HyperThreading -Value "Disabled"
        }
    }
    elseif($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
    {
        if($HealthExSvrObj.HardwareInfo.Processor.Name.StartsWith("AMD"))
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

    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores -gt 24)
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfPhysicalCores -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfLogicalCores -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores
    }
    else
    {
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfPhysicalCores -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores
        $ServerObject | Add-Member –MemberType NoteProperty –Name NumberOfLogicalCores -Value $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores
    }
	if($HealthExSvrObj.HardwareInfo.Model -like "*ProLiant*")
	{
		if($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -eq -1)
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name NUMAGroupSize -Value "Undetermined"
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores)
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
		if($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -eq -1)
		{
			$ServerObject | Add-Member –MemberType NoteProperty –Name AllProcCoresVisible -Value "Undetermined"
		}
		elseif($HealthExSvrObj.HardwareInfo.Processor.EnvironmentProcessorCount -ne $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalCores)
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

Function New-HtmlServerReport {

    $Files = Get-HealthCheckFilesItemsFromLocation
    $FullPaths = Get-OnlyRecentUniqueServersXMLs $Files
    $ImportData = Import-MyData -FilePaths $FullPaths

    $AllServersOutputObject = @()
    foreach($data in $ImportData)
    {
        $AllServersOutputObject += Get-HealthCheckerExchangeServerHtmlInformation $data
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
        $ServerDetailsHtmlTable += "<tr><td>Processor</td><td>$($ServerArrayItem.Name)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Number of Processors</td><td>$($ServerArrayItem.NumberOfProcessors)</td></tr>"
        $ServerDetailsHtmlTable += "<tr><td>Logical/Physical Cores</td><td>$($ServerArrayItem.NumberOfLogicalCores)/$($ServerArrayItem.NumberOfPhysicalCores)</td></tr>"
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
    $HealthObject = Get-HealthCheckerExchangeServer $Server
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
        New-HtmlServerReport
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
