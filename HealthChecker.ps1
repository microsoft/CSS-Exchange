<#
.NOTES
	Name: HealthChecker.ps1
	Original Author: Marc Nivens
    Author: David Paulson
    contributor: Jason Shinbaum 
	Requires: Exchange Management Shell and administrator rights on the target Exchange
	server as well as the local machine.
	Version History:
	1.31 - 9/21/2016
	3/30/2015 - Initial Public Release.
    1/18/2017 - Initial Public Release of version 2. - rewritten by David Paulson.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
	Checks the target Exchange server for various configuration recommendations from the Exchange product group.
.DESCRIPTION
	This script checks the Exchange server for various configuration recommendations outlined in the 
	"Exchange 2013 Performance Recommendations" section on TechNet, found here:

	https://technet.microsoft.com/en-us/library/dn879075(v=exchg.150).aspx

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
    https://technet.microsoft.com/en-us/library/dn879075(v=exchg.150).aspx
    https://technet.microsoft.com/en-us/library/36184b2f-4cd9-48f8-b100-867fe4c6b579(v=exchg.150)#BKMK_Prereq
#>
[CmdletBinding()]
param(
    #Default to use the local computer 
    [string]$Server=($env:COMPUTERNAME),
    [ValidateScript({-not $_.ToString().EndsWith('\')})]$OutputFilePath = ".",
    [switch]$MailboxReport,
    [switch]$LoadBalancingReport,
    $CasServerList = $null,
    $SiteName = $null,
    [switch]$ServerReport,
    $ServerList
)

<#
Note to self. "New Release Update" are functions that i need to update when a new release of Exchange is published
#>

$healthCheckerVersion = "2.6"
$VirtualizationWarning = @"
Virtual Machine detected.  Certain settings about the host hardware cannot be detected from the virtual machine.  Verify on the VM Host that: 

    - There is no more than a 1:1 Physical Core to Virtual CPU ratio (no oversubscribing)
    - If Hyper-Threading is enabled do NOT count Hyper-Threaded cores as physical cores
    - Do not oversubscribe memory or use dynamic memory allocation
    
Although Exchange technically supports up to a 2:1 physical core to vCPU ratio, a 1:1 ratio is strongly recommended for performance reasons.  Certain third party Hyper-Visors such as VMWare have their own guidance.  VMWare recommends a 1:1 ratio.  Their guidance can be found at https://www.vmware.com/files/pdf/Exchange_2013_on_VMware_Best_Practices_Guide.pdf.  For further details, please review the virtualization recommendations on TechNet at https://technet.microsoft.com/en-us/library/36184b2f-4cd9-48f8-b100-867fe4c6b579(v=exchg.150)#BKMK_Prereq.  Related specifically to VMWare, if you notice you are experiencing packet loss on your VMXNET3 adapter, you may want to review the following article from VMWare:  http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2039495. 

"@

#this is to set the verbose information to a different color 
if($PSBoundParameters["Verbose"]){
    #Write verose output in cyan since we already use yellow for warnings 
    $Script:VerboseEnabled = $true
    $VerboseForeground = $Host.PrivateData.VerboseForegroundColor #ToDo add a way to add the default setings back 
    $Host.PrivateData.VerboseForegroundColor = "Cyan"
}


#Enums and custom data types 
Add-Type -TypeDefinition @"
    namespace HealthChecker
    {
        public class HealthExchangeServerObject
        {
            public string ServerName;        //String of the server that we are working with 
            public HardwareObject HardwareInfo;  // Hardware Object Information 
            public OperatingSystemObject  OSVersion; // OS Version Object Information 
            public NetVersionObject NetVersionInfo; //.net Framework object information 
            public ExchangeInformationObject ExchangeInformation; //Detailed Exchange Information 

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
            CU16

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
			Net4d6d2 = 394748
        }

        public class HardwareObject
        {
            public string Manufacturer; //String to display the hardware information 
            public ServerType ServerType; //Enum to determine if the hardware is VMware, HyperV, Physical, or Unknown 
            public double TotalMemory; //Stores the total memory available 
            public object System;   //objec to store the system information that we have collected 
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
            public System.Array NetworkAdapters; //array to keep all the nics on the servers 
            public double TCPKeepAlive;       //value used for the TCP/IP keep alive setting 
            public System.Array HotFixes; //array to keep all the hotfixes of the server
            public PageFileObject PageFile;
            public ServerLmCompatibilityLevel LmCompat;

        }

        public class NICInformationObject 
        {
            public string Description;  //Friendly name of the adapter 
            public string LinkSpeed;    //speed of the adapter 
            public string DriverDate;   // date of the driver that is currently installed on the server 
            public string DriverVersion; // version of the driver that we are on 
            public string RSSEanbled;  //bool to determine if RSS is enabled 
            public string Name;        //name of the adapter 
            public object NICObject; //objec to store the adapter info 
             
        }

        //enum for the Exchange version 
        public enum ExchangeVersion
        {
            Unknown,
            Exchange2010,
            Exchange2013,
            Exchange2016
        }

        //enum for the OSVersion that we are
        public enum OSVersionName
        {
            Unknown,
            Windows2008, 
            Windows2008R2,
            Windows2012,
            Windows2012R2,
            Windows2016
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
            public string LmCompatibilityLevelRef; //The URL for the LmCompatibilityLevel technet (https://technet.microsoft.com/en-us/library/cc960646.aspx)
        }
    }

"@

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

function Exit-Script
{
    Write-Grey("Output file written to " + $OutputFullPath)
    Exit
}



############################################################
############################################################

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
        $page_obj.MaxPageSize = $pagefile.MaximumSize
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
        $cimSession = New-CimSession -ComputerName $Machine_Name
        $NetworkCards = Get-NetAdapter -CimSession $cimSession | ?{$_.MediaConnectionState -eq "Connected"}
        foreach($adapter in $NetworkCards)
        {
            Write-VerboseOutput("Working on getting netAdapeterRSS information for adapter: " + $adapter.InterfaceDescription)
            $RSS_Settings = $adapter | Get-netAdapterRss
            [HealthChecker.NICInformationObject]$nicObject = New-Object -TypeName HealthChecker.NICInformationObject 
            $nicObject.Description = $adapter.InterfaceDescription
            $nicObject.DriverDate = $adapter.DriverDate
            $nicObject.DriverVersion = $adapter.DriverVersionString
            $nicObject.LinkSpeed = (($adapter.Speed)/1000000).ToString() + " Mbps"
            $nicObject.RSSEanbled = $RSS_Settings.Enabled
            $nicObject.Name = $adapter.Name
            $nicObject.NICObject = $adapter 
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
            $nicObject.LinkSpeed = $adapter.Speed
            $nicObject.NICObject = $adapter 
            $aNICObjects += $nicObject
        }

    }

    return $aNICObjects 

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
        $plan = Get-WmiObject -ComputerName $Machine_Name -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "isActive='true'"
    }
    catch
    {
        $plan = $null
    }
    $os_obj.OSVersionBuild = $os.Version
    $os_obj.OSVersion = (Get-OperatingSystemVersion -OS_Version $os_obj.OSVersionBuild)
    $os_obj.OperatingSystemName = $os.Caption
    $os_obj.OperatingSystem = $os
    
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
    $os_obj.NetworkAdapters = (Build-NICInformationObject -Machine_Name $Machine_Name -OSVersion $os_obj.OSVersion) 

    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Machine_Name)
    $RegKey= $Reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
    $os_obj.TCPKeepAlive = $RegKey.GetValue("KeepAliveTime")

    $os_obj.HotFixes = (Get-HotFix -ComputerName $Machine_Name -ErrorAction SilentlyContinue)

    $os_obj.LmCompat = (Build-LmCompatibilityLevel -Machine_Name $Machine_Name)

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

        if($processor.Name -ne $processor_info_object.ProcessorName -or $processor.MaxClockSpeed -ne $processor_info_object.MaxMegacyclesPerCore){$processor_info_object.DifferentProcessorsDetected = $true; Write-VerboseOutput("Different Processors are detected"); Write-Yellow("Different Processors are detected. This shouldn't occur")}
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
[Parameter(Mandatory=$true)][int]$NetVersionKey 
)
    Write-VerboseOutput("Calling: Get-NetFrameworkVersionFriendlyInfo")
    Write-VerboseOutput("Passed: " + $NetVersionKey.ToString())
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
    elseif(($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d6d1wFix) -and ($NetVersionKey -lt [HealthChecker.NetVersion]::Net4d6d2))
    {
        $versionObject.FriendlyName = "4.6.1 with Hotfix 3146716/3146714/3146715"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d6d1wFix
    }
    elseif($NetVersionKey -ge [HealthChecker.NetVersion]::Net4d6d2)
    {
        $versionObject.FriendlyName = "4.6.2"
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Net4d6d2
    }
    else
    {
        $versionObject.FriendlyName = "Unknown" 
        $versionObject.NetVersion = [HealthChecker.NetVersion]::Unknown
    }


    Write-VerboseOutput("Returned: " + $versionObject.FriendlyName)
    return $versionObject
    
}


#Uses registry build numbers from https://msdn.microsoft.com/en-us/library/hh925568(v=vs.110).aspx
Function Build-NetFrameWorkVersionObject {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Build-NetFrameWorkVersionObject")
    Write-VerboseOutput("Passed: $Machine_Name")

    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Machine_Name)
    $RegKey = $Reg.OpenSubKey("SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")
    [int]$NetVersionKey = $RegKey.GetValue("Release")
    $sNetVersionKey = $NetVersionKey.ToString()
    Write-VerboseOutput("Got $sNetVersionKey from the registry")

    [HealthChecker.NetVersionObject]$versionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $NetVersionKey 

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

    if($AdminDisplayVersion.Major -eq 15 -and $AdminDisplayVersion.Minor -eq 1)
    {
        Write-VerboseOutput("Determined that we are on Exchange 2016")
        $exBuildObj.ExchangeVersion = [HealthChecker.ExchangeVersion]::Exchange2016
        if($buildRevision -ge 225.16 -and $buildRevision -lt 225.42) {if($buildRevision -gt 225.16){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::Preview}
        elseif($buildRevision -lt 396.30) {if($buildRevision -gt 225.42){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::RTM}
        elseif($buildRevision -lt 466.34) {if($buildRevision -gt 396.30){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU1}
        elseif($buildRevision -lt 544.27) {if($buildRevision -gt 466.34){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU2}
        elseif($buildRevision -lt 669.32) {if($buildRevision -gt 544.27){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU3}
        elseif($buildRevision -lt 845.34) {if($buildRevision -gt 669.32){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU4}
        elseif($buildRevision -ge 845.34) {if($buildRevision -gt 845.34){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU5}

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
        elseif($buildRevision -ge 1293.2) {if($buildRevision -gt 1293.2){$exBuildObj.InbetweenCUs = $true} $exBuildObj.CU = [HealthChecker.ExchangeCULevel]::CU16}
    }
    else
    {
        Write-Red "Didn't know how to process the Admin Display Version Provided"
        
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
    
    if(($AdminDisplayVersion.Major -eq 15) -and ($AdminDisplayVersion.Minor -eq 0 -or $AdminDisplayVersion.Minor -eq 1))
    {
       Write-VerboseOutput("Determined that we are working with Exchange 2013 or greater")
       [HealthChecker.ExchangeBuildObject]$exBuildObj = Get-ExchangeBuildObject -AdminDisplayVersion $AdminDisplayVersion 
       Write-VerboseOutput("Got the exBuildObj")
       Write-VerboseOutput("Exchange Version is set to: " + $exBuildObj.ExchangeVersion.ToString())
       Write-VerboseOutput("CU is set to: " + $exBuildObj.CU.ToString())
       Write-VerboseOutput("Inbetween CUs: " + $exBuildObj.InbetweenCUs.ToString())
       switch($exBuildObj.ExchangeVersion)
       {
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
                    ([HealthChecker.ExchangeCULevel]::CU4) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU4"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "12/13/2016"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU5) {$tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.FriendlyName = "Exchange 2016 CU5"; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.ReleaseDate = "03/21/2017"; $tempObject.SupportedCU = $true; break}
                    default {Write-Red "Unknown Exchange 2016 build was detected"; $tempObject.Error = $true; break;}
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
                    ([HealthChecker.ExchangeCULevel]::CU15) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU15"; $tempObject.ReleaseDate = "12/13/2016"; $tempObject.SupportedCU = $true; break}
                    ([HealthChecker.ExchangeCULevel]::CU16) {$tempObject.ExchangeBuildObject = $exBuildObj; $tempObject.InbetweenCUs = $exBuildObj.InbetweenCUs; $tempObject.ExchangeBuildNumber = (Get-BuildNumberToString $AdminDisplayVersion); $tempObject.FriendlyName = "Exchange 2013 CU16"; $tempObject.ReleaseDate = "03/21/2017"; $tempObject.SupportedCU = $true; break}
                    default {Write-Red "Unknown Exchange 2013 build was detected"; $tempObject.Error = $TRUE; break;}
                }
                break;
            }
            
        default {$tempObject.Error = $true; Write-Red "Unknown error in Get-ExchangeBuildInformation"}   
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

Exchange 2016 Support 
https://technet.microsoft.com/en-us/library/aa996719(v=exchg.160).aspx

Summary:
Exchange 2013 CU15 & 2016 CU4 .Net Framework 4.6.2 Supported on All OSs
Exchange 2016 CU3 .NET Framework 4.6.2 Supported on Windows 2016 OS - however, stuff is broke on this OS. 

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
        Write-VerboseOutput("Passed: Recommnded/Max Net Version: " + $RecommendedNetVersion.ToString())

        #If we are on the recommended/supported version of .net then we should be okay 
        if($CurrentNetVersion -eq $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current Version of .NET equals the Recommended Version of .NET")
            $NetCheckObj.Supported = $true    
        }
        elseif($CurrentNetVersion -eq [HealthChecker.NetVersion]::Net4d6 -and $RecommendedNetVersion -ge [HealthChecker.NetVersion]::Net4d6d1wFix)
        {
            Write-VerboseOutput("Current version of .NET equals 4.6 while the recommended version of .NET is greater than 4.6.1 with hotfix. This means that we are on an unsupported version because we never supported just 4.6")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__
            $NetCheckObj.DisplayWording = "On .NET 4.6 and this is an unsupported build of .NET for Exchange. Only .NET 4.6.1 with the hotfix and greater are supported. Please upgrade to " + $RecommendedNetVersionObject.FriendlyName + " as soon as possible to get into a supported state."
        }
        #this catch is for when you are on a version of exchange where we can be on let's say 4.5.2 without fix, but there isn't a better option available.
        elseif($CurrentNetVersion -lt $MinSupportNetVersion -and $MinSupportNetVersion -eq $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version of .NET is less than Min Supported Version. Need to upgrade to this version as soon as possible")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ 
            [HealthChecker.NetVersionObject]$MinSupportNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $MinSupportNetVersion.value__ 
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the minimum supported version is " + $MinSupportNetVersionObject.FriendlyName + ". Upgrade to this version as soon as possible."
        }
        #here we are assuming that we are able to get to a much better version of .NET then the min 
        elseif($CurrentNetVersion -lt $MinSupportNetVersion)
        {
            Write-VerboseOutput("Current Version of .NET is less than Min Supported Version. However, the recommended version is the one we want to upgrade to")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ 
            [HealthChecker.NetVersionObject]$MinSupportNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $MinSupportNetVersion.value__ 
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the minimum supported version is " + $MinSupportNetVersionObject.FriendlyName + ", but the recommended version is " + $RecommendedNetVersionObject.FriendlyName + ". upgrade to this version as soon as possible." 
        }
        elseif($CurrentNetVersion -lt $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version is less than the recommended version, but we are at or higher than the Min Supported level. Should upgrade to the recommended version as soon as possible.")
            $NetCheckObj.Supported = $true
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ 
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the recommended version of .NET for this build of Exchange is " + $RecommendedNetVersionObject.FriendlyName + ". Upgrade to this version as soon as possible." 
        }
        elseif($CurrentNetVersion -gt $RecommendedNetVersion)
        {
            Write-VerboseOutput("Current version is greater than the recommended version. This is an unsupported state.")
            $NetCheckObj.Supported = $false
            $NetCheckObj.RecommendedNetVersion = $false 
            [HealthChecker.NetVersionObject]$currentNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $CurrentNetVersion.value__ 
            [HealthChecker.NetVersionObject]$RecommendedNetVersionObject = Get-NetFrameworkVersionFriendlyInfo -NetVersionKey $RecommendedNetVersion.value__
            $NetCheckObj.DisplayWording = "On .NET " + $currentNetVersionObject.FriendlyName + " and the max recommnded version of .NET for this build of Exchange is " + $RecommendedNetVersionObject.FriendlyName + ". Correctly remove the .NET version that you are on and reinstall the recommended max value. Generic catch message for current .NET version being greater than Max .NET version, so ask or lookup on the correct steps to address this issue."
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

                if($exBuildObj.CU -lt [HealthChecker.ExchangeCULevel]::CU12) 
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d5d2wFix
                }
                elseif($exBuildObj.CU -lt [HealthChecker.ExchangeCULevel]::CU15)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d1wFix
                }
                elseif($exBuildObj.CU -eq [HealthChecker.ExchangeCULevel]::CU15)
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d5d2wFix -RecommendedNetVersion Net4d6d2
                    $NetCheckObj.DisplayWording = $NetCheckObj.DisplayWording + " NOTE: Starting with CU16 we will require .NET 4.6.2 before you can install this version of Exchange." 
                }
                else
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d6d2 -RecommendedNetVersion Net4d6d2
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
                else
                {
                    $NetCheckObj = Check-NetVersionToExchangeVersion -CurrentNetVersion $NetVersion -MinSupportNetVersion Net4d6d2 -RecommendedNetVersion Net4d6d2 
                }
                

                break;
            }
        default {$NetCheckObj.Error = $true; Write-VerboseOutput("Error trying to determine major version of Exchange for .NET fix level")}
    }

    return $NetCheckObj

}

Function Get-ExchangeUpdates {
param(
[Parameter(Mandatory=$true)][string]$Machine_Name
)
    Write-VerboseOutput("Calling: Get-ExchangeUpdates")
    Write-VerboseOutput("Passed: " + $Machine_Name)
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Machine_Name)
    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Updates\Exchange 2013\SP1")
    if($RegKey -ne $null)
    {
        $IU = $RegKey.GetSubKeyNames()
        if($IU -ne $null)
        {
            Write-VerboseOutput("Detected fixes installed on the server")
            $fixes = @()
            foreach($key in $IU)
            {
                $IUKey = $Reg.OpenSubKey("SOFTWARE\Microsoft\Updates\Exchange 2013\SP1\" + $key)
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

    #Exchange 2013 and 2016 things to check 
    if($exchInfoObject.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013) 
    {
        Write-VerboseOutput("Exchange 2013 or greater detected")
        $HealthExSvrObj.NetVersionInfo = Build-NetFrameWorkVersionObject -Machine_Name $Machine_Name 
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
                Write-Yellow "unlabed to determine if .NET is supported"
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
            Write-Yellow "couldn't get acturate information on server: $Machine_Name"
        }

        $exchInfoObject.KBsInstalled = Get-ExchangeUpdates -Machine_Name $Machine_Name
    }
    elseif($exchInfoObject.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        Write-VerboseOutput("Exchange 2010 detected")
        $exchInfoObject.ExchangeFriendlyName = "Exchange 2010"
        $exchInfoObject.ExchangeBuildNumber = $exchInfoObject.ExchangeServerObject.AdminDisplayVersion
    }
    else
    {
        Write-Red "unknown version of Exchange detected for server: $Machine_Name"
       
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
    $MountedDBs = $AllDBs | ?{$_.Status -eq 'Healthy'}
    if($MountedDBs.Count -gt 0)
    {
        Write-Grey("`tActive Database:")
        foreach($db in $MountedDBs)
        {
            Write-Grey("`t`t" + $db.Name)
        }
        $MountedDBs.DatabaseName | %{Write-VerboseOutput("Calculating User Mailbox Total for Active Database: $_"); $TotalActiveUserMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited).Count}
        Write-Grey("`tTotal Active User Mailboxes on server: " + $TotalActiveUserMailboxCount)
        $MountedDBs.DatabaseName | %{Write-VerboseOutput("Calculating Public Mailbox Total for Active Database: $_"); $TotalActivePublicFolderMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited -PublicFolder).Count}
        Write-Grey("`tTotal Active Public Folder Mailboxes on server: " + $TotalActivePublicFolderMailboxCount)
        Write-Grey("`tTotal Active Mailboxes on server " + $Machine_Name + ": " + ($TotalActiveUserMailboxCount + $TotalActivePublicFolderMailboxCount).ToString())
    }
    else
    {
        Write-Grey("`tNo Active Mailbox Databases found on server " + $Machine_Name + ".")
    }
    $HealthyDbs = $AllDBs | ?{$_.Status -eq 'Healthy'}
    if($HealthyDbs.count -gt 0)
    {
        Write-Grey("`r`n`tPassive Databases:")
        foreach($db in $HealthyDbs)
        {
            Write-Grey("`t`t" + $db.Name)
        }
        $HealthyDbs.DatabaseName | %{Write-VerboseOutput("`tCalculating User Mailbox Total for Passive Healthy Databases: $_"); $TotalPassiveUserMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited).Count}
        Write-Grey("`tTotal Passive user Mailboxes on Server: " + $TotalPassiveUserMailboxCount)
        $HealthyDbs.DatabaseName | %{Write-VerboseOutput("`tCalculating Passive Mailbox Total for Passive Healthy Databases: $_"); $TotalPassivePublicFolderMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited -PublicFolder).Count}
        Write-Grey("`tTotal Passive Public Mailboxes on server: " + $TotalPassivePublicFolderMailboxCount)
        Write-Grey("`tTotal Passive Mailboxes on server: " + ($TotalPassiveUserMailboxCount + $TotalPassivePublicFolderMailboxCount).ToString()) 
    }
    else
    {
        Write-Grey("`tNo Passive Mailboxes found on server " + $Machine_Name + ".")
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
	elseif($SiteName -ne $null)
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
		Write-Red("No CAS servers found using the specified search criteria.")
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
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Machine_Name)
    $RegKey = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa")
    $RegValue = $RegKey.GetValue("LmCompatibilityLevel")
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
    
    $ServerLmCompatObject.LmCompatibilityLevelRef = "https://technet.microsoft.com/en-us/library/cc960646.aspx"
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

Function Display-ResultsToScreen {
param(
[Parameter(Mandatory=$true)][HealthChecker.HealthExchangeServerObject]$HealthExSvrObj
)
    Write-VerboseOutput("Calling: Display-ResultsToScreen")
    Write-VerboseOutput("For Server: " + $HealthExSvrObj.ServerName)

    ####################
    #Header information#
    ####################

    Write-Green("Exchange Health Checker version " + $healthCheckerVersion)
    Write-Green("System Information Report for " + $HealthExSvrObj.ServerName + " on " + (Get-Date)) 
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
    Write-Grey("`tExchange: " + $HealthExSvrObj.ExchangeInformation.ExchangeFriendlyName)
    Write-Grey("`tBuild Number: " + $HealthExSvrObj.ExchangeInformation.ExchangeBuildNumber)
    if($HealthExSvrObj.ExchangeInformation.SupportedExchangeBuild -eq $false -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -ge [HealthChecker.ExchangeVersion]::Exchange2013)
    {
        $Dif_Days = ((Get-Date) - ([System.Convert]::ToDateTime([DateTime]$HealthExSvrObj.ExchangeInformation.BuildReleaseDate))).Days
        Write-Red("`tOut of date Cumulative Update.  Please upgrade to one of the two most recently released Cumulative Updates. Currently running on a build that is " + $Dif_Days + " Days old")
    }
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -eq [HealthChecker.ExchangeVersion]::Exchange2013 -and ($HealthExSvrObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::Edge -and $HealthExSvrObj.ExchangeInformation.ExServerRole -ne [HealthChecker.ServerRole]::MultiRole))
    {
        Write-Yellow("`tServer Role: " + $HealthExSvrObj.ExchangeInformation.ExServerRole.ToString() + " --- Warning: Multi-Role servers are recommended") 
    }
    else
    {
        Write-Grey("`tServer Role: " + $HealthExSvrObj.ExchangeInformation.ExServerRole.ToString())
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
            Write-Yellow("`tPagefile Size: " + $sDisplay)
            Write-Yellow("`tNote: Please double check page file setting, as WMI Object Win32_ComputerSystem doesn't report the best value for total memory available") 
        }
    }
    #Exchange 2013+ with memory greater than 32 GB. Should be set to 32 + 10 MB for a value 
    #32GB = 1024 * 1024 * 1024 * 32 = 34,359,738,368 
    elseif($HealthExSvrObj.HardwareInfo.TotalMemory -ge 34359738368)
    {
        if($HealthExSvrObj.OSVersion.PageFile.MaxPageSize -eq 32778)
        {
            Write-Grey("`tPagefile Size: " + $HealthExSvrObj.OSVersion.PageFile.MaxPageSize)
        }
        else
        {
            Write-Yellow("`tPagefile Size: " + $HealthExSvrObj.OSVersion.PageFile.MaxPageSize + " --- Warning: Pagefile should be capped at 32778 MB for 32 GB Plus 10 MB")
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
            Write-Yellow("`tPagefile Size: " + $sDisplay)
            Write-Yellow("`tNote: Please double check page file setting, as WMI Object Win32_ComputerSystem doesn't report the best value for total memory available") 
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
                Write-Yellow("`tDetected Version: " + $HealthExSvrObj.NetVersionInfo.FriendlyName + " --- " + $HealthExSvrObj.NetVersionInfo.DisplayWording)
            }
        }
        else
        {
            Write-Red("`tDetected Version: " + $HealthExSvrObj.NetVersionInfo.FriendlyName + " --- " + $HealthExSvrObj.NetVersionInfo.DisplayWording)
        }

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
        Write-Red("`tPower Plan: Not Accessible")
    }
    else
    {
        Write-Red("`tPower Plan: " + $HealthExSvrObj.OSVersion.PowerPlanSetting + " --- Error: High Performance Power Plan is recommended")
    }

    ##################
    #Network Settings#
    ##################

    Write-Grey("NIC settings per active adapter:")
    if($HealthExSvrObj.OSVersion.OSVersion -ge [HealthChecker.OSVersionName]::Windows2012R2)
    {
        foreach($adapter in $HealthExSvrObj.OSVersion.NetworkAdapters)
        {
            Write-Grey(("`tInterface Description: {0} [{1}] " -f $adapter.Description, $adapter.Name))
            if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
            {
                if((New-TimeSpan -Start (Get-Date) -End $adapter.DriverDate) -lt [int]-365)
                {
                    Write-Yellow("`t`tWarning: NIC driver is over 1 year old. Verify you are at the latest version.")
                }
                Write-Grey("`t`tDriver Date: " + $adapter.DriverDate)
                Write-Grey("`t`tDriver Version: " + $adapter.DriverVersion)
                Write-Grey("`t`tLink Speed: " + $adapter.LinkSpeed)
            }
            else
            {
                Write-Yellow("`t`tLink Speed: Cannot be accurately determined due to virtualized hardware")
            }
            if($adapter.RSSEanbled)
            {
                Write-Green("`t`tRSS: Enabled")
            }
            else
            {
                Write-Yellow("`t`tRSS: Disabled --- Warning: Enabling RSS is recommended.")
            }
            
        }

    }
    else
    {
        Write-Grey("NIC settings per active adapter:")
        Write-Yellow("`tMore detailed NIC settings can be detected if both the local and target server are running on Windows 2012 R2 or later.")
        
        foreach($adapter in $HealthExSvrObj.OSVersion.NetworkAdapters)
        {
            Write-Grey("`tInterface Description: " + $adapter.Description)
            if($HealthExSvrObj.HardwareInfo.ServerType -eq [HealthChecker.ServerType]::Physical)
            {
                Write-Grey("`tLink Speed: " + $adapter.LinkSpeed)
            }
            else 
            {
                Write-Yellow("`tLink Speed: Cannot be accurately determined due to virtualization hardware")    
            }
        }
        
    }
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        if($HealthExSvrObj.OSVersion.NetworkAdapters.Count -gt 1 -and ($HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::Mailbox -or $HealthExSvrObj.ExchangeInformation.ExServerRole -eq [HealthChecker.ServerRole]::MultiRole))
        {
            Write-Yellow("`t`tMultiple active network adapters detected. Exchange 2013 or greater may not need separate adapters for MAPI and replication traffic.  For details please refer to https://technet.microsoft.com/en-us/library/29bb0358-fc8e-4437-8feb-d2959ed0f102(v=exchg.150)#NR")
        }
    }

    #######################
    #Processor Information#
    #######################
    Write-Grey("Processor/Memory Information")
    Write-Grey("`tProcessor Type: " + $HealthExSvrObj.HardwareInfo.Processor.ProcessorName)
    #Recommendation by PG is no more than 24 cores (this should include logical with Hyper Threading
    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 24 -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        {
            Write-Yellow("`tHyper-Threading Enabled: Yes")
            Write-Red("`tMore than 24 logical cores detected.  Please disable Hyper-Threading.  For details see`r`n`thttp://http://blogs.technet.com/b/exchange/archive/2015/06/19/ask-the-perf-guy-how-big-is-too-big.aspx")
        }
        else
        {
            Write-Green("`tHyper-Threading Enabled: No")
            Write-Red("`tMore than 24 physical cores detected.  This is not recommended.  For details see`r`n`thttp://http://blogs.technet.com/b/exchange/archive/2015/06/19/ask-the-perf-guy-how-big-is-too-big.aspx")
        }
    }
    elseif($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
    {
        if($HealthExSvrObj.HardwareInfo.Processor.ProcessorName.StartsWith("AMD"))
        {
            Write-Yellow("`tHyper-Threading Enabled: Yes")
            Write-Yellow("`tThis script may incorrectly report that Hyper-Threading is enabled on certain AMD processors.  Check with the manufacturer to see if your model supports SMT.")
        }
        else
        {
            Write-Yellow("`tHyper-Threading Enabled: Yes --- Warning: Enabling Hyper-Threading is not recommended")
        }
    }
    else
    {
        Write-Green("`tHyper-Threading Enabled: No")
    }
    Write-Grey("`tNumber of Processors: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfProcessors)
    if($HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors -gt 24)
    {
        Write-Yellow("`tNumber of Physical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        Write-Yellow("`tNumber of Logical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
    }
    else
    {
        Write-Green("`tNumber of Physical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfPhysicalCores)
        Write-Green("`tNumber of Logical Cores: " + $HealthExSvrObj.HardwareInfo.Processor.NumberOfLogicalProcessors)
    }
    if($HealthExSvrObj.HardwareInfo.Processor.ProcessorIsThrottled)
    {
        #We are set correctly at the OS layer
        if($HealthExSvrObj.OSVersion.HighPerformanceSet)
        {
            Write-Red("`tProcessor speed is being throttled. Power plan is set to `"High performance`", so it is likely that we are throttling in the BIOS of the computer settings")
        }
        else
        {
            Write-Red("`tProcessor speed is being throttled. Power plan isn't set to `"High performance`". Change this ASAP because you are throttling your CPU and is likely causing issues.")
            Write-Red("`tNote: This change doesn't require a reboot and takes affect right away. Re-run the script after doing so")
        }
        Write-Red("`tCurrent Processor Speed: " + $HealthExSvrObj.HardwareInfo.Processor.CurrentMegacyclesPerCore)
        Write-Red("`tMax Processor Speed: " + $HealthExSvrObj.HardwareInfo.Processor.MaxMegacyclesPerCore)
    }
    else
    {
        Write-Grey("`tMegacycles Per Core: " + $HealthExSvrObj.HardwareInfo.Processor.MaxMegacyclesPerCore)
    }
    
    #Memory Going to check for greater than 96GB of memory
    #The value that we shouldn't be greater than is 103,079,215,104 (96 * 1024 * 1024 * 1024) 
    $totalPhysicalMemory = [System.Math]::Round($HealthExSvrObj.HardwareInfo.TotalMemory / 1024 /1024 /1024) 
    if($HealthExSvrObj.HardwareInfo.TotalMemory -gt 103079215104 -and $HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
        Write-Yellow ("`tPhysical Memory: " + $totalPhysicalMemory + " GB --- We recommend for the best performance to be scaled at 96GB of Memory. However, having higher memory than this has yet to be linked directly to a MAJOR performance issue of a server.")
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
	    $services = Test-ServiceHealth -Server $HealthExSvrObj.ServerName | %{$_.ServicesNotRunning}
	    if($services.length -gt 0)
	    {
		    Write-Yellow("`r`nThe following services are not running:")
		    $services | %{Write-Grey($_)}
	    }
    }

    #################
	#TCP/IP Settings#
	#################
    Write-Grey("`r`nTCP/IP Settings:")
    if($HealthExSvrObj.OSVersion.TCPKeepAlive -eq 0)
    {
        Write-Red("The TCP KeepAliveTime value is not specified in the registry.  Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration.  To avoid issues, add the KeepAliveTime REG_DWORD entry under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters and set it to a value between 900000 and 1800000 decimal.  You want to ensure that the TCP idle timeout value gets higher as you go out from Exchange, not lower.  For example if the Exchange server has a value of 30 minutes, the Load Balancer could have an idle timeout of 35 minutes, and the firewall could have an idle timeout of 40 minutes.  Please note that this change will require a restart of the system.  Refer to the sections `"CAS Configuration`" and `"Load Balancer Configuration`" in this blog post for more details:  https://blogs.technet.microsoft.com/exchange/2016/05/31/checklist-for-troubleshooting-outlook-connectivity-in-exchange-2013-and-2016-on-premises/")
    }
    elseif($HealthExSvrObj.OSVersion.TCPKeepAlive -lt 900000 -or $HealthExSvrObj.OSVersion.TCPKeepAlive -gt 1800000)
    {
        Write-Yellow("The TCP KeepAliveTime value is not configured optimally.  It is currently set to " + $KeepAliveValue + ". This can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration.  To avoid issues, set the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime registry entry to a value between 15 and 30 minutes (900000 and 1800000 decimal).  You want to ensure that the TCP idle timeout gets higher as you go out from Exchange, not lower.  For example if the Exchange server has a value of 30 minutes, the Load Balancer could have an idle timeout of 35 minutes, and the firewall could have an idle timeout of 40 minutes.  Please note that this change will require a restart of the system.  Refer to the sections `"CAS Configuration`" and `"Load Balancer Configuration`" in this blog post for more details:  https://blogs.technet.microsoft.com/exchange/2016/05/31/checklist-for-troubleshooting-outlook-connectivity-in-exchange-2013-and-2016-on-premises/")
    }
    else
    {
        Write-Green("The TCP KeepAliveTime value is configured optimally (" + $HealthExSvrObj.OSVersion.TCPKeepAlive + ")")
    }

    ###############################
	#LmCompatibilityLevel Settings#
	###############################
    Write-Grey("`r`nLmCompatibilityLevel Settings:")
    Write-Grey("`tLmCompatibilityLevel is set to: " + $HealthExSvrObj.OSVersion.LmCompat.LmCompatibilityLevel)
    Write-Grey("`tLmCompatibilityLevel Description: " + $HealthExSvrObj.OSVersion.LmCompat.LmCompatibilityLevelDescription)
    Write-Grey("`tLmCompatibilityLevel Ref: " + $HealthExSvrObj.OSVersion.LmCompat.LmCompatibilityLevelRef)

	##############
	#Hotfix Check#
	##############
    
    if($HealthExSvrObj.ExchangeInformation.ExchangeVersion -ne [HealthChecker.ExchangeVersion]::Exchange2010)
    {
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
                    Write-Yellow("Hotfix " + $check + " is recommended for this OS and was not detected.  Please consider installing it to prevent performance issues.")
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


    Write-Grey("`r`n`r`n")

}


Function Main {
    
    

    if((Test-Path $OutputFilePath) -eq $false)
    {
        Write-Host "Invalid value specified for -OutputFilePath." -ForegroundColor Red
        exit 
    }
    $iErrorStartCount = $Error.Count #useful for debugging 
    $OutputFileName = "HealthCheck" + "-" + $Server + "-" + (get-date).tostring("MMddyyyyHHmmss") + ".log"
    $OutputFullPath = $OutputFilePath + "\" + $OutputFileName
    Write-VerboseOutput("Calling: main Script Execution")

    if($LoadBalancingReport)
    {
        [int]$iMajor = (Get-ExchangeServer $Server).AdminDisplayVersion.Major
        if($iMajor -gt 14)
        {
            $OutputFileName = "LoadBalancingReport" + "-" + (get-date).tostring("MMddyyyyHHmmss") + ".log"
            $OutputFullPath = $OutputFilePath + "\" + $OutputFileName
            Write-Green("Exchange Health Checker Script version: " + $healthCheckerVersion)
            Write-Green("Client Access Load Balancing Report on " + (Get-Date))
            Get-CASLoadBalancingReport
            Write-Grey("Output file written to " + $OutputFullPath)
            Write-Break
            Write-Break
        }
        else
        {
            Write-Yellow("-LoadBalancingReport is only supported for Exchange 2013 and greater")
        }
    }
    
    $OutputFileName = "HealthCheck" + "-" + $Server + "-" + (get-date).tostring("MMddyyyyHHmmss") + ".log"
    $OutputFullPath = $OutputFilePath + "\" + $OutputFileName
    $OutXmlFullPath = $OutputFilePath + "\" + ($OutputFileName.Replace(".log",".xml"))
    $HealthObject = Build-HealthExchangeServerObject $Server
    Display-ResultsToScreen $healthObject 
    if($MailboxReport)
    {
        Get-MailboxDatabaseAndMailboxStatistics -Machine_Name $Server
    }
    Write-Grey("Output file written to " + $OutputFullPath)
    if($Error.Count -gt $iErrorStartCount)
    {
        Write-Grey(" ");Write-Grey(" ")

        $index = 0; 
        "Errors that occurred" | Out-File ($OutputFullPath) -Append
        while($index -lt ($Error.Count - $iErrorStartCount))
        {
            $Error[$index++] | Out-File ($OutputFullPath) -Append
        }
        Write-Red("There appears to have been some errors in the script. To assist with debugging of the script, please RE-RUN the script with -Verbose send the .log and .xml file to dpaul@microsoft.com.")
        
    }
    Write-Grey("Exported Data Object written to " + $OutXmlFullPath)
    $HealthObject | Export-Clixml -Path $OutXmlFullPath -Encoding UTF8 -Depth 5
}

Main 