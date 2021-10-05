# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

try {
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
                public DateTime GenerationTime; //Time stamp of running the script
            }

            // ExchangeInformation
            public class ExchangeInformation
            {
                public ExchangeBuildInformation BuildInformation = new ExchangeBuildInformation();   //Exchange build information
                public object GetExchangeServer;      //Stores the Get-ExchangeServer Object
                public object GetMailboxServer;       //Stores the Get-MailboxServer Object
                public object GetOwaVirtualDirectory; //Stores the Get-OwaVirtualDirectory Object
                public object GetWebServicesVirtualDirectory; //stores the Get-WebServicesVirtualDirectory object
                public object GetOrganizationConfig; //Stores the result from Get-OrganizationConfig
                public object msExchStorageGroup;   //Stores the properties of the 'ms-Exch-Storage-Group' Schema class
                public object GetHybridConfiguration; //Stores the Get-HybridConfiguration Object
                public bool EnableDownloadDomains = new bool(); //True if Download Domains are enabled on org level
                public ExchangeNetFrameworkInformation NETFramework = new ExchangeNetFrameworkInformation();
                public bool MapiHttpEnabled; //Stored from organization config
                public System.Array ExchangeServicesNotRunning; //Contains the Exchange services not running by Test-ServiceHealth
                public Hashtable ApplicationPools = new Hashtable();
                public ExchangeRegistryValues RegistryValues = new ExchangeRegistryValues();
                public ExchangeServerMaintenance ServerMaintenance;
                public System.Array ExchangeCertificates;           //stores all the Exchange certificates on the servers.
                public object ExchangeEmergencyMitigationService;   //stores the Exchange Emergency Mitigation Service (EEMS) object
                public Hashtable ApplicationConfigFileStatus = new Hashtable();
            }

            public class ExchangeBuildInformation
            {
                public ExchangeServerRole ServerRole; //Roles that are currently set and installed.
                public ExchangeMajorVersion MajorVersion; //Exchange Version (Exchange 2010/2013/2019)
                public ExchangeCULevel CU;             // Exchange CU Level
                public string FriendlyName;     //Exchange Friendly Name is provided
                public string BuildNumber;      //Exchange Build Number
                public string LocalBuildNumber; //Local Build Number. Is only populated if from a Tools Machine
                public string ReleaseDate;      // Exchange release date for which the CU they are currently on
                public bool SupportedBuild;     //Determines if we are within the correct build of Exchange.
                public object ExchangeSetup;    //Stores the Get-Command ExSetup object
                public System.Array KBsInstalled;  //Stored object IU or Security KB fixes
                public bool March2021SUInstalled;    //True if March 2021 SU is installed
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
                public object GetMailboxServer; //TODO: Remove this
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
                public int FipsAlgorithmPolicyEnabled;       //Stores the Enabled value from HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy
            }
            // End ExchangeInformation

            // OperatingSystemInformation
            public class OperatingSystemInformation
            {
                public OSBuildInformation BuildInformation = new OSBuildInformation(); // contains build information
                public NetworkInformation NetworkInformation = new NetworkInformation(); //stores network information and settings
                public PowerPlanInformation PowerPlan = new PowerPlanInformation(); //stores the power plan information
                public object PageFile;             //stores the page file information
                public LmCompatibilityLevelInformation LmCompatibility; // stores Lm Compatibility Level Information
                public object ServerPendingReboot; // determine if server is pending a reboot.
                public TimeZoneInformation TimeZone = new TimeZoneInformation();    //stores time zone information
                public Hashtable TLSSettings;            // stores the TLS settings on the server.
                public InstalledUpdatesInformation InstalledUpdates = new InstalledUpdatesInformation();  //store the install update
                public ServerBootUpInformation ServerBootUp = new ServerBootUpInformation();   // stores the server boot up time information
                public System.Array VcRedistributable;            //stores the Visual C++ Redistributable
                public OSNetFrameworkInformation NETFramework = new OSNetFrameworkInformation();          //stores OS Net Framework
                public bool CredentialGuardEnabled;
                public OSRegistryValues RegistryValues = new OSRegistryValues();
                public object Smb1ServerSettings;
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
                public object HttpProxy;                // holds the setting for HttpProxy if one is set.
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
            // End OperatingSystemInformation

            // HardwareInformation
            public class HardwareInformation
            {
                public string Manufacturer; //String to display the hardware information
                public ServerType ServerType; //Enum to determine if the hardware is VMware, HyperV, Physical, or Unknown
                public System.Array MemoryInformation; //Detailed information about the installed memory
                public UInt64 TotalMemory; //Stores the total memory cooked value
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
                public string TestingName; // Used for pestering testing
                public int TabNumber;
                public object TestingValue; //Used for pester testing down the road.
                public object OutColumns; //used for colorized format table option.
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
} catch {
    Write-Warning "There was an error trying to add custom classes to the current PowerShell session. You need to close this session and open a new one to have the script properly work."
    exit
}
