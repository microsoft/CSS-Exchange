# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$healthCheckerCustomClass = @"
using System;
using System.Collections;
    namespace HealthChecker
    {
        public class HealthCheckerExchangeServer
        {
            public string ServerName;        //String of the server that we are working with
            public HardwareInformation HardwareInformation;  // Hardware Object Information
            public object  OSInformation; // OS Version Object Information
            public ExchangeInformation ExchangeInformation; //Detailed Exchange Information
            public OrganizationInformation OrganizationInformation; // Organization Information that doesn't need to be collect multiple times.
            public string HealthCheckerVersion; //To determine the version of the script on the object.
            public DateTime GenerationTime; //Time stamp of running the script
        }

        // Organization Information - Things that only need to be collected once
        public class OrganizationInformation
        {
            public object GetOrganizationConfig; //Stores the result from Get-OrganizationConfig
            public object DomainsAclPermissions; //Stores the ACLs that we care about from Exchange Domain that contains the MESO container
            public object WellKnownSecurityGroups; //Stores the well known Exchange Security Groups information
            public object AdSchemaInformation;   //Stores the properties of from the Schema class
            public object GetHybridConfiguration; //Stores the Get-HybridConfiguration Object
            public object EnableDownloadDomains; //True if Download Domains are enabled on org level
            public object WildCardAcceptedDomain; // for issues with * accepted domain.
            public System.Array AMSIConfiguration; //Stores the Setting Override for AMSI Interface
            public bool MapiHttpEnabled; //Stored from organization config
            public object SecurityResults; // Stores different CVE results that are secured against Setup.exe /PrepareAD /PrepareDomain /PrepareSchema
            public bool IsSplitADPermissions = new bool(); // Used to determine if split permissions are detected.
            public int ADSiteCount; // Count for the numbers of sites the environment has.
            public object GetSettingOverride; // Stores the Get-SettingOverride
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
            public object ExchangeAdPermissions; //Stores the Exchange AD permissions for vulnerability testing
            public object ExtendedProtectionConfig; //Stores the extended protection configuration
            public object ExchangeConnectors; //Stores the Get-ExchangeConnectors Object
            public System.Array AMSIConfiguration; //Stores the Setting Override for AMSI Interface
            public System.Array SerializationDataSigningConfiguration; //Stores for the SerializationDataSigning feature configuration
            public ExchangeNetFrameworkInformation NETFramework = new ExchangeNetFrameworkInformation();
            public System.Array ExchangeServicesNotRunning; //Contains the Exchange services not running by Test-ServiceHealth
            public Hashtable ApplicationPools = new Hashtable();
            public object RegistryValues; //stores all Exchange Registry values
            public ExchangeServerMaintenance ServerMaintenance;
            public System.Array ExchangeCertificates;           //stores all the Exchange certificates on the servers.
            public object ExchangeEmergencyMitigationService;   //stores the Exchange Emergency Mitigation Service (EEMS) object
            public Hashtable ApplicationConfigFileStatus = new Hashtable();
            public object DependentServices; // store the results for the dependent services of Exchange.
            public object IISSettings;  //Stores the IISConfigurationSettings, applicationHostConfig and IISModulesInformation
            public object SettingOverrides; //Stores the information regarding the Exchange Setting Overrides on the server.
        }

        public class ExchangeBuildInformation
        {
            public ExchangeServerRole ServerRole; //Roles that are currently set and installed.
            public ExchangeMajorVersion MajorVersion; //Exchange Version (Exchange 2010/2013/2019)
            public ExchangeCULevel CU;             // Exchange CU Level
            public object VersionInformation; // Stores results from Get-ExchangeBuildVersionInformation
            public System.Version LocalBuildNumber; //Local Build Number. Is only populated if from a Tools Machine
            public object ExchangeSetup;    //Stores the Get-Command ExSetup object
            public System.Array KBsInstalled;  //Stored object IU or Security KB fixes
            public bool March2021SUInstalled;    //True if March 2021 SU is installed
            public object FIPFSUpdateIssue; //Stores FIP-FS update issue information
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
        // End ExchangeInformation

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
            Windows2022,
            WindowsCore
        }

        //enum for the DWORD value of the .NET frame 4 that we are on
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
            public int EnvironmentProcessorCount; //[system.environment]::ProcessorCount
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
            public object TableValue;
            public string Class;
        }

        public class DisplayResultsLineInfo
        {
            public string DisplayValue;
            public string Name;
            public string TestingName; // Used for pestering testing
            public string CustomName; // Used for security vulnerability
            public int TabNumber;
            public object TestingValue; //Used for pester testing down the road.
            public object CustomValue; // Used for security vulnerability
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
            public object HealthCheckerExchangeServer;
            public Hashtable HtmlServerValues = new Hashtable();
            public Hashtable DisplayResults = new Hashtable();
        }
    }
"@

try {
    #Enums and custom data types
    if (-not($ScriptUpdateOnly)) {
        Add-Type -TypeDefinition $healthCheckerCustomClass -ErrorAction Stop
    }
} catch {
    Write-Warning "There was an error trying to add custom classes to the current PowerShell session. You need to close this session and open a new one to have the script properly work."
    exit
}
