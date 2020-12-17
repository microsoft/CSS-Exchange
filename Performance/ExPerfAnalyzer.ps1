[CmdletBinding()]
Param(
#[Parameter(Mandatory=$true,ParameterSetName="FileDirectory")][string]$PerfmonFileDirectory,
[Parameter(Mandatory=$false,ParameterSetName="FileDirectory")]
	[Parameter(ParameterSetName="SingleFile")][int64]$MaxSamples = [Int64]::MaxValue,
[Parameter(Mandatory=$false,ParameterSetName="FileDirectory")]
	[Parameter(ParameterSetName="SingleFile")][DateTime]$StartTime = [DateTime]::MinValue,
[Parameter(Mandatory=$false,ParameterSetName="FileDirectory")]
	[Parameter(ParameterSetName="SingleFile")][DateTime]$EndTime = [DateTime]::MaxValue,
[Parameter(Position=0,Mandatory=$true,ParameterSetName="SingleFile")][string]$PerfmonFile,
[Parameter(Mandatory=$false,ParameterSetName="RegisterHandler")][Switch]$RegisterHandler
)
$ScriptVersion = "v2.3"
$ShowNProcesses = 10

#Class
Add-Type @"
using System; 
using System.Collections.Generic;
using System.Linq;

namespace PerformanceHealth
{
	public class HealthReport
	{
		public string ChangeTime;
		public string Status;
		public string Reason;
		public string DisplayInfo;
		//public System.Array ChangeLog; 
	}

	public class HealthReportEntries
	{
		public string ChangeTime;
		public string Status;
		public string Reason;
		public string DisplayInfo; 
	}

	public class ServerPerformanceObject
	{
		public string ServerName;
		public string FileName; 
		public System.DateTime StartTime;
		public System.DateTime EndTime;
		public AccuracyObject Accuracy;
		public HealthReport HealthReport;
		public object[] CounterData;
		public System.TimeSpan ReadTime;
	}
	
	public class CounterDataObject
	{
		public string FullName;
		public string ServerName;
		public string ObjectName;
		public string InstanceName;
		public string CounterName;
		public string CounterCategory;
		public string DetectIssuesType;
		public string CounterType; 
		public HealthReport HealthReport;
		public AccuracyObject Accuracy;
		public DisplayOptionsObject DisplayOptions;
		public CounterThresholds Threshold;
		public QuickSummaryStatsObject QuickSummaryStats;
		public object[] AllRawData;
		public IEnumerable<object> RawData { get { return AllRawData.Skip(1); } }
		public object FirstSample { get { return RawData.First(); } }
		public object LastSample { get { return RawData.Last(); } }
	}

	public class CounterNameObject
    {
        public string ServerName;
        public string ObjectName;
        public string CounterName;
        public string InstanceName;
        public string FullName;
    }


	public class CounterThresholds
	{
		public double MaxValue;
		public double WarningValue;
		public double AverageValue; 
	}



	public class DisplayOptionsObject 
	{
		public double FormatDivider;
		public string FormatString;
	}

	public class QuickSummaryStatsObject
	{
		public double Avg;
		public double Min;
		public double Max;
		public System.DateTime StartTime;
		public System.DateTime EndTime; 
		public System.TimeSpan Duration; 
	}

	/*
	public class RawDataObject
	{
		public System.DateTime TimeStamp;
		//public UInt64 TimeBase; 
		//public UInt64 RawValue;
		//public UInt64 SecondValue;
		public double CookedValue; 
	}
	*/
	public class AccuracyObject
	{
		public double Percentage;
		public int SumDatPoints;
		public int EstimatedDataPoints; 
	}

	public class PerfFileDataInfo
	{
		public object[] CounterSamples;
		public TimeSpan ReadingFileTime;
		public string FileName;
	}

}

"@ 

<#
Main Object class 

[array]aMainObject
	[ServerPerformanceObject]
		[string]ServerName
		[DateTime]StartTime
		[DateTime]EndTime
		[AccuracyObject]Accuracy
			[double]Percentage
			[int]SumDataPoints
			[int]EstimatedDataPoints		
		[HealthReport]
			[string/enum]Status
			[string]ChangeTime
			[string]Reason
			[string]DisplayInfo
			[Array]ChangeLog
				[HealthReportEntries]
					[string]ChangeTime
					[string/enum]Status
					[string]Reason
					[string]DisplayInfo
		[array]CounterData
			[CounterDataObject]
				[string]FullName
				[string]ServerName
				[string]ObjectName
				[string]InstanceName
				[string]CounterName
				[string]CounterCategory
				[string]DetectIssuesType
				[string]CounterType
				[HealthReport]
				[AccuracyObject]Accuracy
				[DisplayOptions]
					[string]FormatString
					[double]FormatDivider
				[CounterThresholds]Threshold
					[double]MaxValue
					[double]WarningValue
					[double]AverageValue
				[QuickSummaryStats]
					[double]Avg
					[double]Min
					[double]Max
					[DateTime]StartTime
					[DateTime]EndTime
					[TimeSpan]Duration
				[Array]RawData
					[DateTime]TimeStamp
					[UInt64]TimeBase
					[UInt64]RawValue
					[UInt64]SecondValue
					[Double]CookedValue

#>


<#
Format of the xml counters 
<Counter Name = "">
	<Category></Category>
	<CounterSetName></CounterSetName>
	<CounterName></CounterName>
	<DisplayOptions>
		<FormatDivider></FormatDivider>
		<FormatString></FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>


<Counter Name = "\System\Context Switches/sec">
	<Category>Processor</Category>
	<CounterSetName>System</CounterSetName>
	<CounterName>Context Switches/sec</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>90000</Average>
		<Maxvalue>200000</Maxvalue>
		<WarningValue>150000</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>NormalGreaterThanThresholdCheck</Main>
	</MonitorChecks>
</Counter>



#>

$xmlCountersToAnalyze = [xml]@"
<Counters>
<Counter Name = "\LogicalDisk(*)\Avg. Disk sec/Read">
	<Category>Disk</Category>
	<CounterSetName>LogicalDisk</CounterSetName>
	<CounterName>Avg. Disk sec/Read</CounterName>
	<DisplayOptions>
		<FormatDivider>0.001</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>0.020</Average>
		<Maxvalue>0.001</Maxvalue>
		<WarningValue>0.001</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>DeepGreaterThanThresholdCheck</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\LogicalDisk(*)\Avg. Disk sec/Write">
	<Category>Disk</Category>
	<CounterSetName>LogicalDisk</CounterSetName>
	<CounterName>Avg. Disk sec/Write</CounterName>
	<DisplayOptions>
		<FormatDivider>0.001</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>0.020</Average>
		<Maxvalue>0.001</Maxvalue>
		<WarningValue>0.001</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>DeepGreaterThanThresholdCheck</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\LogicalDisk(*)\Avg. Disk sec/Transfer">
	<Category>Disk</Category>
	<CounterSetName>LogicalDisk</CounterSetName>
	<CounterName>Avg. Disk sec/Transfer</CounterName>
	<DisplayOptions>
		<FormatDivider>0.001</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>0</Average>
		<Maxvalue>0</Maxvalue>
		<WarningValue>0</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>None</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\LogicalDisk(*)\Disk Transfers/sec">
	<Category>Disk</Category>
	<CounterSetName>LogicalDisk</CounterSetName>
	<CounterName>Disk Transfers/sec</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N1}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>0</Average>
		<Maxvalue>0</Maxvalue>
		<WarningValue>0</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>None</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\LogicalDisk(*)\Disk Bytes/sec">
	<Category>Disk</Category>
	<CounterSetName>LogicalDisk</CounterSetName>
	<CounterName>Disk Bytes/sec</CounterName>
	<DisplayOptions>
		<FormatDivider>1024</FormatDivider>
		<FormatString>{0:N0}KB</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>0</Average>
		<Maxvalue>0</Maxvalue>
		<WarningValue>0</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>None</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\LogicalDisk(*)\Avg. Disk Queue Length">
	<Category>Disk</Category>
	<CounterSetName>LogicalDisk</CounterSetName>
	<CounterName>Avg. Disk Queue Length</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N2}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>0</Average>
		<Maxvalue>0</Maxvalue>
		<WarningValue>0</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>None</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\LogicalDisk(*)\% Idle Time">
	<Category>Disk</Category>
	<CounterSetName>LogicalDisk</CounterSetName>
	<CounterName>% Idle Time</CounterName>
	<DisplayOptions>
		<FormatDivider>100</FormatDivider>
		<FormatString>{0:p1}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>0</Average>
		<Maxvalue>0</Maxvalue>
		<WarningValue>0</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>None</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\Memory\Available MBytes">
	<Category>Memory</Category>
	<CounterSetName>Memory</CounterSetName>
	<CounterName>Available MBytes</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}MB</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>1536</Average>
		<Maxvalue>512</Maxvalue>
		<WarningValue>1024</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>NormalLessThanThresholdCheck</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\Processor(*)\% Processor Time">
	<Category>Processor</Category>
	<CounterSetName>Processor</CounterSetName>
	<CounterName>% Processor Time</CounterName>
	<DisplayOptions>
		<FormatDivider>100</FormatDivider>
		<FormatString>{0:p1}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>75</Average>
		<Maxvalue>95</Maxvalue>
		<WarningValue>85</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>NormalGreaterThanThresholdCheck</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\Process(*)\% Processor Time">
	<Category>Process</Category>
	<CounterSetName>Process</CounterSetName>
	<CounterName>% Processor Time</CounterName>
	<DisplayOptions>
		<FormatDivider>100</FormatDivider>
		<FormatString>{0:p1}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\Process(*)\Working Set">
	<Category>Process</Category>
	<CounterSetName>Process</CounterSetName>
	<CounterName>Working Set</CounterName>
	<DisplayOptions>
		<FormatDivider>1048576</FormatDivider>
		<FormatString>{0:N0}MB</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\System\Processor Queue Length">
	<Category>Processor</Category>
	<CounterSetName>System</CounterSetName>
	<CounterName>Processor Queue Length</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average>2</Average>
		<Maxvalue>200</Maxvalue>
		<WarningValue>120</WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main>NormalGreaterThanThresholdCheck</Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchange ADAccess Domain Controllers(*)\LDAP Search Time">
	<Category>MSExchangeADAccess</Category>
	<CounterSetName>MSExchange ADAccess Domain Controllers</CounterSetName>
	<CounterName>LDAP Search Time</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchange ADAccess Domain Controllers(*)\LDAP Read Time">
	<Category>MSExchangeADAccess</Category>
	<CounterSetName>MSExchange ADAccess Domain Controllers</CounterSetName>
	<CounterName>LDAP Read Time</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\ASP.NET Apps v4.0.30319(*)\Requests Executing">
	<Category>ASPNET</Category>
	<CounterSetName>ASP.NET Apps v4.0.30319</CounterSetName>
	<CounterName>Requests Executing</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchangeIS Client Type(*)\RPC Average Latency">
	<Category>MSExchangeIS</Category>
	<CounterSetName>MSExchangeIS Client Type</CounterSetName>
	<CounterName>RPC Average Latency</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchangeIS Client Type(*)\RPC Operations/sec">
	<Category>MSExchangeIS</Category>
	<CounterSetName>MSExchangeIS Client Type</CounterSetName>
	<CounterName>RPC Operations/sec</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchangeIS Store(*)\Active mailboxes">
	<Category>MSExchangeIS</Category>
	<CounterSetName>MSExchangeIS Store</CounterSetName>
	<CounterName>Active mailboxes</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchange HttpProxy(*)\Average ClientAccess Server Processing Latency">
	<Category>HttpProxy</Category>
	<CounterSetName>MSExchange HttpProxy</CounterSetName>
	<CounterName>Average ClientAccess Server Processing Latency</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchange RpcClientAccess\RPC Averaged Latency">
	<Category>RpcClientAccess</Category>
	<CounterSetName>MSExchange RpcClientAccess</CounterSetName>
	<CounterName>RPC Averaged Latency</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N1}ms</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchange RpcClientAccess\Active User Count">
	<Category>RpcClientAccess</Category>
	<CounterSetName>MSExchange RpcClientAccess</CounterSetName>
	<CounterName>Active User Count</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
<Counter Name = "\MSExchange RpcClientAccess\RPC Requests">
	<Category>RpcClientAccess</Category>
	<CounterSetName>MSExchange RpcClientAccess</CounterSetName>
	<CounterName>RPC Requests</CounterName>
	<DisplayOptions>
		<FormatDivider>1</FormatDivider>
		<FormatString>{0:N0}</FormatString>
	</DisplayOptions>
	<Threshold>
		<Average></Average>
		<Maxvalue></Maxvalue>
		<WarningValue></WarningValue>
	</Threshold>
	<MonitorChecks>
		<Main></Main>
	</MonitorChecks>
</Counter>
</Counters>
"@

#"\\*\LogicalDisk(*)\Avg. Disk sec/Read","\\*\LogicalDisk(*)\Avg. Disk sec/Write","\\*\LogicalDisk(*)\Avg. Disk sec/Transfer","\\*\LogicalDisk(*)\Disk Transfers/sec","\\*\LogicalDisk(*)\Disk Bytes/sec","\\*\LogicalDisk(*)\Avg. Disk Queue Length","\\*\LogicalDisk(*)\% Idle Time","\\*\Processor(_Total)\% Processor Time","\\*\System\Processor Queue Length","\\*\System\Context Switches/sec","\\*\Memory\Available MBytes","\\*\Netlogon(*)\*","\\*\Processor Information(*)\% of Maximum Frequency"
#"\LogicalDisk(*)\Avg. Disk sec/Read","\LogicalDisk(*)\Avg. Disk sec/Write","\LogicalDisk(*)\Avg. Disk sec/Transfer","\LogicalDisk(*)\Disk Transfers/sec","\LogicalDisk(*)\Disk Bytes/sec","\LogicalDisk(*)\Avg. Disk Queue Length","\LogicalDisk(*)\% Idle Time","\Processor(_Total)\% Processor Time","\System\Processor Queue Length","\System\Context Switches/sec","\Memory\Available MBytes","\Netlogon(*)\*","\Processor Information(*)\% of Maximum Frequency"
Function Get-PerformanceDataFromFileLocal {
	[CmdletBinding()]
	[OutputType([System.Collections.Generic.List[PerformanceHealth.PerfFileDataInfo]])]
	param(
		[parameter(mandatory=$true)][string[]]$FullPath,
		[parameter(mandatory=$true)][string[]]$Counters,
		[parameter(mandatory=$true)][Int64]$MaxSamples,
		[parameter(mandatory=$true)][DateTime]$StartTime,
		[parameter(mandatory=$true)][DateTime]$EndTime
	)


	Write-Verbose ("[{0}]: Passed {1} files." -f [DateTime]::Now, $FullPath.Count)
	[System.Collections.Generic.List[PerformanceHealth.PerfFileDataInfo]]$aPerfFileDataInfo = New-Object System.Collections.Generic.List[PerformanceHealth.PerfFileDataInfo]
	if($FullPath.Count -gt 0)
	{
		
		foreach($file in $FullPath)
		{
			$loopStartTime = [System.DateTime]::Now
			$perfDataInfoObj = New-Object PerformanceHealth.PerfFileDataInfo
			$perfDataInfoObj.FileName = $file
			$importParams = @{
				Path = $file
				StartTime = $StartTime
				EndTime = $EndTime
				MaxSamples = $MaxSamples
				ErrorAction = "SilentlyContinue"
				Verbose = $false
			}


			if($Counters -ne $null -and $Counters.Count -gt 0)
			{
				$importParams.Add("Counter", $Counters)
			}


			Write-Verbose ("[{0}]: Importing counters from file. File Size: {1}MB. File Name: {2}." -f [DateTime]::Now, ((Get-Item $file).Length / 1024 / 1024), $file)
			#$importCounterSamples = (Import-Counter @importParams).CounterSamples
			$perfDataInfoObj.CounterSamples = (Import-Counter @importParams).CounterSamples
			Write-Verbose ("[{0}]: Finished Importing counters from file. File Name: {1}" -f [DateTime]::Now, $file)
			#$aCounterSamples.Add($importCounterSamples)
			$perfDataInfoObj.ReadingFileTime =  New-TimeSpan $($loopStartTime) $([System.DateTime]::Now)
			$aPerfFileDataInfo.Add($perfDataInfoObj)
		}

	}
	#This returns an Array that contains the results per file in their own array. The function after this needs to be able to pull out and review the data as needed. 
	return $aPerfFileDataInfo

}


Function Convert-PerformanceCounterSampleObjectToServerPerformanceObjectWithQuickAnalyze {
[CmdletBinding()]
[OutputType([System.Collections.Generic.List[System.Object]])]
param(
[Parameter(Mandatory=$true)][Array]$RawData,
[Parameter(Mandatory=$true)][xml]$XmlList,
[Parameter(Mandatory=$false)][string]$FileName,
[Parameter(Mandatory=$false)][timespan]$ReadTimeSpan
)
	Write-Verbose("Calling Convert-PerformanceCounterSampleObjectToServerPerformanceObjectWithQuickAnalyze")
	$measure_gData = Measure-Command { $gData = $RawData | Group-Object Path}
	Write-Verbose("Grouped Raw Data in {0} seconds" -f $measure_gData.TotalSeconds)
	Write-Verbose("There are {0} different paths detected" -f $gData.Count)

	Function Get-FullCounterNameObject
	{
		param(
			[Parameter(Mandatory=$true)][object]$PerformanceCounterSample 
		)

		$FullCounterSamplePath = $PerformanceCounterSample.Path 
		#\\adt-e2k13aio1\logicaldisk(harddiskvolume1)\avg. disk sec/read
		$iEndOfServerIndex = $FullCounterSamplePath.IndexOf("\",2) #\\adt-e2k13aio1 <> \logicaldisk(harddiskvolume1)\avg. disk sec/read
		$iStartOfCounterIndex = $FullCounterSamplePath.LastIndexOf("\") + 1#\\adt-e2k13aio1\logicaldisk(harddiskvolume1)\ <> avg. disk sec/read
		$iEndOfCounterObjectIndex = $FullCounterSamplePath.IndexOf("(")
		if($iEndOfCounterObjectIndex -eq -1){$iEndOfCounterObjectIndex = $FullCounterSamplePath.LastIndexOf("\")}
		$obj = New-Object PerformanceHealth.CounterNameObject
		$obj.ServerName = ($FullCounterSamplePath.Substring(2,($iEndOfServerIndex - 2)))
		$obj.ObjectName = ($FullCounterSamplePath.Substring($iEndOfServerIndex + 1, $iEndOfCounterObjectIndex - $iEndOfServerIndex - 1 ))
		$obj.CounterName = ($FullCounterSamplePath.Substring($FullCounterSamplePath.LastIndexOf("\") + 1))
		if(($FullCounterSamplePath.Contains("(")) -and ($FullCounterSamplePath.Contains("#")))
		{
				$instanceName = $FullCounterSamplePath.Substring($FullCounterSamplePath.IndexOf("(") + 1, ($FullCounterSamplePath.IndexOf(")") - $FullCounterSamplePath.IndexOf("(") - 1))
		}
		else
		{
			$instanceName = ($PerformanceCounterSample.InstanceName)
		}
		$obj.InstanceName = $instanceName
		$obj.FullName = ($FullCounterSamplePath)
		return $obj
	}


	Function Build-ServerPerformanceObject_CounterData {
	param(
		[Parameter(Mandatory=$true)][object]$CounterNameObject
	)
		[PerformanceHealth.CounterDataObject]$counterDataPerfObject = New-Object PerformanceHealth.CounterDataObject
		$counterDataPerfObject.FullName = $CounterNameObject.FullName 
		$counterDataPerfObject.ServerName = $CounterNameObject.ServerName 
		$counterDataPerfObject.ObjectName = $CounterNameObject.ObjectName
		$counterDataPerfObject.InstanceName = $CounterNameObject.InstanceName 
		$counterDataPerfObject.CounterName = $CounterNameObject.CounterName 
		$counterDataPerfObject.CounterCategory = [string]::Empty
		$counterDataPerfObject.DetectIssuesType = [string]::Empty
		$counterDataPerfObject.HealthReport = New-Object -TypeName PerformanceHealth.HealthReport 
		$counterDataPerfObject.Accuracy = New-Object -TypeName PerformanceHealth.AccuracyObject
		$counterDataPerfObject.DisplayOptions = New-Object -TypeName PerformanceHealth.DisplayOptionsObject
		$counterDataPerfObject.Threshold = New-Object PerformanceHealth.CounterThresholds
		$counterDataPerfObject.QuickSummaryStats = New-Object -TypeName PerformanceHealth.QuickSummaryStatsObject 
		#$tRawData = New-Object -TypeName PerformanceHealth.RawDataObject
		#[System.Collections.Generic.List[System.Object]]$trd = New-Object -TypeName System.Collections.Generic.List[System.Object]
		#$trd.Add($tRawData)
		#$counterDataPerfObject | Add-Member -Name RawData -MemberType NoteProperty -Value $trd
		return $counterDataPerfObject
	}

	Function Build-ServerPerformanceObject_Server {
	param(
		[Parameter(Mandatory=$true)][object]$CounterNameObject
	)

		[PerformanceHealth.ServerPerformanceObject]$serverPerfObject = New-Object -TypeName PerformanceHealth.ServerPerformanceObject
		$serverPerfObject.FileName = $CounterNameObject.FileName
		$serverPerfObject.ServerName = $CounterNameObject.ServerName
		$serverPerfObject.Accuracy = New-Object -TypeName PerformanceHealth.AccuracyObject 
		$serverPerfObject.HealthReport = New-Object -TypeName PerformanceHealth.HealthReport 
		$serverPerfObject.StartTime = [DateTime]::MinValue
		$serverPerfObject.EndTime = [DateTime]::MaxValue
		
		return $serverPerfObject
	}

	$tMasterObject = New-Object System.Collections.Generic.List[System.Object]

	foreach($gPath in $gData)
	{
		$counterNameObj = Get-FullCounterNameObject -PerformanceCounterSample $gPath.Group[0]
		$counterDataObj = Build-ServerPerformanceObject_CounterData -CounterNameObject $counterNameObj
		$counterDataObj.AllRawData = $gPath.Group
		$counterDataObj.CounterType = $counterDataObj.FirstSample.CounterType

		#Now we need to loop through the xml to add the counter data information 
		foreach($xmlCounter in $XmlList.Counters.Counter)
		{
			if($counterDataObj.ObjectName -like ("*" + $xmlCounter.CounterSetName) -and
				$counterDataObj.CounterName -eq $xmlCounter.CounterName
			)
			{
				$counterDataObj.DetectIssuesType = $xmlCounter.MonitorChecks.Main
				$counterDataObj.Threshold.MaxValue = $xmlCounter.Threshold.MaxValue
				$counterDataObj.Threshold.WarningValue = $xmlCounter.Threshold.WarningValue 
				$counterDataObj.Threshold.AverageValue = $xmlCounter.Threshold.Average
				$counterDataObj.CounterCategory = $xmlCounter.Category
				$counterDataObj.DisplayOptions.FormatDivider = $xmlCounter.DisplayOptions.FormatDivider
				$counterDataObj.DisplayOptions.FormatString = $xmlCounter.DisplayOptions.FormatString
				#If we find it, we shouldn't need to loop through any longer and we can break out of the XML loop 
				break; 
			}
		}

		#Now we need to quick Analyze the data sets while we are in here. 
		# $measured = $counterObj.RawData | Measure-Object -Property CookedValue -Maximum -Minimum -Average   ## Bill Long removed this, checking with him to verify why this change was made. 

		$min = [Int64]::MaxValue; 
		$max = [Int64]::MinValue; 
		foreach($sample in $counterDataObj.RawData)
		{
			if($sample.CookedValue -lt $min) {$min = $sample.CookedValue}
			if($sample.CookedValue -gt $max) {$max = $sample.CookedValue}
		}

		$counterDataObj.QuickSummaryStats.Min = $min
		$counterDataObj.QuickSummaryStats.Max = $max
		$counterDataObj.QuickSummaryStats.StartTime = $counterDataObj.FirstSample.TimeStamp
		$counterDataObj.QuickSummaryStats.EndTime = $counterDataObj.LastSample.TimeStamp
		$counterDataObj.QuickSummaryStats.Duration = New-TimeSpan $($counterDataObj.QuickSummaryStats.StartTime) $($counterDataObj.QuickSummaryStats.EndTime)

		#Calculate Averages 
		#Average calculation for Average counters taken from these references:
		#https://msdn.microsoft.com/en-us/library/ms804010.aspx
		#https://blogs.msdn.microsoft.com/ntdebugging/2013/09/30/performance-monitor-averages-the-right-way-and-the-wrong-way/
		
		if($counterDataObj.CounterType -like "AverageTimer*")
		{
			$numTicksDiff = $counterDataObj.LastSample.RawValue - $counterDataObj.FirstSample.RawValue
			$frequency = $counterDataObj.LastSample.TimeBase
			$numOpsDif = $counterDataObj.LastSample.SecondValue - $counterDataObj.FirstSample.SecondValue 
			if($frequency -ne 0 -and $numTicksDiff -ne 0 -and $numOpsDif -ne 0)
			{
				$counterDataObj.QuickSummaryStats.Avg = (($numTicksDiff / $frequency) / $numOpsDif)
			}
		}
		else
		{
			$counterDataObj.QuickSummaryStats.Avg = ($counterDataObj.RawData | Measure-Object -Property CookedValue -Average).Average
		}
		
		$tMasterObject.Add($counterDataObj)
	}

	#Now we need to group for the server object (if we have multiple) and build the server object and return the data
	$MasterObject = New-Object System.Collections.Generic.List[System.Object]
	$serversGroup = $tMasterObject | Group-Object ServerName 
	foreach($svr in $serversGroup)
	{
		$cdo = Get-FullCounterNameObject -PerformanceCounterSample ($svr.Group[0].RawData | Select-Object -First 1)
		$svrData = Build-ServerPerformanceObject_Server -CounterNameObject $cdo
		$svrData.CounterData = $svr.Group 
		$svrData.FileName = $FileName
		$svrData.ReadTime = $ReadTimeSpan
		$svrData.StartTime = ($svr.Group[0].RawData | Sort-Object TimeStamp | Select-Object -First 1).TimeStamp
		$svrData.EndTime = ($svr.Group[0].RawData | Sort-Object TimeStamp | Select-Object -Last 1).TimeStamp
		$MasterObject.Add($svrData)
	}

	return $MasterObject
}


Function Output-QuickSummaryDetails {
[CmdletBinding()]
param(
[Parameter(Mandatory=$true)][Object]$ServerObject
)
	Write-Verbose("[{0}] : Calling Output-QuickSummaryDetails" -f [DateTime]::Now)
	
	$Script:displayString = [string]::Empty
	$strLength_detail = 48
	$strLength_columnWidth = 12
	
	Function Add-Line {
	param(
		[Parameter(Mandatory=$true)][string]$New_line
	)
		$Script:displayString += $New_line + "`r`n"
	}
	$Script:measure_display = Measure-Command{
	Add-Line("Exchange Perfmon Log Summary")
	Add-Line("=============================")
	Add-Line("{0,-18} : {1}" -f "File", $ServerObject.FileName)
	Add-Line("{0,-18} : {1}" -f "Server", $ServerObject.ServerName )
	Add-Line("{0,-18} : {1}" -f "Start Time", $ServerObject.StartTime)
	Add-Line("{0,-18} : {1}" -f "End Time",$ServerObject.EndTime)
	Add-Line("{0,-18} : {1}" -f "Duration",(New-TimeSpan $($ServerObject.StartTime) $($ServerObject.EndTime)).ToString())
	#Setup the output file 
	
	$outFile = $ServerObject.FileName + "_Quick_Summary.txt"

	$groupCounterCategory = $ServerObject.CounterData | Group-Object CounterCategory | ?{$_.Name -ne "" -and $_.Name -ne "Process"} | Sort-Object Name
	$groupCounterCategoryProcess = $ServerObject.CounterData | Group-Object CounterCategory | ?{$_.Name -eq "Process"}
	$groupCounterCategoryN = $ServerObject.CounterData | Group-Object CounterCategory | ?{$_.Name -eq ""}

	foreach($gCategory in $groupCounterCategory)
	{
		Add-Line(" ")
		Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f $gcategory.Name, "Min","Max","Avg")
		Add-Line("==========================================================================================")
		#because these are all based off the sum category that could contain different Counter Object Names, we are going to group by that first then the actual counter
		$gObjectCounter = $gCategory.Group | Group-Object ObjectName 
		foreach($objCounter in $gObjectCounter)
		{
			$gCounterNameObject = $objCounter.Group | Group-Object Countername 
			
			foreach($counterGroup in $gCounterNameObject)
			{
				if($counterGroup.Group[0].InstanceName -eq "")
				{
					
					$fs = $counterGroup.Group[0].DisplayOptions.FormatString
					$fd = $counterGroup.Group[0].DisplayOptions.FormatDivider 
					Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f ("\" + $counterGroup.Group[0].ObjectName + "\" + $counterGroup.Group[0].CounterName),
						($fs -f ($counterGroup.Group[0].QuickSummaryStats.Min / $fd)),
						($fs -f ($counterGroup.Group[0].QuickSummaryStats.Max / $fd)),
						($fs -f ($counterGroup.Group[0].QuickSummaryStats.Avg / $fd)))
				}
				else
				{
					Add-Line("{0,-$($strLength_detail+2)}" -f ("\" + $counterGroup.Group[0].ObjectName + "(*)\" + $counterGroup.Group[0].CounterName))
					foreach($instanceObj in $counterGroup.Group)
					{
						$fs = $instanceObj.DisplayOptions.FormatString
						$fd = $instanceObj.DisplayOptions.FormatDivider
						Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f $instanceObj.InstanceName,
							($fs -f ($instanceObj.QuickSummaryStats.Min / $fd)),
							($fs -f ($instanceObj.QuickSummaryStats.Max / $fd)),
							($fs -f ($instanceObj.QuickSummaryStats.Avg / $fd))
						)
					}
				}

			}
		}

	}

	foreach($gCategory in $groupCounterCategoryProcess)
	{
		$gCounterNameObject = $gCategory.Group | Group-Object CounterName
		Add-Line(" ")
		Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f $gcategory.Name, "Min","Max","Avg")
		Add-Line("==========================================================================================")
		
		foreach($counterGroup in $gCounterNameObject)
		{
			Add-Line("{0,-$($strLength_detail+2)}" -f ("\" + $counterGroup.Group[0].ObjectName + "(*)\" + $counterGroup.Group[0].CounterName))
			$TopN = $counterGroup.Group | ?{$_.InstanceName -ne "_total" -and $_.InstanceName -ne "idle"} | Select * -ExpandProperty QuickSummaryStats | Sort-Object Avg -Descending | Select-Object -First $ShowNProcesses 
			foreach($process in $TopN)
			{
				$fs = $process.DisplayOptions.FormatString
				$fd = $process.DisplayOptions.FormatDivider
				Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f $process.InstanceName,
					($fs -f ($process.QuickSummaryStats.Min / $fd)),
					($fs -f ($process.QuickSummaryStats.Max / $fd)),
					($fs -f ($process.QuickSummaryStats.Avg / $fd))
					)
			}
		}

	}

	
	foreach($gCategory in $groupCounterCategoryN)
	{
		$gObjectCounter = $gCategory.Group | Group-Object ObjectName 
		foreach($objCounter in $gObjectCounter)
		{
			$gCounterNameObject = $objCounter.Group | Group-Object CounterName
			foreach($counterGroup in $gCounterNameObject)
			{
				if($counterGroup.Group[0].InstanceName -eq "")
				{
					
					Add-Line(" ")
					Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f ($counterGroup.Group[0].ObjectName + "-" + $counterGroup.Group[0].CounterName), "Min", "Max", "Avg")
					Add-Line("==========================================================================================")
					Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f ("\" + $counterGroup.Group[0].ObjectName + "\" + $counterGroup.Group[0].CounterName),
						$counterGroup.Group[0].QuickSummaryStats.Min,
						$counterGroup.Group[0].QuickSummaryStats.Max,
						$counterGroup.Group[0].QuickSummaryStats.Avg)
				}
				else
				{
					Add-Line(" ")
					Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f ($counterGroup.Group[0].ObjectName + "-" + $counterGroup.Group[0].CounterName), "Min", "Max", "Avg")
					Add-Line("==========================================================================================")
					Add-Line("{0,-$strLength_detail} {1,$strLength_columnWidth} {2,$strLength_columnWidth} {3,$strLength_columnWidth}" -f ($counterGroup.Group[0].InstanceName),
						$counterGroup.Group[0].QuickSummaryStats.Min,
						$counterGroup.Group[0].QuickSummaryStats.Max,
						$counterGroup.Group[0].QuickSummaryStats.Avg)
				}
			}
		}
	}

	Add-Line(" ")
	Add-Line(" ")
	Add-Line("Analysis Stats")
	Add-Line("================")
	Add-Line("{0,-24} : {1}" -f "Report Generated by", "ExPerfAnalyzer.ps1 " + $ScriptVersion)
	Add-Line("{0,-24} : {1}" -f "Written by", "Matthew Huynh (mahuynh@microsoft.com) & David Paulson (dpaul@microsoft.com)")
	Add-Line("{0,-24} : {1}" -f "Contributor", "Bill Long")
	$currentTime = [dateTime]::Now
	Add-Line("{0,-24} : {1}" -f "Generated On",($currentTime.ToShortDateString() + " " + $currentTime.ToShortTimeString()))
	$totalCounterProcessed = $ServerObject.CounterData.Count
	$totalSamples = $ServerObject.CounterData.RawData.Count
	Add-Line("{0,-24} : {1:N0}" -f "Total Counters Processed", $totalCounterProcessed)
	Add-Line("{0,-24} : {1:N0}" -f "Total Samples", $totalSamples)
	$pTime = (New-TimeSpan $($script:processStartTime) $([datetime]::Now))
	Add-Line("{0,-24} : {1:N1}s" -f "Total File Read Time", ($ServerObject.ReadTime.TotalSeconds))
	Add-Line("{0,-24} : {1:N1}s" -f "Total Processing Time", $pTime.TotalSeconds)
	Add-Line("{0,-24} : {1:N5}s" -f "Samples Processed/sec", ([double]$totalSamples / $pTime.TotalSeconds))
	Add-Line("{0,-24} : {1:N5}s" -f "Proc. Time Per Sample", ($pTime.TotalSeconds /[double]$totalSamples))


	}
	$Script:displayString | Out-File -FilePath $outFile -Force
	&$outFile
}




Function Get-CountersFromXml {
param(
[Parameter(Mandatory=$true)][xml]$xmlCounters,
[Parameter(Mandatory=$false)][bool]$IncludeWildForServers = $false
)
	$aCounters = New-Object System.Collections.Generic.List[System.Object]
	if($IncludeWildForServers)
	{
		foreach($counter in $xmlCounters.Counters.Counter)
		{
			$aCounters.Add("\\*" + $counter.Name)
		}
	}
	else
	{
		foreach($counter in $xmlCounters.Counters.Counter)
		{
			$aCounters.Add($counter.Name)
		}
	}

	return $aCounters
}

Function Main {

	$script:processStartTime = [System.DateTime]::Now

	#determine the logic we want out of the script 
	Switch($PSCmdlet.ParameterSetName)
	{
		"FileDirectory"
		{
			Write-Verbose("File Directory Option detected")
			if(-not (Test-Path $PerfmonFileDirectory))
			{
				Write-Error ("Path '{0}' is invalid or cannot be accessed." -f $PerfmonFileDirectory)
				exit
			}
			
			$AllFiles = (Get-ChildItem $PerfmonFileDirectory | ?{$_.Name.EndsWith(".blg")}).VersionInfo.FileName 
			
			
			switch($AllFiles.Count)
			{
				0
					{
						Write-Error ("Cannot find any .blg files in the path '{0}'." -f $PerfmonFileDirectory)
						exit
					}
				#Need to use different logic if only 1 file was detected 
				1
					{
						Write-Verbose("We have detected {0} .blg files in directory {1}" -f ($AllFiles.count), $PerfmonFileDirectory)
						$rawLocalData = Get-PerformanceDataFromFileLocal -FullPath $AllFiles -Counters (Get-CountersFromXml -xmlCounters $xmlCountersToAnalyze -IncludeWildForServers $true) -MaxSamples $MaxSamples -StartTime $StartTime -EndTime $EndTime
						$mainObject = Convert-PerformanceCounterSampleObjectToServerPerformanceObject -RawData $rawLocalData 
						$mainObject = Add-CountersToAnalyzeToObject -XmlList $xmlCountersToAnalyze -mainObject $mainObject
						$mainObject = Analyze-DataOfObject -mainObject $mainObject
						$displayResults = Output-QuickSummaryDetails -ServerObject $mainObject 
						$displayResults
						break
					}
				#else there are more files 
				default
					{
						Write-Verbose("We have detected {0} .blg files in directory {1}" -f ($AllFiles.count), $PerfmonFileDirectory)
						break
					}
			}

			break;
		}

		"SingleFile"
		{
			if (-not (Test-Path $PerfmonFile))
			{
				Write-Error ("File {0} does not exist or cannot be accessed." -f $PerfmonFile)
				exit
			}
            if (-not $PerfmonFile.EndsWith(".blg"))
			{
				Write-Error ("File {0} does not have a .blg file extension." -f $PerfmonFile)
				exit
			}
			Write-Host ("Single file mode: processing '{0}'" -f $PerfmonFile)
			$script:perffromlocalfile = Measure-Command{ $rawLocalData = Get-PerformanceDataFromFileLocal -FullPath $PerfmonFile -Counters (Get-CountersFromXml -xmlCounters $xmlCountersToAnalyze -IncludeWildForServers $true) -MaxSamples $MaxSamples -StartTime $StartTime -EndTime $EndTime}
			$script:convertTotal = Measure-Command{ $mainObject = Convert-PerformanceCounterSampleObjectToServerPerformanceObjectWithQuickAnalyze -RawData $rawLocalData.CounterSamples -XmlList $xmlCountersToAnalyze  -FileName $rawLocalData.FileName -ReadTimeSpan $rawLocalData.ReadingFileTime}
			Output-QuickSummaryDetails -ServerObject $mainObject 
			break;
		}

        "RegisterHandler"
        {
            # register this script as a handler for perfmon BLG files
            New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null
            $scriptPath = $MyInvocation.ScriptName
            $defaultCommand = 'powershell.exe -command "& ' + "'" + $scriptPath + "'" + " '%1'" + '"'
            Write-Debug $defaultCommand
            $newRegKey = New-Item HKCR:\Diagnostic.Perfmon.Document\shell\ExPerfAnalyzer\command -Force -Value $defaultCommand
            $string = "ExPerfAnalyzer {0}registered itself as a shell handler for perfmon .blg files."
            if ($newRegKey -ne $null) {
                Write-Host -ForegroundColor Green ($string -f "")
            } else {
                Write-Error ($string -f "failed to ")
            }
            break;
        }

	}

}


Main