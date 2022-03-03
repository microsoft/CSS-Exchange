# About ExPerfWiz
ExPerfWiz is a PowerShell based script to help automate the collection of performance data on Exchange 2013, 2016 and 2019 servers.  Supported operating systems are Windows 2012, 2012 R2, 2016 and 2019 Core and Standard.

# Initial Run
Run .\ExPerfWiz.ps1 from an elevated shell.

* You will be prompted to setup a default collector on the current server.
* Selecting Y will configure but not start a default collector on the current server.
* Selecting N will return to a prompt without creating a collector.

Once a prompt is returned all of the ExPerfWiz functions will now be available to run.

# Common Usage
`New-Experfwiz -folderpath C:\perfwiz -startoncreate`

# How to use
The following functions are provided by ExPerfWiz to manage data collection.

### `Get-ExPerfwiz`
Gets ExPerfwiz data collector sets

Switch | Description|Default
-------|-------|-------
Name|Name of the Data Collector set|Exchange_Perfwiz
Server|Name of the Server |Local Machine
ShowLog|Displays the ExperfWiz Log file|NA


### `New-ExPerfwiz`
Creates an ExPerfwiz data collector set
Will overwrite any existing sets with the same name

Switch | Description|Default
-------|-------|-------
Circular| Enabled or Disable circular logging|Disabled
Duration| How long should the performance data be collected|08:00:00
FolderPath|Output Path for performance logs|NA
Interval|How often the performance data should be collected.|5s
MaxSize|Maximum size of the perfmon log in MegaBytes (256-4096)|1024Mb
Name|The name of the data collector set|Exchange_Perfwiz
Server|Name of the server where the perfmon collector should be created|Local Machine
StartOnCreate|Starts the counter set as soon as it is created|False
StartTime|Daily time to start perfmon counter|NA
Template| XML perfmon template file that should be loaded to create the data collector set.|Exch_13_16_19_Full.xml
Threads|Includes threads in the counter set.|False

### `Set-ExPerfwiz`
Modifies the configuration of an existing data collector set.

Switch | Description|Default
-------|-------|-------
Duration| How long should the performance data be collected|08:00:00
Interval|How often the performance data should be collected.|5s
MaxSize|Maximum size of the perfmon log in MegaBytes (256-4096)|1024Mb
Name|The name of the data collector set|Exchange_Perfwiz
Server|Name of the server where the perfmon collector should be created|Local Machine
StartTime|Daily time to start perfmon counter|NA
Quiet|Suppress output|False


### `Remove-ExPerfwiz`
Removes an ExPerfwiz data collector set

Switch | Description|Default
-------|-------|-------
Name|Name of the Perfmon Collector set|Exchange_Perfwiz
Server|Name of the server to remove the collector set from|Local Machine

### `Start-ExPerfwiz`
Starts an ExPerfwiz data collector set

Switch | Description|Default
-------|-------|-------
Name|The Name of the Data Collector set to start|Exchange_Perfwiz
Server|Name of the remote server to start the data collector set on.|Local Machine

### `Stop-ExPerfwiz`
Stops an ExPerfwiz data collector set

Switch | Description|Default
-------|-------|-------
Name|Name of the data collector set to stop.|Exchange_Perfwiz
Server|Name of the server to stop the collector set on.|Local Machine

# Example Usage

### Default usage for data gathering

  `New-ExPerfwiz -FolderPath C:\experfwiz -StartOnCreate`

### Stop Data Collection

  `Stop-ExPerfwiz`

### Collect data from another server

  `New-ExPerfwiz -FolderPath C:\experfwiz -server RemoteExchServer`

### Collect data from multiple servers

`Get-ExchangeServer | Foreach {New-Experfwiz -folderpath C:\experfwiz -startoncreate -Server $_.name}`

# Important Notes
* The default duration is 8 hours to save on disk space meaning that the data collection will stop after 8 hours.
* Using -Threads should only be done if needed to troubleshoot the issue.  It will SIGNIFICANTLY increase the size of the resulting perfmon files.
* Do not stop the log gathering thru the Perfmon GUI that can result in an unreadable log file.  Always stop the data gathering with Stop-Experfwiz.