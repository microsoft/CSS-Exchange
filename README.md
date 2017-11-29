# ExchangeLogCollector
This script is intended to collect the Exchange default logging data from the server in a consistent manner to make it easier to troubleshoot an issue when large amounts of data is needed to be collected. You can specify what logs you want to collect by the switches that are available, then the script has logic built in to determine how to collect the data. 

# How to Run 
The script MUST be run as Administrator in Exchange Management Shell on an Exchange Server that you would like to collect the data from. This script is mainly built around Exchange 2013 and greater, but it should be able to collect data in Exchange 2010 still just fine. This script is great to collect a set of data for an issue without needing to collect a lot of data that isn’t needed for an issue. 

Within the version 2.1 or greater, we are now able to do remote collections if the target machine is on Windows Server 2012 or greater to use Invoke-Command. If Invoke-Command works remotely, then we will allow you to attempt to collect the data. You can still utilize the script to collect locally as it used to be able to, if the target OS doesn’t allow this. 

Prior to collecting the data, we check to make sure that there is at least 15GB of free space at the location of where we are trying to save the data of the target server. You have the option to use the Disk Override switch but use at your own discretion. 

Examples: 

This cmdlet will collect all default logs of the local Exchange Server and store them in the default location of “C:\MS_Logs_Collection” 

*.\ExchangeLogCollector.ps1 -AllPossibleLogs*

This cmdlet will collect all relevant data regarding database failovers from server EXCH1 and EXCH2 and store them at Z:\Data\Logs. Note: at the end of the collection, the script will copy over the data to the local host execution server to make data collection even easier. 

*.\ExchangeLogCollector.ps1 -DatabaseFailoverIssue -Servers EXCH1,EXCH2 -FilePath Z:\Data\Logs*

This cmdlet will collect all relevant data regarding IIS Logs (within the last 3 days by default) and all RPC type logs from the servers EXCH1 and EXCH2 and store them at the default location of “C:\MS_Logs_Collection”

*.\ExchangeLogCollector.ps1 -Servers EXCH1,EXCH2 -IISLogs -RPCLogs*
