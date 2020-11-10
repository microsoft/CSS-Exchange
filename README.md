# Download 
To download this script, download the latest version [here](https://github.com/dpaulson45/HealthChecker/releases)

# HealthChecker
The Exchange Server Health Checker script helps detect common configuration issues that are known to cause performance issues and other long running issues that are caused by a simple configuration change within an Exchange Environment. It also helps collect useful information of your server to help speed up the process of common information gathering of your server. 

# How To Run
This script **must** be run as Administrator in Exchange Management Shell on an Exchange Server. You can provide no parameters and the script will just run against the local server and provide the detail output of the configuration of the server. 

Examples:

This cmdlet with run Health Checker Script by default and run against the local server.

```
.\HealthChecker.ps1
```

This cmdlet will run the Health Checker Script against the specified server.

```
.\HealthChecker.ps1 -Server EXCH1
```
This cmdlet will build the HTML report for all the XML files located in the same location as the Health Checker Script. 

```
.\HealthChecker.ps1 -BuildHtmlServersReport
```

This cmdlet will build the HTML report for all the XML files located in the directory specified in the XMLDirectoryPath Parameter. 

```
.\HealthChecker.ps1 -BuildHtmlServersReport -XMLDirectoryPath C:\Location
```

This cmdlet will run the Health Checker Load Balancing Report for all the Exchange 2013/2016 CAS (Front End connections only) in the Organization. 

```
.\HealthChecker.ps1 -LoadBalancingReport
```

This cmdlet will run the Health Checker Load Balancing Report for these Servers EXCH1, EXCH2, and EXCH3

```
.\HealthChecker.ps1 -LoadBalancingReport -CasServerList EXCH1,EXCH2,EXCH3
```

This cmdlet will run the Health Checker Load Balancing Report for the Exchange 2013/2016 CAS (Front End connections only) in the site SiteA.

```
.\HealthChecker.ps1 -LoadBalancingReport -SiteName SiteA
```

This cmdlet will run the Health Checker Mailbox Report against the Server EXCH1

```
.\HealthChecker.ps1 -MailboxReport -Server EXCH1 
```

# Parameters

Parameter | Description
----------|------------
Server | The server that you would like to run the Health Checker Script against. Parameter not valid with -BuildHTMLServersReport or LoadBalancingReport. Default is the localhost.
OutputFilePath | The output location for the log files that the script produces. Default is the current directory.
MailboxReport | Produces the Mailbox Report for the server provided.
LoadBalancingReport | Runs the Load Balancing Report for the Script 
CasServerList | Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against. 
SiteName | Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against in the site. 
XMLDirectoryPath | Used in combination with BuildHtmlServersReport switch for the location of the HealthChecker XML files for servers which you want to be included in the report. Default location is the current directory.
BuildHtmlServersReport | Switch to enable the script to build the HTML report for all the servers XML results in the XMLDirectoryPath location. 
HtmlReportFile | Name of the HTML output file from the BuildHtmlServersReport. Default is ExchangeAllServersReport.html
DCCoreRatio | Gathers the Exchange to DC/GC Core ratio and displays the results in the current site that the script is running in.