# HealthChecker
This script is the Exchange Server Health Checker script that helps detect common configuration issues that are known to cause performance issues within an Exchange Environment. You can run this script against every Exchange Server that is in your environment and it will clearly indicate what you should be addressing. 

#How To Run
This script MUST be run as Administrator in Exchange Management Shell on an Exchange Server. You can provide no parameters and the script will just run against the local server and provide the detail output of the configuration of the server. 

Within the version 2.18 or greater, you are now able to generate a HTML report from the XML files that are created from the initial collection of the Health Checker Script. For this to work, you need to have run the Health Checker Script against all the servers that you would like in the report and have all the XML outputs in a single directory. After this, you can run the Health Checker script again with using the parameter -BuildHtmlServersReport and we will generate a nice HTML report that will combined all the information into a single view. 

Examples:

This cmdlet with run Health Checker Script by default and run against the local server.

*.\HealthChecker.ps1*

This cmdlet will run the Health Checker Script against the specified server.

*.\HealthChecker.ps1 -Server EXCH1*

This cmdlet will build the HTML report for all the XML files located in the same location as the Health Checker Script. 

*.\HealthChecker.ps1 -BuildHtmlServersReport*

This cmdlet will build the HTML report for all the XML files located in the directory specified in the XMLDirectoryPath Parameter. 

*.\HealthChecker.ps1 -BuildHtmlServersReport -XMLDirectoryPath C:\Location*

This cmdlet will run the Health Checker Load Balancing Report for all the Exchange 2013/2016 CAS (Front End connections only) in the Organization. 

*.\HealthChecker.ps1 -LoadBalancingReport*

This cmdlet will run the Health Checker Load Balancing Report for these Servers EXCH1, EXCH2, and EXCH3

*.\HealthChecker.ps1 -LoadBalancingReport -CasServerList EXCH1,EXCH2,EXCH3*

This cmdlet will run the Health Checker Load Balancing Report for the Exchange 2013/2016 CAS (Front End connections only) in the site SiteA.

*.\HealthChecker.ps1 -LoadBalancingReport -SiteName SiteA

This cmdlet will run the Health Checker Mailbox Report against the Server EXCH1

*.\HealthChecker.ps1 -MailboxReport -Server EXCH1 


# Parameters 

Server - The server that you would like to run the Health Checker Script against. Parameter not valid with -BuildHTMLServersReport or LoadBalancingReport. Default is the localhost. 

OutputFilePath - The output location for the log files that the script produces. Default is the current directory. 

MailboxReport - Produces the Mailbox Report for the server provided. 

LoadBalancingReport - Runs the Load Balancing Report for the Script 

CasServerList - Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against. 

SiteName - Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against in the site. 

XMLDirectoryPath - Used in combination with the location of the XML files for which you want to be included in the report. Default location is the current directory. 

BuildHtmlServersReport - Switch to enable the script to build the HTML report for all the servers XML results in the XMLDirectoryPath location. 

HtmlReportFile - Name of the HTML output file from the BuildHtmlServersReport. Default is ExchangeAllServersReport.html