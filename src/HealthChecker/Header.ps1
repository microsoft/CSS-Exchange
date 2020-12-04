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