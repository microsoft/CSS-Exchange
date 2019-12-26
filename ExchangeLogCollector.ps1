<#
.NOTES
    Name: ExchangeLogCollector.ps1
    Author: David Paulson
    Requires: Powershell on an Exchange 2010+ Server with Administrator rights

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
    Collects the requested logs off the Exchange server based off the switches that are used.
.DESCRIPTION
    Collects the requested logs off the Exchange server based off the switches that are used.
.PARAMETER FilePath
    The Location of where you would like the data to be copied over to 
.PARAMETER Servers
    An array of servers that you would like to collect data from.
.PARAMETER EWSLogs
    Will collect the EWS logs from the Exchange Server 
.PARAMETER IISLogs 
    Will Collect the IIS Logs from the Exchange Server 
.PARAMETER DailyPerformanceLogs
    Used to collect Exchange 2013+ Daily Performance Logs 
.PARAMETER ManagedAvailability 
    Used to collect managed Availability Logs from the Exchange 2013+ Server
.PARAMETER Experfwiz 
    Used to collect Experfwiz data from the server 
.PARAMETER RPCLogs
    Used to collect the PRC Logs from the server 
.PARAMETER EASLogs
    Used to collect the Exchange Active Sync Proxy Logs 
.PARAMETER ECPLogs
    Used to collect the ECP Logs from the Exchange server 
.PARAMETER AutoDLogs
    Used to Collect the AutoD Logs from the server 
.PARAMETER OWALogs
    Used to collect the OWA Logs from the server 
.PARAMETER ADDriverLogs
    Used to collect the AD Driver Logs from the server 
.PARAMETER SearchLogs
    Used to collect the Search Logs from the server 
.PARAMETER HighAvailabilityLogs
    Used to collect the High Availability Information from the server 
.PARAMETER MapiLogs
    Used to collect the Mapi Logs from the server 
.PARAMETER MessageTrackingLogs
    Used to collect the Message Tracking Logs from the server 
.PARAMETER HubProtocolLogs
    Used to collect the Hub Protocol Logs from the server
.PARAMETER HubConnectivityLogs
    Used to collect the Hub Connectivity Logs from the server 
.PARAMETER FrontEndConnectivityLogs
    Used to collect the Front End Connectivity Logs from the server 
.PARAMETER FrontEndProtocolLogs
    Used to collect the Front End Protocol Logs from the server 
.PARAMETER MailboxConnectivityLogs
    Used to collect the Mailbox Connectivity Logs from the server 
.PARAMETER MailboxProtocolLogs
    Used to collect the Mailbox Protocol Logs from the server 
.PARAMETER QueueInformationThisServer
    Used to collect the Queue Information from this server 
.PARAMETER ReceiveConnectors
    Used to collect the Receive Connector information from this server 
.PARAMETER SendConnectors
    Used to collect the Send connector information from the Org 
.PARAMETER DAGInformation
    Used to collect the DAG Information for this DAG
.PARAMETER GetVdirs
    Used to collect the Virtual Directories of the environment 
.PARAMETER OrganizationConfig
    Used to collect the Organization Configuration from the environment. 
.PARAMETER TransportConfig
    Used to collect the Transport Configuration from this Exchange Server 
.PARAMETER DefaultTransportLogging
    Used to Get all the default logging that is enabled on the Exchange Server for Transport Information 
.PARAMETER Exmon 
    Used to Collect the Exmon Information 
.PARAMETER ServerInfo
    Used to collect the general Server information from the server 
.PARAMETER ExchangeServerInfo 
    Used to collect Exchange Server data (Get-ExchangeServer, Get-MailboxServer...). Enabled whenever ServerInfo is used as well.
.PARAMETER PopLogs
    Used to collect the POP protocol logs
.PARAMETER ImapLogs 
    Used to collect the IMAP protocol logs
.PARAMETER MSInfo 
    Old switch that was used for collecting the general Server information 
.PARAMETER CollectAllLogsBasedOnDaysWorth
    Used to collect some of the default logging based off Days Worth vs the whole directory 
.PARAMETER AppSysLogs
    Used to collect the Application and System Logs. Default is set to true
.PARAMETER AllPossibleLogs
    Switch to enable all default logging enabled on the Exchange server. 
.PARAMETER SkipEndCopyOver
    Boolean to prevent the copy over after a remote collection.
.PARAMETER DaysWorth
    To determine how far back we would like to collect data from 
.PARAMETER ScriptDebug
    To enable Debug Logging for the script to determine what might be wrong with the script 
.PARAMETER DatabaseFailoverIssue
    To enable the common switches to assist with determine the cause of database failover issues 
.PARAMETER PerformanceIssues
    To enable the common switches for data collection to assist with determing the cause of a Performance issue. 
.PARAMETER PerformanceMailflowIssues
    To enable the common switches for data collection to assist with determine the cause of a Mailflow Performance Type issue. 
.PARAMETER ExperfwizLogmanName
    To be able to set the Experfwiz Logman Name that we would be looking for. By Default "Exchange_Perfwiz"
.PARAMETER ExmonLogmanName
    To be able to set the Exmon Logman Name that we would be looking for. By Default "Exmon_Trace"
.PARAMETER AcceptEULA
    Switch used to bypass the disclaimer confirmation 

#>

#Parameters 
[CmdletBinding()]
Param (

[string]$FilePath = "C:\MS_Logs_Collection",
[Array]$Servers,
[switch]$EWSLogs,
[switch]$IISLogs,
[switch]$DailyPerformanceLogs,
[switch]$ManagedAvailability,
[switch]$Experfwiz,
[switch]$RPCLogs,
[switch]$EASLogs,
[switch]$ECPLogs,
[switch]$AutoDLogs,
[switch]$OWALogs,
[switch]$ADDriverLogs,
[switch]$SearchLogs,
[switch]$HighAvailabilityLogs,
[switch]$MapiLogs,
[switch]$MessageTrackingLogs,
[switch]$HubProtocolLogs,
[switch]$HubConnectivityLogs,
[switch]$FrontEndConnectivityLogs,
[switch]$FrontEndProtocolLogs,
[switch]$MailboxConnectivityLogs,
[switch]$MailboxProtocolLogs,
[switch]$QueueInformationThisServer,
[switch]$ReceiveConnectors,
[switch]$SendConnectors,
[switch]$DAGInformation,
[switch]$GetVdirs,
[switch]$OrganizationConfig,
[switch]$TransportConfig,
[switch]$DefaultTransportLogging,
[switch]$Exmon,
[switch]$ServerInfo,
[switch]$ExchangeServerInfo,
[switch]$PopLogs,
[switch]$ImapLogs,
[switch]$CollectAllLogsBasedOnDaysWorth = $false, 
[switch]$AppSysLogs = $true,
[switch]$AllPossibleLogs,
[bool]$SkipEndCopyOver,
[int]$DaysWorth = 3,
[switch]$DatabaseFailoverIssue,
[switch]$PerformanceIssues,
[switch]$PerformanceMailflowIssues,
[string]$ExperfwizLogmanName = "Exchange_Perfwiz",
[string]$ExmonLogmanName = "Exmon_Trace",
[switch]$AcceptEULA,
[switch]$ScriptDebug

)

$scriptVersion = "2.12"

###############################################
#                                             #
#              Local Functions                #
#                                             #
###############################################

#disclaimer 
Function Write-Disclaimer {
$display = @"

    Exchange Log Collector v{0}

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
    BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    -This script will copy over data based off the switches provied. 
    -We will check for at least {1} GB of free space at the local target directory BEFORE 
        attempting to do the remote execution. It will continue to check to make sure that we have 
        at least {2} GB of free space throughout the data collection. If some data is determined 
        that if we were to copy it over it would place us over that threshold, we will not copy that
        data set over. The script will continue to run while still constantly check the free space
        available before doing a copy action. 
    -Please run this script at your own risk. 

"@ -f $scriptVersion, ($Script:StandardFreeSpaceInGBCheckSize = 10), $Script:StandardFreeSpaceInGBCheckSize

    Clear-Host
    Write-ScriptHost -WriteString $display -ShowServer $false

    if(-not($AcceptEULA))
    {
        Enter-YesNoLoopAction -Question "Do you wish to continue? " -YesAction {} -NoAction {exit}
    }

}

Function Write-FeedBack {
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host "Looks like the script is done. If you ran into any issues or have additional feedback, please feel free to reach out ExToolsFeedback@microsoft.com."
}

#Template Master https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Enter-YesNoLoopAction/Enter-YesNoLoopAction.ps1
Function Enter-YesNoLoopAction {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$Question,
    [Parameter(Mandatory=$true)][scriptblock]$YesAction,
    [Parameter(Mandatory=$true)][scriptblock]$NoAction
    )
    
    #Function Version 1.2
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    
    Write-VerboseWriter("Calling: Enter-YesNoLoopAction")
    Write-VerboseWriter("Passed: [string]Question: {0}" -f $Question)
    
    do{
        $answer = Read-Host ("{0} ('y' or 'n')" -f $Question)
        Write-VerboseWriter("Read-Host answer: {0}" -f $answer)
    }while($answer -ne 'n' -and $answer -ne 'y')
    
    if($answer -eq 'y')
    {
        &$YesAction
    }
    else 
    {
        &$NoAction
    }
}

#Template Master https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Confirm-ExchangeShell/Confirm-ExchangeShell.ps1
Function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][bool]$LoadExchangeShell = $true,
    [Parameter(Mandatory=$false)][bool]$LoadExchangeVariables = $true,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.5
    <#
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-HostWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ExchangeInstallDirectory/Get-ExchangeInstallDirectory.ps1
    #>
    
    $passed = $false 
    Write-VerboseWriter("Calling: Confirm-ExchangeShell")
    Write-VerboseWriter("Passed: [bool]LoadExchangeShell: {0} | [bool]LoadExchangeVariables: {1}" -f $LoadExchangeShell,
    $LoadExchangeVariables)
    #Test that we are on Exchange 2010 or newer
    if((Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup') -or 
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'))
    {
        Write-VerboseWriter("We are on Exchange 2010 or newer")
        try 
        {
            Get-ExchangeServer -ErrorAction Stop | Out-Null
            Write-VerboseWriter("Exchange PowerShell Module already loaded.")
            $passed = $true 
        }
        catch 
        {
            Write-VerboseWriter("Failed to run Get-ExchangeServer")
            if($CatchActionFunction -ne $null)
            {
                & $CatchActionFunction
                $watchErrors = $true
            }
            if($LoadExchangeShell)
            {
                Write-HostWriter "Loading Exchange PowerShell Module..."
                try
                {
                    if($watchErrors)
                    {
                        $currentErrors = $Error.Count
                    }
                    Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                    Connect-ExchangeServer -Auto -ClientApplication:ManagementShell 
                    $passed = $true #We are just going to assume this passed. 
                    if($watchErrors)
                    {
                        $index = 0
                        while($index -lt ($Error.Count - $currentErrors))
                        {
                            & $CatchActionFunction $Error[$index]
                            $index++
                        }
                    } 
                }
                catch 
                {
                    Write-HostWriter("Failed to Load Exchange PowerShell Module...")
                }
            }
        }
        finally 
        {
            if($LoadExchangeVariables -and 
                $passed)
            {
                if($ExInstall -eq $null -or $ExBin -eq $null)
                {
                    $Global:ExInstall = Get-ExchangeInstallDirectory 
                    $Global:ExBin = $Global:ExInstall + "\Bin"
    
                    Write-VerboseWriter("Set ExInstall: {0}" -f $Global:ExInstall)
                    Write-VerboseWriter("Set ExBin: {0}" -f $Global:ExBin)
                }
            }
        }
    }
    else 
    {
        Write-VerboseWriter("Does not appear to be an Exchange 2010 or newer server.")
    }
    Write-VerboseWriter("Returned: {0}" -f $passed)
    return $passed
}

#Function to test if you are an admin on the server
#Template Master https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Confirm-Administrator/Confirm-Administrator.ps1 
Function Confirm-Administrator {
    #Function Version 1.0
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
    {
        return $true 
    }
    else 
    {
        return $false 
    }
}

Function Confirm-LocalEdgeServer{
    $server = Get-ExchangeBasicServerObject -ServerName $env:COMPUTERNAME
    if($server.Edge)
    {
        return $true 
    }
    else 
    {
        return $false 
    }
}

Function Get-TransportLoggingInformationPerServer {
param(
[string]$Server,
[int]$Version,
[bool]$EdgeServer,
[bool]$CASOnly,
[bool]$MailboxOnly
)
    Write-ScriptDebug("Function Enter: Get-TransportLoggingInformationPerServer")
    Write-ScriptDebug("Passed: [string]Server: {0} | [int]Version: {1} | [bool]EdgeServer: {2} | [bool]CASOnly: {3} | [bool]MailboxOnly: {4}" -f $Server, $Version, $EdgeServer, $CASOnly, $MailboxOnly)
    $hubObject = New-Object PSCustomObject
    $tranportLoggingObject = New-Object PSCustomObject
    if($Version -ge 15)
    {
        if(-not($CASOnly))
        {
            #Hub Transport Layer 
            $data = Get-TransportService -Identity $Server
            $hubObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name MessageTrackingLogPath -Value ($data.MessageTrackingLogPath.PathName) 
            $hubObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name QueueLogPath -Value ($data.QueueLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name WlmLogPath -Value ($data.WlmLogPath.PathName)
            $tranportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject

        }
        
        if(-not ($EdgeServer))
        {
            #Front End Transport Layer 
            if(($Version -eq 15 -and (-not ($MailboxOnly))) -or $Version -ge 16)
            {
                $FETransObject = New-Object PSCustomObject
                $data = Get-FrontendTransportService -Identity $Server
                $FETransObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
                $FETransObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
                $FETransObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
                $FETransObject | Add-Member -MemberType NoteProperty -Name AgentLogPath -Value ($data.AgentLogPath.PathName)
                $tranportLoggingObject | Add-Member -MemberType NoteProperty -Name FELoggingInfo -Value $FETransObject
            }

            if(($Version -eq 15 -and (-not ($CASOnly))) -or $Version -ge 16)
            {
                            #Mailbox Transport Layer 
                $mbxObject = New-Object PSCustomObject
                $data = Get-MailboxTransportService -Identity $Server
                $mbxObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name MailboxDeliveryThrottlingLogPath -Value ($data.MailboxDeliveryThrottlingLogPath.PathName)
                $tranportLoggingObject | Add-Member -MemberType NoteProperty -Name MBXLoggingInfo -Value $mbxObject 
            }

        }
        
    }

    elseif($Version -eq 14)
    {
        $data = Get-TransportServer -Identity $Server
        $hubObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name MessageTrackingLogPath -Value ($data.MessageTrackingLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
        $tranportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject
    }

    else 
    {
        Write-ScriptHost -WriteString ("trying to determine transport information for server {0} and wasn't able to determine the correct version type" -f $Server) -ShowServer $false
        return     
    }

    Write-ScriptDebug("ReceiveConnectors: {0} | QueueInformationThisServer: {1}" -f $ReceiveConnectors, $QueueInformationThisServer)
    if($ReceiveConnectors)
    {
        $value = Get-ReceiveConnector -Server $Server 
        $tranportLoggingObject | Add-Member -MemberType NoteProperty -Name ReceiveConnectorData -Value $value 
    }
    if($QueueInformationThisServer -and (-not($Version -eq 15 -and $CASOnly)))
    {
        $value = Get-Queue -Server $Server 
        $tranportLoggingObject | Add-Member -MemberType NoteProperty -Name QueueData -Value $value 
    }

    Write-ScriptDebug("Function Exit: Get-TransportLoggingInformationPerServer")
    return $tranportLoggingObject 
}

Function Get-ExchangeBasicServerObject {
param(
[Parameter(Mandatory=$true)][string]$ServerName
)
    Write-ScriptDebug("Function Enter: Get-ExchangeBasicServerObject")
    Write-ScriptDebug("Passed: [string]ServerName: {0}" -f $ServerName)
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    $failure = $false
    try {
        $exchServerObject = New-Object PSCustomObject 
        $exchServerObject | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerName
        $getExchangeServer = Get-ExchangeServer $ServerName -Status -ErrorAction Stop 
        $exchServerObject | Add-Member -MemberType NoteProperty -Name ExchangeServer -Value $getExchangeServer
    }
    catch {
        Write-ScriptHost -WriteString ("Failed to detect server {0} as an Exchange Server" -f $ServerName) -ShowServer $false -ForegroundColor "Red"
        $failure = $true 
    }
    finally {
        $ErrorActionPreference = $oldErrorAction
    }

    if($failure -eq $true)
    {
        return $failure
    }

    $exchAdminDisplayVersion = $exchServerObject.ExchangeServer.AdminDisplayVersion
    $exchServerRole = $exchServerObject.ExchangeServer.ServerRole 
    Write-ScriptDebug("AdminDisplayVersion: {0} | ServerRole: {1}" -f $exchAdminDisplayVersion.ToString(), $exchServerRole.ToString())
    if($exchAdminDisplayVersion.GetType().Name -eq "string")
    {
        $start = $exchAdminDisplayVersion.IndexOf(" ")
        $split = $exchAdminDisplayVersion.Substring( $start + 1, 4).split('.')
        [int]$major = $split[0]
        [int]$minor = $split[1]
    }
    if($exchAdminDisplayVersion.Major -eq 14 -or $major -eq 14)
    {
        $exchVersion = 14
    }
    elseif($exchAdminDisplayVersion.Major -eq 15 -or $major -eq 15)
    {
        #determine if 2013/2016/2019
        if($exchAdminDisplayVersion.Minor -eq 0 -or $minor -eq 0)
        {
            $exchVersion = 15
        }
        elseif($exchAdminDisplayVersion.Minor -eq 1 -or $minor -eq 1)
        {
            $exchVersion = 16
        }
        else
        {
            $exchVersion = 19
        }
    }
    else
    {
        Write-ScriptHost -WriteString ("Failed to determine what version server {0} is. AdminDisplayVersion: {1}." -f $ServerName, $exchAdminDisplayVersion.ToString()) -ShowServer $false -ForegroundColor "Red"
        return $true 
    }

    Function Confirm-MailboxServer{
    param([string]$Value)
        if($value -like "*Mailbox*" -and (-not(Confirm-EdgeServer -Value $Value))){return $true} else{ return $false}
    }

    Function Confirm-CASServer{
    param([string]$Value,[int]$Version)
        if((-not(Confirm-EdgeServer -Value $Value)) -and (($Version -ge 16) -or ($Value -like "*ClientAccess*"))){return $true} else{return $false}
    }

    Function Confirm-CASOnlyServer{
    param([string]$Value)
        if($Value -eq "ClientAccess"){return $true} else {return $false}
    }

    Function Confirm-MailboxOnlyServer{
    param([string]$Value)
        if($Value -eq "Mailbox"){return $true} else {return $false}
    }

    Function Confirm-HubServer {
    param([string]$Value,[int]$Version)
        if((($Version -ge 15) -and (-not (Confirm-CASOnlyServer -Value $Value))) -or ($Value -like "*HubTransport*")){return $true} else {return $false}
    }

    Function Confirm-EdgeServer {
    param([string]$Value)
        if($Value -eq "Edge"){return $true}else {return $false}
    }

    Function Confirm-DAGMember{
    param([bool]$MailboxServer,[string]$ServerName)
        if($MailboxServer)
        {
            if((Get-MailboxServer $ServerName).DatabaseAvailabilityGroup -ne $null){return $true}
            else{return $false}
        }
        else {
            return $false
        }
    }

    $exchServerObject | Add-Member -MemberType NoteProperty -Name Mailbox -Value (Confirm-MailboxServer -value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name CAS -Value (Confirm-CASServer -value $exchServerRole -version $exchVersion)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Hub -Value (Confirm-HubServer -value $exchServerRole -version $exchVersion)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name CASOnly -Value (Confirm-CASOnlyServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name MailboxOnly -Value (Confirm-MailboxOnlyServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Edge -Value (Confirm-EdgeServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Version -Value $exchVersion 
    $exchServerObject | Add-Member -MemberType NoteProperty -Name DAGMember -Value (Confirm-DAGMember -MailboxServer $exchServerObject.Mailbox -ServerName $exchServerObject.ServerName)

    Write-ScriptDebug("Confirm-MailboxServer: {0} | Confirm-CASServer: {1} | Confirm-HubServer: {2} | Confirm-CASOnlyServer: {3} | Confirm-MailboxOnlyServer: {4} | Confirm-EdgeServer: {5} | Confirm-DAGMember {6} | Version: {7} | AnyTransportSwitchesEnabled: {8}" -f $exchServerObject.Mailbox,
    $exchServerObject.CAS,
    $exchServerObject.Hub,
    $exchServerObject.CASOnly,
    $exchServerObject.MailboxOnly,
    $exchServerObject.Edge,
    $exchServerObject.DAGMember,
    $exchServerObject.Version,
    $Script:AnyTransportSwitchesEnabled
    )

    return $exchServerObject
}

Function Get-ServerObjects {
param(
[Parameter(Mandatory=$true)][Array]$ValidServers
)
    
    Write-ScriptDebug ("Function Enter: Get-ServerObjects")
    Write-ScriptDebug ("Passed: {0} number of Servers" -f $ValidServers.Count)
    $svrsObject = @()
    $validServersList = @() 
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    foreach($svr in $ValidServers)
    {
        Write-ScriptDebug -stringdata ("Working on Server {0}" -f $svr)

        $sobj = Get-ExchangeBasicServerObject -ServerName $svr
        if($sobj -eq $true)
        {
            Write-ScriptHost -WriteString ("Removing Server {0} from the list" -f $svr) -ForegroundColor "Red" -ShowServer $false
            continue
        }
        else 
        {
            $validServersList += $svr 
        }

        if($Script:AnyTransportSwitchesEnabled -and ($sobj.Hub -or $sobj.Version -ge 15))
        {
            $sobj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $true 
            $sobj | Add-Member -Name TransportInfo -MemberType NoteProperty -Value (Get-TransportLoggingInformationPerServer -Server $svr -version $sobj.Version -EdgeServer $sobj.Edge -CASOnly $sobj.CASOnly -MailboxOnly $sobj.MailboxOnly)
        }
        else 
        {
            $sobj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $false    
        }

        if($PopLogs)
        {
            $sobj | Add-Member -Name PopLogsLocation -MemberType NoteProperty -Value ((Get-PopSettings -Server $svr).LogFileLocation)
        }

        if($ImapLogs)
        {
            $sobj | Add-Member -Name ImapLogsLocation -MemberType NoteProperty -Value ((Get-ImapSettings -Server $svr).LogFileLocation)
        }

        $svrsObject += $sobj 
    }
    $ErrorActionPreference = $oldErrorAction
    if (($svrsObject -eq $null) -or ($svrsObject.Count -eq 0))
    {
        Write-ScriptHost -WriteString ("Something wrong happened in Get-ServerObjects stopping script") -ShowServer $false -ForegroundColor "Red"
        exit 
    }
    #Set the valid servers 
    $Script:ValidServers = $validServersList
    Write-ScriptDebug("Function Exit: Get-ServerObjects")
    Return $svrsObject
}

Function Get-ArgumentList {
param(
[Parameter(Mandatory=$true)][array]$Servers 
)
    
    $obj = New-Object PSCustomObject 
    $obj | Add-Member -Name FilePath -MemberType NoteProperty -Value $FilePath
    $obj | Add-Member -Name RootFilePath -MemberType NoteProperty -Value $Script:RootFilePath
    $obj | Add-Member -Name ServerObjects -MemberType NoteProperty -Value (Get-ServerObjects -ValidServers $Servers)
    $obj | Add-Member -Name ManagedAvailability -MemberType NoteProperty -Value $ManagedAvailability
    $obj | Add-Member -Name AppSysLogs -MemberType NoteProperty -Value $AppSysLogs
    $obj | Add-Member -Name EWSLogs -MemberType NoteProperty -Value $EWSLogs
    $obj | Add-Member -Name DailyPerformanceLogs -MemberType NoteProperty -Value $DailyPerformanceLogs   
    $obj | Add-Member -Name RPCLogs -MemberType NoteProperty -Value $RPCLogs 
    $obj | Add-Member -Name EASLogs -MemberType NoteProperty -Value $EASLogs 
    $obj | Add-Member -Name ECPLogs -MemberType NoteProperty -Value $ECPLogs 
    $obj | Add-Member -Name AutoDLogs -MemberType NoteProperty -Value $AutoDLogs
    $obj | Add-Member -Name OWALogs -MemberType NoteProperty -Value $OWALogs
    $obj | Add-Member -Name ADDriverLogs -MemberType NoteProperty -Value $ADDriverLogs
    $obj | Add-Member -Name SearchLogs -MemberType NoteProperty -Value $SearchLogs
    $obj | Add-Member -Name HighAvailabilityLogs -MemberType NoteProperty -Value $HighAvailabilityLogs
    $obj | Add-Member -Name MapiLogs -MemberType NoteProperty -Value $MapiLogs
    $obj | Add-Member -Name MessageTrackingLogs -MemberType NoteProperty -Value $MessageTrackingLogs
    $obj | Add-Member -Name HubProtocolLogs -MemberType NoteProperty -Value $HubProtocolLogs
    $obj | Add-Member -Name HubConnectivityLogs -MemberType NoteProperty -Value $HubConnectivityLogs
    $obj | Add-Member -Name FrontEndConnectivityLogs -MemberType NoteProperty -Value $FrontEndConnectivityLogs
    $obj | Add-Member -Name FrontEndProtocolLogs -MemberType NoteProperty -Value $FrontEndProtocolLogs
    $obj | Add-Member -Name MailboxConnectivityLogs -MemberType NoteProperty -Value $MailboxConnectivityLogs
    $obj | Add-Member -Name MailboxProtocolLogs -MemberType NoteProperty -Value $MailboxProtocolLogs
    $obj | Add-Member -Name QueueInformationThisServer -MemberType NoteProperty -Value $QueueInformationThisServer
    $obj | Add-Member -Name ReceiveConnectors -MemberType NoteProperty -Value $ReceiveConnectors 
    $obj | Add-Member -Name SendConnectors -MemberType NoteProperty -Value $SendConnectors 
    $obj | Add-Member -Name DAGInformation -MemberType NoteProperty -Value $DAGInformation 
    $obj | Add-Member -Name GetVdirs -MemberType NoteProperty -Value $GetVdirs 
    $obj | Add-Member -Name TransportConfig -MemberType NoteProperty -Value $TransportConfig
    $obj | Add-Member -Name DefaultTransportLogging -MemberType NoteProperty -Value $DefaultTransportLogging
    $obj | Add-Member -Name ServerInfo -MemberType NoteProperty -Value $ServerInfo
    $obj | Add-Member -Name CollectAllLogsBasedOnDaysWorth -MemberType NoteProperty -Value $CollectAllLogsBasedOnDaysWorth
    $obj | Add-Member -Name DaysWorth -MemberType NoteProperty -Value $DaysWorth 
    $obj | Add-Member -Name IISLogs -MemberType NoteProperty -Value $IISLogs 
    $obj | Add-Member -Name AnyTransportSwitchesEnabled -MemberType NoteProperty -Value $script:AnyTransportSwitchesEnabled
    $obj | Add-Member -Name HostExeServerName -MemberType NoteProperty -Value ($env:COMPUTERNAME)
    $obj | Add-Member -Name Experfwiz -MemberType NoteProperty -Value $Experfwiz
    $obj | Add-Member -Name ExperfwizLogmanName -MemberType NoteProperty -Value $ExperfwizLogmanName
    $obj | Add-Member -Name Exmon -MemberType NoteProperty -Value $Exmon
    $obj | Add-Member -Name ExmonLogmanName -MemberType NoteProperty -Value $ExmonLogmanName
    $obj | Add-Member -Name ScriptDebug -MemberType NoteProperty -Value $ScriptDebug
    $obj | Add-Member -Name ExchangeServerInfo -MemberType NoteProperty -Value $ExchangeServerInfo
    $obj | Add-Member -Name StandardFreeSpaceInGBCheckSize -MemberType NoteProperty $Script:StandardFreeSpaceInGBCheckSize
    $obj | Add-Member -Name PopLogs -MemberType NoteProperty -Value $PopLogs
    $obj | Add-Member -Name ImapLogs -MemberType NoteProperty -Value $ImapLogs 
    
    #Collect only if enabled we are going to just keep it on the base of the passed parameter object to make it simple 
    $mbx = $false
    foreach($svr in $obj.ServerObjects)
    {
        if($svr.ServerName -eq $env:COMPUTERNAME)
        {
            $mbx = $true
            $checkSvr = $svr
        }
    }
    if(($mbx) -and ($HighAvailabilityLogs) -and ($checkSvr.DAGMember))
    {
        Write-ScriptHost -WriteString ("Generating cluster logs for the local server's DAG only") -ShowServer $false 
        Write-ScriptHost -WriteString ("Server: {0}" -f $checkSvr.ServerName) -ShowServer $false 
        #Only going to do this for the local server's DAG 
        $cmd = "Cluster log /g"
        Invoke-Expression -Command $cmd | Out-Null
    }
    if($SendConnectors)
    {
        #TODO move this to a different location, but for now this should work. 
        $value = Get-SendConnector 
        $Script:SendConnectorData = $value
        #$obj | Add-Member -MemberType NoteProperty -Name SendConnectorData -Value $value
    }

    
    Return $obj 
}

Function Test-PossibleCommonScenarios {

    #all possible logs 
    if($AllPossibleLogs)
    {
        $Script:EWSLogs = $true 
        $Script:IISLogs = $true 
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailability = $true 
        $Script:RPCLogs = $true 
        $Script:EASLogs = $true 
        $Script:AutoDLogs = $true
        $Script:OWALogs = $true 
        $Script:ADDriverLogs = $true 
        $Script:SearchLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ServerInfo = $true 
        $Script:GetVdirs = $true
        $Script:DAGInformation = $true 
        $Script:DefaultTransportLogging = $true
        $Script:MapiLogs = $true 
        $Script:OrganizationConfig = $true
        $Script:ECPLogs = $true
        $Script:ExchangeServerInfo = $true
        $Script:PopLogs = $true 
        $Script:ImapLogs = $true 
        $Script:Experfwiz = $true
    }

    if($DefaultTransportLogging)
    {
        $Script:HubConnectivityLogs = $true 
        $Script:MessageTrackingLogs = $true 
        $Script:QueueInformationThisServer = $true 
        $Script:SendConnectors = $true 
        $Script:ReceiveConnectors = $true 
        $Script:TransportConfig = $true
        $Script:FrontEndConnectivityLogs = $true 
        $Script:MailboxConnectivityLogs = $true 
        $Script:FrontEndProtocolLogs = $true 
    }

    if($DatabaseFailoverIssue)
    {
        $Script:DailyPerformanceLogs = $true
        $Script:HighAvailabilityLogs = $true 
        $Script:ManagedAvailability = $true 
        $Script:DAGInformation = $true
        $Script:Experfwiz = $true
    }
    if($PerformanceIssues)
    {
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailability = $true
        $Script:Experfwiz = $true
    }
    if($PerformanceMailflowIssues)
    {
        $Script:DailyPerformanceLogs = $true 
        $Script:Experfwiz = $true 
        $Script:MessageTrackingLogs = $true 
        $Script:QueueInformationThisServer = $true 
        $Script:TransportConfig = $true 
    }
    
    #See if any transport logging is enabled. 
    $Script:AnyTransportSwitchesEnabled = $false
    if($HubProtocolLogs -or 
    $HubConnectivityLogs -or 
    $MessageTrackingLogs -or
    $QueueInformationThisServer -or
    $SendConnectors -or 
    $ReceiveConnectors -or
    $TransportConfig -or
    $FrontEndConnectivityLogs -or 
    $FrontEndProtocolLogs -or 
    $MailboxConnectivityLogs -or
    $MailboxProtocolLogs -or 
    $DefaultTransportLogging){$Script:AnyTransportSwitchesEnabled = $true}

    if($ServerInfo -or $ManagedAvailability)
    {
        $Script:ExchangeServerInfo = $true 
    }

}

Function Test-NoSwitchesProvided {
    if($EWSLogs -or 
    $IISLogs -or 
    $DailyPerformanceLogs -or 
    $ManagedAvailability -or 
    $Experfwiz -or 
    $RPCLogs -or 
    $EASLogs -or 
    $ECPLogs -or 
    $AutoDLogs -or 
    $SearchLogs -or 
    $OWALogs -or 
    $ADDriverLogs -or
    $HighAvailabilityLogs -or
    $MapiLogs -or 
    $Script:AnyTransportSwitchesEnabled -or
    $DAGInformation -or
    $GetVdirs -or 
    $OrganizationConfig -or
    $Exmon -or 
    $ServerInfo -or
    $PopLogs -or 
    $ImapLogs -or 
    $ExchangeServerInfo
    ){return}
    else 
    {
        Write-Host ""
        Write-ScriptHost -WriteString "WARNING: Doesn't look like any parameters were provided, are you sure you are running the correct command? This is ONLY going to collect the Application and System Logs." -ShowServer $false -ForegroundColor "Yellow"        
        Enter-YesNoLoopAction -Question "Would you like to continue?" -YesAction {Write-Host "Okay moving on..."} -NoAction {exit} 
    }
}

Function Test-RemoteExecutionOfServers {
param(
[Parameter(Mandatory=$true)][Array]$ServerList
)
    Write-ScriptDebug("Function Enter: Test-RemoteExecutionOfServers")
    $serversUp = @() 
    Write-ScriptHost -WriteString "Checking to see if the servers are up in this list:" -ShowServer $false 
    foreach($server in $ServerList) {Write-ScriptHost -WriteString $server -ShowServer $false}
    Write-ScriptHost -WriteString " " -ShowServer $false 
    Write-ScriptHost -WriteString "Checking their status...." -ShowServer $false 
    foreach($server in $ServerList)
    {
        Write-ScriptHost -WriteString ("Checking server {0}...." -f $server) -ShowServer $false -NoNewLine $true
        if((Test-Connection $server -Quiet))
        {   
            Write-ScriptHost -WriteString "Online" -ShowServer $false -ForegroundColor "Green"
            $serversUp += $server
        }
        else 
        {
            Write-ScriptHost -WriteString "Offline" -ShowServer $false -ForegroundColor "Red"
            Write-ScriptHost -WriteString ("Removing Server {0} from the list to collect data from" -f $server) -ShowServer $false 
        }
    }
    #Now we should check to see if can use WRM with invoke-command
    Write-ScriptHost " " -ShowServer $false 
    Write-ScriptHost -WriteString "For all the servers that are up, we are going to see if remote execution will work" -ShowServer $false 
    #shouldn't need to test if they are Exchange servers, as we should be doing that locally as well. 
    $validServers = @()
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    foreach($server in $serversUp)
    {

        try {
            Write-ScriptHost -WriteString ("Checking Server {0}....." -f $server) -ShowServer $false -NoNewLine $true
            Invoke-Command -ComputerName $server -ScriptBlock { Get-Process | Out-Null}
            #if that doesn't fail, we should be okay to add it to the working list 
            Write-ScriptHost -WriteString ("Passed") -ShowServer $false -ForegroundColor "Green" 
            $validServers += $server
        }
        catch {
            Write-ScriptHost -WriteString "Failed" -ShowServer $false -ForegroundColor "Red" 
            Write-ScriptHost -WriteString ("Removing Server {0} from the list to collect data from" -f $server) -ShowServer $false 
        }
    }
    Write-ScriptDebug("Function Exit: Test-RemoteExecutionOfServers")
    $ErrorActionPreference = $oldErrorAction
    return $validServers 
}



Function Get-VdirsLDAP {

$authTypeEnum = @" 
namespace AuthMethods  
{
    using System;
    [Flags]
    public enum AuthenticationMethodFlags
    {
        None = 0,
        Basic = 1,
        Ntlm = 2,
        Fba = 4,
        Digest = 8,
        WindowsIntegrated = 16,
        LiveIdFba = 32,
        LiveIdBasic = 64,
        WSSecurity = 128,
        Certificate = 256,
        NegoEx = 512,
        // Exchange 2013
        OAuth = 1024,
        Adfs = 2048,
        Kerberos = 4096,
        Negotiate = 8192,
        LiveIdNegotiate = 16384,
    }
}
"@
    
    Write-ScriptHost -WriteString "Collecting Virtual Directory Information..." -ShowServer $false
    Add-Type -TypeDefinition $authTypeEnum -Language CSharp
    
    $objRootDSE = [ADSI]"LDAP://rootDSE"
    $strConfigurationNC = $objRootDSE.configurationNamingContext
    $objConfigurationNC = New-object System.DirectoryServices.DirectoryEntry("LDAP://$strConfigurationNC")
    $searcher = new-object DirectoryServices.DirectorySearcher
    $searcher.filter = "(&(objectClass=msExchVirtualDirectory)(!objectClass=container))" 
    $searcher.SearchRoot = $objConfigurationNC
    $searcher.CacheResults = $false  
    $searcher.SearchScope = "Subtree"
    $searcher.PageSize = 1000  
    
    # Get all the results
    $colResults  = $searcher.FindAll()
    
    $objects = @()
    
    # Loop through the results and
    foreach ($objResult in $colResults)
    {
        $objItem = $objResult.getDirectoryEntry()
        $objProps = $objItem.Properties
        
        $place = $objResult.Path.IndexOf("CN=Protocols,CN=")
        $ServerDN = [ADSI]("LDAP://" + $objResult.Path.SubString($place,($objResult.Path.Length - $place)).Replace("CN=Protocols,",""))
        [string]$Site = $serverDN.Properties.msExchServerSite.ToString().Split(",")[0].Replace("CN=","")
        [string]$server = $serverDN.Properties.adminDisplayName.ToString()
        [string]$version = $serverDN.Properties.serialNumber.ToString()
        
    
        $obj = New-Object PSObject 
        $obj | Add-Member -MemberType NoteProperty -name Server -value $server
        $obj | Add-Member -MemberType NoteProperty -name Version -value $version
        $obj | Add-Member -MemberType NoteProperty -name Site -value $Site
        [string]$var = $objProps.DistinguishedName.ToString().Split(",")[0].Replace("CN=","")
        $obj | Add-Member -MemberType NoteProperty -name VirtualDirectory -value $var
        [string]$var = $objProps.msExchInternalHostName
        $obj | Add-Member -MemberType NoteProperty -name InternalURL -value $var
        
        if (-not [string]::IsNullOrEmpty($objProps.msExchInternalAuthenticationMethods))
        {
            $obj | Add-Member -MemberType NoteProperty -name InternalAuthenticationMethods -value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchInternalAuthenticationMethods)
        }
        else
        {
            $obj | Add-Member -MemberType NoteProperty -name InternalAuthenticationMethods -value $null
        }
        
        [string]$var = $objProps.msExchExternalHostName
        $obj | Add-Member -MemberType NoteProperty -name ExternalURL -value $var 
    
        if (-not [string]::IsNullOrEmpty($objProps.msExchExternalAuthenticationMethods))
        {
            $obj | Add-Member -MemberType NoteProperty -name ExternalAuthenticationMethods -value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchExternalAuthenticationMethods)
        }
        else
        {
            $obj | Add-Member -MemberType NoteProperty -name ExternalAuthenticationMethods -value $null
        }
        
        if (-not [string]::IsNullOrEmpty($objProps.msExch2003Url))
        {
            [string]$var = $objProps.msExch2003Url
            $obj | Add-Member -MemberType NoteProperty -name Exchange2003URL  -value $var
        }
        else
        {
            $obj | Add-Member -MemberType NoteProperty -name Exchange2003URL -value $null
        }
        
        [Array]$objects += $obj
    }
    
    return $objects 
}

Function Get-ExchangeServerDAGName {
param(
[string]$Server 
)
    Write-ScriptDebug("Function Enter: Get-ExchangeServerDAGName")
    Write-ScriptDebug("Passed: [string]Server: {0}" -f $Server)
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        $dagName = (Get-MailboxServer $Server -ErrorAction Stop).DatabaseAvailabilityGroup.Name 
        Write-ScriptDebug("Returning dagName: {0}" -f $dagName)
        Write-ScriptDebug("Function Exit: Get-ExchangeServerDAGName")
        return $dagName
    }
    catch {
        Write-ScriptHost -WriteString ("Looks like this server {0} isn't a Mailbox Server. Unable to get DAG Infomration." -f $Server) -ShowServer $false 
        return $null 
    }
    finally
    {
        $ErrorActionPreference = $oldErrorAction 
    }
}

Function Get-MailboxDatabaseInformationFromDAG{
param(
[parameter(Mandatory=$true)]$DAGInfo
)
    Write-ScriptDebug("Function Enter: Get-MailboxDatabaseInformationFromDAG")
    Write-ScriptHost -WriteString ("Getting Database information from {0} DAG member servers" -f $DAGInfo.Name) -ShowServer $false 
    $allDupMDB = @()
    foreach($serverObj in $DAGInfo.Servers)
    {
        foreach($server in $serverObj.Name)
        {
            $allDupMDB += Get-MailboxDatabase -Server $server -Status 
        }
    }
    #remove all dups 
    $MailboxDBS = @()
    foreach($t_mdb in $allDupMDB)
    {
        $add = $true
        foreach($mdb in $MailboxDBS)
        {
            if($mdb.Name -eq $t_mdb.Name)
            {
                $add = $false
                break
            }
        }
        if($add)
        {
            $MailboxDBS += $t_mdb
        }
    }

    Write-ScriptHost -WriteString ("Found the following databases:") -ShowServer $false 
    foreach($mdb in $MailboxDBS)
    {
        Write-ScriptHost -WriteString ($mdb) -ShowServer $false 
    }

    $MailboxDBInfo = @() 

    foreach($mdb in $MailboxDBS)
    {
        $mdb_Name = $mdb.Name 
        $dbObj = New-Object PSCustomObject
        $dbObj | Add-Member -MemberType NoteProperty -Name MDBName -Value $mdb_Name
        $dbObj | Add-Member -MemberType NoteProperty -Name MDBInfo -Value $mdb
        $value = Get-MailboxDatabaseCopyStatus $mdb_Name\*
        $dbObj | Add-Member -MemberType NoteProperty -Name MDBCopyStatus -Value $value
        $MailboxDBInfo += $dbObj
    }
    Write-ScriptDebug("Function Exit: Get-MailboxDatabaseInformationFromDAG")
    return $MailboxDBInfo
}

Function Get-DAGInformation {

    $dagName = Get-ExchangeServerDAGName -Server $env:COMPUTERNAME #only going to get the local server's DAG info
    if($dagName -ne $null)
    {
        $dagObj = New-Object PSCustomObject
        $value = Get-DatabaseAvailabilityGroup $dagName -Status 
        $dagObj | Add-Member -MemberType NoteProperty -Name DAGInfo -Value $value 
        $value = Get-DatabaseAvailabilityGroupNetwork $dagName 
        $dagObj | Add-Member -MemberType NoteProperty -Name DAGNetworkInfo -Value $value
        $dagObj | Add-Member -MemberType NoteProperty -Name AllMdbs -Value (Get-MailboxDatabaseInformationFromDAG -DAGInfo $dagObj.DAGInfo)
        return $dagObj
    }
}

Function Test-DiskSpace {
param(
[Parameter(Mandatory=$true)][array]$Servers,
[Parameter(Mandatory=$true)][string]$Path,
[Parameter(Mandatory=$true)][int]$CheckSize
)
    Write-ScriptDebug("Function Enter: Test-DiskSpace")
    Write-ScriptDebug("Passed: [string]Path: {0} | [int]CheckSize: {1}" -f $Path, $CheckSize)
    Write-ScriptHost -WriteString ("Checking the free space on the servers before collecting the data...") -ShowServer $false 
    if(-not ($Path.EndsWith("\")))
    {
        $Path = "{0}\" -f $Path
    }

    Function Test-ServerDiskSpace {
    param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][int]$FreeSpace,
    [Parameter(Mandatory=$true)][int]$CheckSize 
    )
        Write-ScriptDebug("Calling Test-ServerDiskSpace")
        Write-ScriptDebug("Passed: [string]Server: {0} | [int]FreeSpace: {1} | [int]CheckSize: {2}" -f $Server, $FreeSpace, $CheckSize)

        if($FreeSpace -gt $CheckSize)
        {
            Write-ScriptHost -WriteString ("[Server: {0}] : We have more than {1} GB of free space." -f $Server, $CheckSize) -ShowServer $false 
            return $true 
        }
        else 
        {
            Write-ScriptHost -WriteString ("[Server: {0}] : We have less than {1} GB of free space." -f $Server, $CheckSize) -ShowServer $false 
            return $false 
        }
    }

    if($Servers.Count -eq 1 -and $Servers[0] -eq $env:COMPUTERNAME)
    {
        Write-ScriptDebug("Local server only check. Not going to invoke Start-JobManager")
        $freeSpace = Get-FreeSpace -FilePath $Path
        if(Test-ServerDiskSpace -Server $Servers[0] -FreeSpace $freeSpace -CheckSize $CheckSize)
        {
            return $Servers[0]
        }
        else 
        {
            return $null 
        }
    }

    $serverArgs = @()
    foreach($server in $Servers)
    {
        $obj = New-Object PSCustomObject 
        $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $server 
        $obj | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $Path 
        $serverArgs += $obj
    }

    Write-ScriptDebug("Getting Get-FreeSpace string to create Script Block")
    $getFreeSpaceString = (${Function:Get-FreeSpace}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
    Write-ScriptDebug("Creating Script Block")
    $getFreeSpaceScriptBlock = [scriptblock]::Create($getFreeSpaceString)
    $serversData = Start-JobManager -ServersWithArguments $serverArgs -ScriptBlock $getFreeSpaceScriptBlock -VerboseFunctionCaller ${Function:Write-ScriptDebug} -HostFunctionCaller ${Function:Write-ScriptHost} -NeedReturnData $true -DisplayReceiveJobInCorrectFunction $true -JobBatchName "Getting the free space for test disk space"
    $passedServers = @()
    foreach($server in $Servers)
    {

        $freeSpace = $serversData[$server]
        if(Test-ServerDiskSpace -Server $server -FreeSpace $freeSpace -CheckSize $CheckSize)
        {
            $passedServers += $server 
        }
    }

    if($passedServers.Count -eq 0)
    {
        Write-ScriptHost -WriteString("Looks like all the servers didn't pass the disk space check.") -ShowServer $false 
        Write-ScriptHost -WriteString("Because there are no servers left, we will stop the script.") -ShowServer $false 
        exit 
    }
    elseif($passedServers.Count -ne $Servers.Count)
    {
        Write-ScriptHost -WriteString ("Looks like all the servers didn't pass the disk space check.") -ShowServer $false 
        Write-ScriptHost -WriteString ("We will only collect data from these servers: ") -ShowServer $false 
        foreach($svr in $passedServers)
        {
            Write-ScriptHost -ShowServer $false -WriteString ("{0}" -f $svr)
        }
        Enter-YesNoLoopAction -Question "Are yu sure you want to continue?" -YesAction {} -NoAction {exit} 
    }
    Write-ScriptDebug("Function Exit: Test-DiskSpace")
    return $passedServers
}

Function Get-RemoteLogLocation {
param(
[parameter(Mandatory=$true)][array]$Servers,
[parameter(Mandatory=$true)][string]$RootPath 
)
    Write-ScriptDebug("Calling: Get-RemoteLogLocation")
    Write-ScriptDebug("Passed: Number of servers {0} | [string]RootPath:{1}" -f $Servers.Count, $RootPath)
    Function Get-ZipLocation 
    {
        param(
        [parameter(Mandatory=$true)][string]$RootPath
        )
        $like = "*-{0}*.zip" -f (Get-Date -Format Md)
        $item = $RootPath + (Get-ChildItem $RootPath | ?{$_.Name -like $like} | sort CreationTime -Descending)[0]
        
        $obj = New-Object -TypeName PSCustomObject 
        $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $env:COMPUTERNAME
        $obj | Add-Member -MemberType NoteProperty -Name ZipFolder -Value $item
        $obj | Add-Member -MemberType NoteProperty -Name Size -Value ((Get-Item $item).Length)
        return $obj
    }
    
    $logInfo = Invoke-Command -ComputerName $Servers -ScriptBlock ${function:Get-ZipLocation} -ArgumentList $RootPath 
    
    return $logInfo
}

Function Test-DiskSpaceForCopyOver {
param(
[parameter(Mandatory=$true)][array]$LogPathObject,
[parameter(Mandatory=$true)][string]$RootPath 
)
    Write-ScriptDebug("Function Enter: Test-DiskSpaceForCopyOver")
    foreach($svrObj in $LogPathObject)
    {
        $totalSize += $svrObj.Size 
    }
    #switch it to GB in size 
    $totalSizeGB = $totalSize / 1GB
    #Get the local free space again 
    $freeSpace = Get-FreeSpace -FilePath $RootPath
    if($freeSpace -gt ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize))
    {
        Write-ScriptHost -ShowServer $true -WriteString ("Looks like we have enough free space at the path to copy over the data")
        Write-ScriptHost -ShowServer $true -WriteString ("FreeSpace: {0} TestSize: {1} Path: {2}" -f $freeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
        return $true
    }
    else 
    {
        Write-ScriptHost -ShowServer $true -WriteString("Looks like we don't have enough free space to copy over the data") -ForegroundColor "Yellow"
        Write-ScriptHost -ShowServer $true -WriteString("FreeSpace: {0} TestSize: {1} Path: {2}" -f $FreeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
        return $false
    }

}

Function Verify-LocalServerIsUsed {
param(
[Parameter(Mandatory=$true)]$Servers
)
    foreach($server in $Servers)
    {
        if($server -eq $env:COMPUTERNAME)
        {
            Write-ScriptDebug ("Local Server {0} is in the list" -f $server)
            return 
        }
    }

    Write-ScriptHost -ShowServer $true -WriteString("The server that you are running the script from isn't in the list of servers that we are collecting data from, this is currently not supported. Stopping the script.") -ForegroundColor "Yellow"
    exit 
}
   
Function Get-WritersToAddToScriptBlock {

    $writersString = "Function Write-InvokeCommandReturnHostWriter { " + (${Function:Write-InvokeCommandReturnHostWriter}).ToString() + " } `n`n Function Write-InvokeCommandReturnVerboseWriter { " + (${Function:Write-InvokeCommandReturnVerboseWriter}).ToString() + " } `n`n#"
    return $writersString 
}

###############################################
#                                             #
#          Possible Remote Functions          #
#                                             #
###############################################

Function Remote-Functions {
param(
[Parameter(Mandatory=$true)][object]$PassedInfo
)

    #Template Master https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Compress-Folder/Compress-Folder.ps1    
    Function Compress-Folder {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$Folder,
    [Parameter(Mandatory=$false)][bool]$IncludeMonthDay = $false,
    [Parameter(Mandatory=$false)][bool]$IncludeDisplayZipping = $true,
    [Parameter(Mandatory=$false)][bool]$ReturnCompressedLocation = $false
    )
    
    #Function Version 1.3
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-HostWriter.ps1
    #>
    
        Function Get-DirectorySize {
        param(
        [Parameter(Mandatory=$true)][string]$Directory,
        [Parameter(Mandatory=$false)][bool]$IsCompressed = $false 
        )
            Write-VerboseWriter("Calling: Get-DirectorySize")
            Write-VerboseWriter("Passed: [string]Directory: {0} | [bool]IsCompressed: {1}" -f $Directory, $IsCompressed)
            $itemSize = 0
            if($IsCompressed)
            {
                $itemSize = (Get-Item $Directory).Length 
            }
            else 
            {
                $childItems = Get-ChildItem $Directory -Recurse | Where-Object{-not($_.Mode.StartsWith("d-"))}
                foreach($item in $childItems)
                {
                    $itemSize += $item.Length
                }
            }
            return $itemSize
        }
        Function Enable-IOCompression
        {
            $successful = $true 
            Write-VerboseWriter("Calling: Enable-IOCompression")
            try 
            {
                Add-Type -AssemblyName System.IO.Compression.Filesystem -ErrorAction Stop
            }
            catch 
            {
                Write-HostWriter("Failed to load .NET Compression assembly. Unable to compress up the data.")
                $successful = $false 
            }
            Write-VerboseWriter("Returned: [bool]{0}" -f $successful)
            return $successful
        }
        Function Confirm-IOCompression 
        {
            Write-VerboseWriter("Calling: Confirm-IOCompression")
            $assemblies = [Appdomain]::CurrentDomain.GetAssemblies()
            $successful = $false
            foreach($assembly in $assemblies)
            {
                if($assembly.Location -like "*System.IO.Compression.Filesystem*")
                {
                    $successful = $true 
                    break 
                }
            }
            Write-VerboseWriter("Returned: [bool]{0}" -f $successful)
            return $successful
        }

        Function Compress-Now
        {
            Write-VerboseWriter("Calling: Compress-Now ")
            $zipFolder = Get-ZipFolderName -Folder $Folder -IncludeMonthDay $IncludeMonthDay
            if($IncludeDisplayZipping)
            {
                Write-HostWriter("Compressing Folder {0}" -f $Folder)
            }
            $sizeBytesBefore = Get-DirectorySize -Directory $Folder
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            [System.IO.Compression.ZipFile]::CreateFromDirectory($Folder, $zipFolder)
            $timer.Stop()
            $sizeBytesAfter = Get-DirectorySize -Directory $zipFolder -IsCompressed $true
            Write-VerboseWriter("Compressing directory size of {0} MB down to the size of {1} MB took {2} seconds." -f ($sizeBytesBefore / 1MB), ($sizeBytesAfter / 1MB),  $timer.Elapsed.TotalSeconds)

            if((Test-Path -Path $zipFolder))
            {
                Write-VerboseWriter("Compress successful, removing folder.")
                Remove-Item $Folder -Force -Recurse 
            }
            if($ReturnCompressedLocation)
            {
                Set-Variable -Name compressedLocation -Value $zipFolder -Scope 1 
            }
        }
        
        Function Get-ZipFolderName {
        param(
        [Parameter(Mandatory=$true)][string]$Folder,
        [Parameter(Mandatory=$false)][bool]$IncludeMonthDay = $false
        )
            Write-VerboseWriter("Calling: Get-ZipFolderName")
            Write-VerboseWriter("Passed - [string]Folder:{0} | [bool]IncludeMonthDay:{1}" -f $Folder, $IncludeMonthDay)
            if($IncludeMonthDay)
            {
                $zipFolderNoEXT = "{0}-{1}" -f $Folder, (Get-Date -Format Md)
            }
            else 
            {
                $zipFolderNoEXT = $Folder
            }
            Write-VerboseWriter("[string]zipFolderNoEXT: {0}" -f $zipFolderNoEXT)
            $zipFolder = "{0}.zip" -f $zipFolderNoEXT
            if(Test-Path $zipFolder)
            {
                [int]$i = 1
                do{
                    $zipFolder = "{0}-{1}.zip" -f $zipFolderNoEXT,$i 
                    $i++
                }while(Test-Path $zipFolder)
            }
            Write-VerboseWriter("Returned: [string]zipFolder {0}" -f $zipFolder)
            return $zipFolder
        }
        
        
        Write-VerboseWriter("Calling: Compress-Folder")
        Write-VerboseWriter("Passed - [string]Folder: {0} | [bool]IncludeDisplayZipping: {1} | [bool]ReturnCompressedLocation: {2}" -f $Folder, 
        $IncludeDisplayZipping,
        $ReturnCompressedLocation)

        $compressedLocation = [string]::Empty
        if(Test-Path $Folder)
        {
            if(Confirm-IOCompression)
            {
                Compress-Now
            }
            else
            {
                if(Enable-IOCompression)
                {
                    Compress-Now
                }
                else
                {
                    Write-HostWriter("Unable to compress folder {0}" -f $Folder)
                    Write-VerboseWriter("Unable to enable IO compression on this system")
                }
            }
        }
        else
        {
            Write-HostWriter("Failed to find the folder {0}" -f $Folder)
        }
        if($ReturnCompressedLocation)
        {
            Write-VerboseWriter("Returning: {0}" -f $compressedLocation)
            return $compressedLocation
        }
    }

    #Template master https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Get-FreeSpace/Get-FreeSpace.ps1
    Function Get-FreeSpace {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory=$false)][ValidateScript({$_.ToString().EndsWith("\")})][string]$FilePath,
        [Parameter(Mandatory=$false,Position=1)][object]$PassedObjectParameter
        )
        
        #Function Version 1.3
        <#
        Required Functions:
            https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-InvokeCommandReturnVerboseWriter.ps1
            https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-InvokeCommandReturnHostWriter.ps1
        #>
        if($PassedObjectParameter -ne $null)
        {
            if($PassedObjectParameter.FilePath -ne $null)
            {
                $FilePath = $PassedObjectParameter.FilePath
            }
            else 
            {
                $FilePath = $PassedObjectParameter
            }
            $InvokeCommandReturnWriteArray = $true 
        }
        $stringArray = @()
        Write-InvokeCommandReturnVerboseWriter("Calling: Get-FreeSpace")
        Write-InvokeCommandReturnVerboseWriter("Passed: [string]FilePath: {0}" -f $FilePath)
        
        Function Update-TestPath {
        param(
        [Parameter(Mandatory=$true)][string]$FilePath 
        )
            $updateFilePath = $FilePath.Substring(0,$FilePath.LastIndexOf("\", $FilePath.Length - 2)+1)
            return $updateFilePath
        }
        
        Function Get-MountPointItemTarget{
        param(
        [Parameter(Mandatory=$true)][string]$FilePath 
        )
            $itemTarget = [string]::Empty
            if(Test-Path $testPath)
            {
                $item = Get-Item $FilePath
                if($item.Target -like "Volume{*}\")
                {
                    Write-InvokeCommandReturnVerboseWriter("File Path appears to be a mount point target: {0}" -f $item.Target)
                    $itemTarget = $item.Target
                }
                else {
                    Write-InvokeCommandReturnVerboseWriter("Path didn't appear to be a mount point target")    
                }
            }
            else {
                Write-InvokeCommandReturnVerboseWriter("Path isn't a true path yet.")
            }
            return $itemTarget    
        }
        
        Function Invoke-ReturnValue {
        param(
        [Parameter(Mandatory=$true)][int]$FreeSpaceSize
        )
            if($InvokeCommandReturnWriteArray)
            {
                $hashTable = @{"ReturnObject"=$freeSpaceSize}
                Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope 1 
                return $stringArray
            }
            return $FreeSpaceSize
        }
        
        $drivesList = Get-WmiObject Win32_Volume -Filter "drivetype = 3"
        $testPath = $FilePath
        $freeSpaceSize = -1 
        while($true)
        {
            if($testPath -eq [string]::Empty)
            {
                Write-InvokeCommandReturnHostWriter("Unable to fine a drive that matches the file path: {0}" -f $FilePath)
                return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
            }
            Write-InvokeCommandReturnVerboseWriter("Trying to find path that matches path: {0}" -f $testPath)
            foreach($drive in $drivesList)
            {
                if($drive.Name -eq $testPath)
                {
                    Write-InvokeCommandReturnVerboseWriter("Found a match")
                    $freeSpaceSize = $drive.FreeSpace / 1GB 
                    Write-InvokeCommandReturnVerboseWriter("Have {0}GB of Free Space" -f $freeSpaceSize)
                    return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
                }
                Write-InvokeCommandReturnVerboseWriter("Drive name: '{0}' didn't match" -f $drive.Name)
            }
        
            $itemTarget = Get-MountPointItemTarget -FilePath $testPath
            if($itemTarget -ne [string]::Empty)
            {
                foreach($drive in $drivesList)
                {
                    if($drive.DeviceID.Contains($itemTarget))
                    {
                        $freeSpaceSize = $drive.FreeSpace / 1GB 
                        Write-InvokeCommandReturnVerboseWriter("Have {0}GB of Free Space" -f $freeSpaceSize)
                        return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
                    }
                    Write-InvokeCommandReturnVerboseWriter("DeviceID didn't appear to match: {0}" -f $drive.DeviceID)
                }
                if($freeSpaceSize -eq -1)
                {
                    Write-InvokeCommandReturnHostWriter("Unable to fine a drive that matches the file path: {0}" -f $FilePath)
                    Write-InvokeCommandReturnHostWriter("This shouldn't have happened.")
                    return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
                }
            }
            $testPath = Update-TestPath -FilePath $testPath
        }
    }

    # Template Master: https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/New-Folder/New-Folder.ps1
    Function New-Folder {
        [CmdletBinding()]
        param(
        [Alias("NewFolder")]
        [Parameter(Mandatory=$false)][array]$NewFolders,
        [Parameter(Mandatory=$false)][bool]$IncludeDisplayCreate,
        [Parameter(Mandatory=$false,Position=1)][object]$PassedParametersObject
        )
        
        #Function Version 1.4
        <#
        Required Functions:
            https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-InvokeCommandReturnVerboseWriter.ps1
            https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-InvokeCommandReturnHostWriter.ps1
        #>
        Function New-Directory {
        param(
        [Parameter(Mandatory=$false)][string]$NewFolder
        )
            if(-not (Test-Path -Path $NewFolder))
            {
                if($IncludeDisplayCreate -or $InvokeCommandReturnWriteArray)
                {
                    Write-InvokeCommandReturnHostWriter -WriteString ("Creating Directory: {0}" -f $NewFolder) -ScopeLevel 2
                }
                [System.IO.Directory]::CreateDirectory($NewFolder) | Out-Null
            }
            else 
            {
                if($IncludeDisplayCreate -or $InvokeCommandReturnWriteArray)
                {
                    Write-InvokeCommandReturnHostWriter -WriteString ("Directory {0} is already created!" -f $NewFolder) -ScopeLevel 2
                }
            }
        }
        
        $stringArray = @() 
        if($PassedParametersObject -ne $null)
        {
            if($PassedParametersObject.NewFolders -ne $null)
            {
                $NewFolders = $PassedParametersObject.NewFolders
            }
            else 
            {
                $NewFolders = $PassedParametersObject
            }
            $InvokeCommandReturnWriteArray = $true 
        }
        if($NewFolders.Count -gt 1)
        {
            $verboseDisplayNewFolders = "Multiple ('{0}') Folders Passed" -f $NewFolders.Count
        }
        else 
        {
            $verboseDisplayNewFolders = $NewFolders[0]
        }
        Write-InvokeCommandReturnVerboseWriter("Calling: New-Folder")
        Write-InvokeCommandReturnVerboseWriter("Passed: [string]NewFolders: {0} | [bool]IncludeDisplayCreate: {1}" -f $verboseDisplayNewFolders,
        $IncludeDisplayCreate)
        
        foreach($newFolder in $NewFolders)
        {
            New-Directory -NewFolder $newFolder
        }
        
        if($InvokeCommandReturnWriteArray)
        {
            return $stringArray
        }
    }

    Function Write-ScriptDebug {
    param(
    [Parameter(Mandatory=$true)]$stringdata 
    )
        if($PassedInfo.ScriptDebug -or $Script:ScriptDebug)
        {
            Write-Host("[{0} - Script Debug] : {1}" -f $env:COMPUTERNAME, $stringdata) -ForegroundColor Cyan
        }
    }

    #Function Version 1.1
    Function Write-HostWriter {
    param(
    [Parameter(Mandatory=$true)][string]$WriteString 
    )
        if($Script:Logger -ne $null)
        {
            $Script:Logger.WriteHost($WriteString)
        }
        elseif($HostFunctionCaller -eq $null)
        {
            Write-Host $WriteString
        }
        else
        {
            &$HostFunctionCaller $WriteString    
        }
    }

    #Function Version 1.1
    Function Write-VerboseWriter {
    param(
    [Parameter(Mandatory=$true)][string]$WriteString
    )
        if($Script:Logger -ne $null)
        {
            $Script:Logger.WriteHost($WriteString)
        }
        elseif($VerboseFunctionCaller -eq $null)
        {
            Write-Verbose $WriteString
        }
        else 
        {
            &$VerboseFunctionCaller $WriteString
        }
    }

    #Function Version 1.0
    Function Write-InvokeCommandReturnVerboseWriter {
    param(
    [Parameter(Mandatory=$true)][string]$WriteString,
    [int]$ScopeLevel = 1
    )
        if($InvokeCommandReturnWriteArray)
        {
            $hashTable = @{"Verbose"=("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString)}
            Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope $ScopeLevel 
        }
        else 
        {
            Write-VerboseWriter($WriteString)
        }
    }

    #Function Version 1.0
    Function Write-InvokeCommandReturnHostWriter {
    param(
    [Parameter(Mandatory=$true)][string]$WriteString,
    [int]$ScopeLevel = 1
    )
        if($InvokeCommandReturnWriteArray)
        {
            $hashTable = @{"Host"=("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString)}
            Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope $ScopeLevel 
        }
        else 
        {
            Write-HostWriter $WriteString
        }
    }

    Function Write-ScriptHost{
    param(
    [Parameter(Mandatory=$true)][string]$WriteString,
    [Parameter(Mandatory=$false)][bool]$ShowServer = $true,
    [Parameter(Mandatory=$false)][string]$ForegroundColor = "Gray",
    [Parameter(Mandatory=$false)][bool]$NoNewLine = $false
    )
        if($ShowServer)
        {
            Write-Host("[{0}] : {1}" -f $env:COMPUTERNAME, $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
        }
        else 
        {
            Write-Host("{0}" -f $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine 
        }
    }
    
    Function Zip-Folder {
    param(
    [string]$Folder,
    [bool]$ZipItAll,
    [bool]$AddCompressedSize = $true
    )
        if($ZipItAll)
        {
            Compress-Folder -Folder $Folder -IncludeMonthDay $true
        }
        else 
        {
            $compressedLocation =  Compress-Folder -Folder $Folder -ReturnCompressedLocation $AddCompressedSize
            if($AddCompressedSize -and ($compressedLocation -ne [string]::Empty))
            {
                $Script:TotalBytesSizeCompressed += ($size = Get-ItemsSize -FilePaths $compressedLocation)
                $Script:FreeSpaceMinusCopiedAndCompressedGB -= ($size / 1GB)
                Write-ScriptDebug("Current Sizes after compression: [double]TotalBytesSizeCompressed: {0} | [double]FreeSpaceMinusCopiedAndCompressedGB: {1}" -f $Script:TotalBytesSizeCompressed,
                $Script:FreeSpaceMinusCopiedAndCompressedGB)
            }
        }
    }

    Function Get-StringDataForNotEnoughFreeSpaceFile{
    param(
    [Parameter(Mandatory=$true)][hashtable]$hasher
    )
        Write-ScriptDebug("Calling: Get-StringDataForNotEnoughFreeSpaceFile")
        $reader = [string]::Empty
        $totalSizeMB = 0
        foreach($key in $hasher.Keys)
        {
            $reader += ("File: {0} | Size: {1} MB`r`n" -f $key, ($keyValue = $hasher[$key]).ToString())
            $totalSizeMB += $keyValue
        }
        $reader += ("`r`nTotal Size Attempted To Copy Over: {0} MB`r`nCurrent Available Free Space: {1} GB" -f $totalSizeMB, $Script:CurrentFreeSpaceGB)
        return $reader
    }

    Function Get-ItemsSize {
    param(
    [Parameter(Mandatory=$true)][array]$FilePaths
    )
        Write-ScriptDebug("Calling: Get-ItemsSize")
        $totalSize = 0 
        $hashSizes = @{}
        foreach($file in $FilePaths)
        {
            if(Test-Path $file)
            {
                $totalSize += ($fileSize = (Get-Item $file).Length)
                Write-ScriptDebug("File: {0} | Size: {1} MB" -f $file, ($fileSizeMB = $fileSize / 1MB))
                $hashSizes.Add($file, ("{0}" -f $fileSizeMB))
            }
            else 
            {
                Write-ScriptDebug("File no longer exists: {0}" -f $file)    
            }
        }
        Set-Variable -Name ItemSizesHashed -Value $hashSizes -Scope Script
        Write-ScriptDebug("Returning: {0}" -f $totalSize)
        return $totalSize
    }

    Function Test-FreeSpace{
        param(
        [Parameter(Mandatory=$true)][array]$FilePaths
        )
            Write-ScriptDebug("Calling: Test-FreeSpace")
            $passed = $true 
            $currentSizeCopy = Get-ItemsSize -FilePaths $FilePaths 
            #It is better to be safe than sorry, checking against probably a value way higher than needed. 
            if(($Script:FreeSpaceMinusCopiedAndCompressedGB - ($currentSizeCopy / 1GB)) -lt $Script:AdditionalFreeSpaceCushionGB)
            {
                Write-ScriptDebug("Estimated free space is getting low, going to recalculate.")
                Write-ScriptDebug("Current values: [double]FreeSpaceMinusCopiedAndCompressedGB: {0} | [double]currentSizeCopy: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3}" -f $Script:FreeSpaceMinusCopiedAndCompressedGB, 
                ($currentSizeCopy / 1GB), 
                $Script:AdditionalFreeSpaceCushionGB,
                $Script:CurrentFreeSpaceGB)
                $freeSpace = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
                Write-ScriptDebug("True current free space: {0}" -f $freeSpace)
                if($freeSpace -lt ($Script:CurrentFreeSpaceGB - .5))
                {
                    #If we off by .5GB, we need to know about this and look at the data to determine if we might have some logical errors. It is possible that the disk is that active, but that wouldn't be good either for this script. 
                    Write-ScriptDebug("CRIT: Disk Space logic is off. CurrentFreeSpaceGB: {0} | ActualFreeSpace: {1}" -f $Script:CurrentFreeSpaceGB, $freeSpace)
                }

                $Script:CurrentFreeSpaceGB = $freeSpace 
                $Script:FreeSpaceMinusCopiedAndCompressedGB = $freeSpace

                $passed = $freeSpace -gt ($addSize =$Script:AdditionalFreeSpaceCushionGB + ($currentSizeCopy / 1GB))
                if(!($passed))
                {
                    Write-ScriptHost("Free space on the drive has appear to be used up past recommended thresholds. Going to stop this execution of the script. If you feel this is an Error, please notify ExToolsFeedback@microsoft.com") -ShowServer $true -ForegroundColor "Red"
                    Write-ScriptHost("FilePath: {0} | FreeSpace: {1} | Looking for: {2}" -f $Script:RootCopyToDirectory, $freeSpace, ($freeSpace + $addSize)) -ShowServer $true -ForegroundColor "Red"
                    return $passed 
                }

            } 
            $Script:TotalBytesSizeCopied += $currentSizeCopy
            $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:FreeSpaceMinusCopiedAndCompressedGB - ($currentSizeCopy / 1GB)
    
            Write-ScriptDebug("Current values [double]FreeSpaceMinusCopiedAndCompressedGB: {0} | [double]TotalBytesSizeCopied: {1}" -f $Script:FreeSpaceMinusCopiedAndCompressedGB, $Script:TotalBytesSizeCopied)
            Write-ScriptDebug("Returning: {0}" -f $passed)
            return $passed
    }
    

    Function Copy-FullLogFullPathRecurse {
    param(
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][string]$CopyToThisLocation
    )   
        Write-ScriptDebug("Function Enter: Copy-FullLogFullPathRecurse")
        Write-ScriptDebug("Passed: [string]LogPath: {0} | [string]CopyToThisLocation: {1}" -f $LogPath, $CopyToThisLocation)
        New-Folder -NewFolder $CopyToThisLocation -IncludeDisplayCreate $true
        if(Test-Path $LogPath)
        {
            $childItems = Get-ChildItem $LogPath -Recurse
            $items = @() 
            foreach($childItem in $childItems)
            {
                if(!($childItem.Mode.StartsWith("d-")))
                {
                    $items += $childItem.VersionInfo.FileName 
                }
            }
            
            if($items -ne $null)
            {
                if(Test-FreeSpace -FilePaths $items)
                {
                    Copy-Item $LogPath\* $CopyToThisLocation -Recurse -ErrorAction SilentlyContinue
                    Zip-Folder $CopyToThisLocation
                }
                else 
                {
                    Write-ScriptDebug("Not going to copy over this set of data due to size restrictions.")
                    New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToThisLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -hasher $Script:ItemSizesHashed)  | Out-Null
                }
            }
            else 
            {
                Write-ScriptHost("No data at path '{0}'. Unable to copy this data." -f $LogPath)
                New-Item -Path ("{0}\NoDataDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
            }
        }
        else 
        {
            Write-ScriptHost("No Folder at {0}. Unable to copy this data." -f $LogPath)
            New-Item -Path ("{0}\NoFolderDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
        }
        Write-ScriptDebug("Function Exit: Copy-FullLogFullPathRecurse")
    }

    Function Copy-LogsBasedOnTime {
    param(
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][string]$CopyToThisLocation
    )
        Write-ScriptDebug("Function Enter: Copy-LogsBasedOnTime")
        Write-ScriptDebug("Passed: [string]LogPath: {0} | [string]CopyToThisLocation: {1}" -f $LogPath, $CopyToThisLocation)
        New-Folder -NewFolder $CopyToThisLocation -IncludeDisplayCreate $true

        Function No-FilesInLocation {
        param(
        [Parameter(Mandatory=$true)][string]$CopyFromLocation,
        [Parameter(Mandatory=$true)][string]$CopyToLocation 
        )
            Write-ScriptHost -WriteString ("It doesn't look like you have any data in this location {0}." -f $CopyFromLocation) -ForegroundColor "Yellow"
            #Going to place a file in this location so we know what happened
            $tempFile = $CopyToLocation + "\NoFilesDetected.txt"
            New-Item $tempFile -ItemType File -Value $LogPath | Out-Null
            Start-Sleep 1
        }

        $date = (Get-Date).AddDays(0-$PassedInfo.DaysWorth)
        $copyFromDate = "$($Date.Month)/$($Date.Day)/$($Date.Year)"
        Write-ScriptDebug("Copy From Date: {0}" -f $copyFromDate)
        $skipCopy = $false 
        if(!(Test-Path $LogPath))
        {
            #if the directory isn't there, we need to handle it
            No-FilesInLocation -CopyFromLocation $LogPath -CopyToLocation $CopyToThisLocation
            Write-ScriptDebug("Function Exit: Copy-LogsBasedOnTime")
            return 
        }
        #We are not copying files recurse so we need to not include possible directories or we will throw an error 
        $files = Get-ChildItem $LogPath | Sort-Object LastWriteTime -Descending | ?{$_.LastWriteTime -ge $copyFromDate -and $_.Mode -notlike "d*"}
        #if we don't have any logs, we want to attempt to copy something 
        if($files -eq $null)
        {
            <#
                There are a few different reasons to get here
                1. We don't have any files in the timeframe request in the directory that we are looking at
                2. We have sub directories that we need to look into and look at those files (Only if we don't have files in the currently location so we aren't pulling files like the index files from message tracking)
            #>
            Write-ScriptDebug("Copy-LogsBasedOnTime: Failed to find any logs in the directory provided, need to do a deeper look to find some logs that we want.")
            $allFiles = Get-ChildItem $LogPath | Sort-Object LastWriteTime -Descending
            Write-ScriptDebug("Displaying all items in the directory: {0}" -f $LogPath)
            foreach($file in $allFiles)
            {
                Write-ScriptDebug("File Name: {0} Last Write Time: {1}" -f $file.Name, $file.LastWriteTime)
            }
            
            #Let's see if we have any files in this location while having directories 
            $directories = $allFiles | ?{$_.Mode -like "d*"}
            $filesInDirectory = $allFiles | ?{$_.Mode -notlike "d*"}

            if(($directories -ne $null) -and ($filesInDirectory -eq $null))
            {
                #This means we should be looking in the sub directories not the current directory so let's re-do that logic to try to find files in that timeframe. 
                foreach($dir in $directories)
                {
                    $newLogPath = $dir.FullName
                    $newCopyToThisLocation = "{0}\{1}" -f $CopyToThisLocation, $dir.Name
                    New-Folder -NewFolder $newCopyToThisLocation -IncludeDisplayCreate $true
                    $files = Get-ChildItem $newLogPath| Sort-Object LastWriteTime -Descending | ?{$_.LastWriteTime -ge $copyFromDate -and $_.Mode -notlike "d*"}
                    if($files -eq $null)
                    {
                        No-FilesInLocation -CopyFromLocation $newLogPath -CopyToLocation $newCopyToThisLocation
                    }
                    else 
                    {
                        Write-ScriptDebug("Found {0} number of files at the location {1}" -f $files.Count, $newLogPath)
                        $filesFullPath = @()
                        $files | %{$filesFullPath += $_.VersionInfo.FileName}
                        Copy-BulkItems -CopyToLocation $newCopyToThisLocation -ItemsToCopyLocation $filesFullPath
                        Zip-Folder -Folder $newCopyToThisLocation
                    }
                }
                Write-ScriptDebug("Function Exit: Copy-LogsBasedOnTime")
                return 
            }

            #If we get here, we want to find the latest file that isn't a directory.
            $files = $allFiles | ?{$_.Mode -notlike "d*"} | Select-Object -First 1 

            #If we are still null, we want to let them know 
            If($files -eq $null)
            {
                $skipCopy = $true 
                No-FilesInLocation -CopyFromLocation $LogPath -CopyToLocation $CopyToThisLocation
            }
        }
        Write-ScriptDebug("Found {0} number of files at the location {1}" -f $Files.Count, $LogPath)
        #ResetFiles to full path 
        $filesFullPath = @()
        $files | %{$filesFullPath += $_.VersionInfo.FileName}

        if(-not ($skipCopy))
        {
            Copy-BulkItems -CopyToLocation $CopyToThisLocation -ItemsToCopyLocation $filesFullPath
            Zip-Folder -Folder $CopyToThisLocation
        }
        Write-ScriptDebug("Function Exit: Copy-LogsBasedOnTime")
    }

    Function Copy-BulkItems {
    param(
    [string]$CopyToLocation,
    [Array]$ItemsToCopyLocation
    )
        if(-not(Test-Path $CopyToLocation))
        {
            New-Folder -NewFolder $CopyToLocation -IncludeDisplayCreate $true
        }

        if(Test-FreeSpace -FilePaths $ItemsToCopyLocation)
        {
            foreach($item in $ItemsToCopyLocation)
            {
                Copy-Item -Path $item -Destination $CopyToLocation -ErrorAction SilentlyContinue
            }
        }
        else 
        {
            Write-ScriptHost("Not enough free space to copy over this data set.")
            New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -hasher $Script:ItemSizesHashed) | Out-Null
        }
    }

    Function Remove-EventLogChar {
    param(
        [string]$location 
    )
        Get-ChildItem $location | Rename-Item -NewName {$_.Name -replace "%4","-"}
    }

    Function Add-ServerNameToFileName{
    param(
    [Parameter(Mandatory=$true)][string]$FilePath
    )
        Write-ScriptDebug("Calling: Add-ServerNameToFileName")
        Write-ScriptDebug("Passed: [string]FilePath: {0}" -f $FilePath)
        $fileName = "{0}_{1}" -f $env:COMPUTERNAME, ($name = $FilePath.Substring($FilePath.LastIndexOf("\") + 1))
        $filePathWithServerName = $FilePath.Replace($name,$fileName) 
        Write-ScriptDebug("Returned: {0}" -f $filePathWithServerName)
        return $filePathWithServerName
    }

    Function Test-CommandExists {
    param(
    [string]$command
    )
        $oldAction = $ErrorActionPreference
        $ErrorActionPreference = "Stop"

        try {
            if(Get-Command $command){return $true}
        }
        catch {
            return $false
        }
        finally{
            $ErrorActionPreference = $oldAction
        }
    }

    Function Set-IISDirectoryInfo {
        Write-ScriptDebug("Function Enter: Set-IISDirectoryInfo")

        Function Get-IISDirectoryFromGetWebSite 
        {
            Write-ScriptDebug("Get-WebSite command exists")
            foreach($WebSite in $(Get-WebSite))
            {
                $logFile = "$($Website.logFile.directory)\W3SVC$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
                $Script:IISLogDirectory += $logFile + ";"
                Write-ScriptDebug("Found Directory: {0}" -f $logFile)
            }
            #remove the last ; 
            $Script:IISLogDirectory = $Script:IISLogDirectory.Substring(0, $Script:IISLogDirectory.Length - 1)
            #$Script:IISLogDirectory = ((Get-WebConfigurationProperty "system.applicationHost/sites/siteDefaults" -Name logFile).directory).Replace("%SystemDrive%",$env:SystemDrive) 
            Write-ScriptDebug("Set IISLogDirectory: {0}" -f $Script:IISLogDirectory)
        }

        Function Get-IISDirectoryFromDefaultSettings 
        {
            $Script:IISLogDirectory = "C:\inetpub\logs\LogFiles\" #Default location for IIS Logs 
            Write-ScriptDebug("Get-WebSite command doesn't exists. Set IISLogDirectory to: {0}" -f $Script:IISLogDirectory)
        }

        if((Test-CommandExists -command "Get-WebSite"))
        {
            Get-IISDirectoryFromGetWebSite
        }
        else 
        {
            #May need to load the module 
            try 
            {
                Write-ScriptDebug("Going to attempt to load the WebAdministration Module")
                Import-Module WebAdministration
                Write-ScriptDebug("Successful loading the module")
                if((Test-CommandExists -command "Get-WebSite"))
                {
                    Get-IISDirectoryFromGetWebSite
                }
            }
            catch 
            {
                Get-IISDirectoryFromDefaultSettings
            }
            
        }
        #Test out the directories that we found. 
        foreach($directory in $Script:IISLogDirectory.Split(";"))
        {
            if(-not (Test-Path $directory))
            {
                Write-ScriptDebug("Failed to find a valid path for at least one of the IIS directories. Test path: {0}" -f $directory)
                Write-ScriptDebug("Function Exit: Set-IISDirectoryInfo - Failed")
                Write-ScriptHost -ShowServer $true -WriteString ("Failed to determine where the IIS Logs are located at. Unable to collect them.") -ForegroundColor "Red"
                return $false
            }
        }

        Write-ScriptDebug("Function Exit: Set-IISDirectoryInfo - Passed")
        return $true 
    }

    ####### Collect Logs Functions #####################
    Function Save-ServerInfoData {
        Write-ScriptDebug("Function Enter: Save-ServerInfoData")
        $copyTo = $Script:RootCopyToDirectory + "\General_Server_Info"
        New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true

        #Get MSInfo from server 
        msinfo32.exe /nfo (Add-ServerNameToFileName -FilePath ("{0}\msinfo.nfo" -f $copyTo))
        Write-ScriptHost -WriteString ("Waiting for msinfo32.exe process to end before moving on...") -ForegroundColor "Yellow"
        while((Get-Process | ?{$_.ProcessName -eq "msinfo32"}).ProcessName -eq "msinfo32")
        {
            sleep 5;
        }

        #Include TLS Registry Information #84
        $tlsSettings = @()
        try 
        {
            $tlsSettings += Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Recurse | ?{$_.Name -like "*TLS*"} -ErrorAction stop 
        }
        catch 
        {
            Write-ScriptDebug("Failed to get child items of 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'")
        }
        try 
        {
            $regBaseV4 = "HKLM:SOFTWARE\{0}\.NETFramework\v4.0.30319"
            $tlsSettings += Get-Item ($currentKey = $regBaseV4 -f "Microsoft") -ErrorAction stop 
            $tlsSettings += Get-Item ($currentKey = $regBaseV4 -f "Wow6432Node\Microsoft") -ErrorAction stop 
        }
        catch 
        {
            Write-ScriptDebug("Failed to get child items of '{0}'" -f $currentKey)
        }
        try 
        {
            $regBaseV2 = "HKLM:SOFTWARE\{0}\.NETFramework\v2.0.50727"
            $tlsSettings += Get-Item ($currentKey = $regBaseV2 -f "Microsoft") -ErrorAction stop 
            $tlsSettings += Get-Item ($currentKey = $regBaseV2 -f "Wow6432Node\Microsoft") -ErrorAction stop 
        }
        catch 
        {
            Write-ScriptDebug("Failed to get child items of '{0}'" -f $currentKey)
        }
        Save-DataInfoToFile -DataIn $tlsSettings -SaveToLocation ("{0}\TLS_RegistrySettings" -f $copyTo) -FormatList $false

        #Running Processes #35 
        Save-DataInfoToFile -dataIn (Get-Process) -SaveToLocation ("{0}\Running_Processes" -f $copyTo) -FormatList $false

        #Services Information #36
        Save-DataInfoToFile -dataIn (Get-Service) -SaveToLocation ("{0}\Services_Information" -f $copyTo) -FormatList $false

        #VSSAdmin Information #39
        Save-DataInfoToFile -DataIn (vssadmin list Writers) -SaveToLocation ("{0}\VSS_Writers" -f $copyTo) -SaveXMLFile $false 

        #Driver Information #34
        Save-DataInfoToFile -dataIn (Get-ChildItem ("{0}\System32\drivers" -f $env:SystemRoot) | Where-Object{$_.Name -like "*.sys"}) -SaveToLocation ("{0}\System32_Drivers" -f $copyTo)

        Save-DataInfoToFile -DataIn (Get-HotFix | Select-Object Source, Description, HotFixID, InstalledBy, InstalledOn) -SaveToLocation ("{0}\HotFixInfo" -f $copyTo)
        
        #TCPIP Networking Information #38
        Save-DataInfoToFile -DataIn (ipconfig /all) -SaveToLocation ("{0}\IPConfiguration" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (netstat -anob) -SaveToLocation ("{0}\NetStat_ANOB" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (route print) -SaveToLocation ("{0}\Network_Routes" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (arp -a) -SaveToLocation ("{0}\Network_ARP" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (netstat -nato) -SaveToLocation ("{0}\Netstat_NATO" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (netstat -es) -SaveToLocation ("{0}\Netstat_ES" -f $copyTo) -SaveXMLFile $false 

        #IPsec 
        Save-DataInfoToFile -DataIn (netsh ipsec dynamic show all) -SaveToLocation ("{0}\IPsec_netsh_dynamic" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (netsh ipsec static show all) -SaveToLocation ("{0}\IPsec_netsh_static" -f $copyTo) -SaveXMLFile $false 

        #FLTMC
        Save-DataInfoToFile -DataIn (fltmc) -SaveToLocation ("{0}\FLTMC_FilterDrivers" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (fltmc volumes) -SaveToLocation ("{0}\FLTMC_Volumes" -f $copyTo) -SaveXMLFile $false 
        Save-DataInfoToFile -DataIn (fltmc instances) -SaveToLocation ("{0}\FLTMC_Instances" -f $copyTo) -SaveXMLFile $false 
        
        $hiveKey = @()
        try
        {
            $hiveKey = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Exchange\ -Recurse -ErrorAction Stop 
        }
        catch 
        {
            #at this point don't do anything besides debug log 
            Write-ScriptDebug("Failed to get child item on HKLM:\SOFTWARE\Microsoft\Exchange\")
        }
        $hiveKey += Get-ChildItem HKLM:\SOFTWARE\Microsoft\ExchangeServer\ -Recurse
        Save-DataInfoToFile -DataIn $hiveKey -SaveToLocation ("{0}\Exchange_Registry_Hive" -f $copyTo) -SaveTextFile $false 

        Save-DataInfoToFile -DataIn (gpresult /R /Z) -SaveToLocation ("{0}\GPResult" -f $copyTo) -SaveXMLFile $false 
        gpresult /H (Add-ServerNameToFileName -FilePath ("{0}\GPResult.html" -f $copyTo))

        #Storage Information 
        if(Test-CommandExists -command "Get-Volume")
        {
            Save-DataInfoToFile -DataIn (Get-Volume) -SaveToLocation ("{0}\Volume" -f $copyTo)
        }
        else 
        {
            Write-ScriptDebug("Get-Volume isn't a valid command")    
        }

        if(Test-CommandExists -command "Get-Disk")
        {
            Save-DataInfoToFile -DataIn (Get-Disk) -SaveToLocation ("{0}\Disk" -f $copyTo)
        }
        else 
        {
            Write-ScriptDebug("Get-Disk isn't a valid command")    
        }

        if(Test-CommandExists -command "Get-Partition")
        {
            Save-DataInfoToFile -DataIn (Get-Partition) -SaveToLocation ("{0}\Partition" -f $copyTo) 
        }
        else
        {
            Write-ScriptDebug("Get-Partition isn't a valid command")
        }

        Zip-Folder -Folder $copyTo
        Write-ScriptDebug("Function Exit: Save-ServerInfoData")
    }

    Function Save-WindowsEventLogs {
        
        Write-ScriptDebug("Function Enter: Save-WindowsEventLogs")
        $baseSaveLocation = $Script:RootCopyToDirectory + "\Windows_Event_Logs"
        $SaveLogs = @{}
        if($PassedInfo.AppSysLogs)
        {
            Write-ScriptDebug("Adding Application and System Logs")
            $Logs = @()
            $Logs += "Application.evtx"
            $Logs += "System.evtx"
            $Logs += "MSExchange Management.evtx"
            $SaveLogs.Add("Windows-Logs",$Logs) 
        }
        if($PassedInfo.ManagedAvailability)
        {
            Write-ScriptDebug("Adding Managed Availability Logs")
            $Logs = @()
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4MaintenanceDefinition.evtx"
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4MaintenanceResult.evtx"
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4MonitorDefinition.evtx"
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4MonitorResult.evtx"
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4ProbeDefinition.evtx"
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4ProbeResult.evtx"
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4ResponderDefinition.evtx"
            $Logs += "Microsoft-Exchange-ActiveMonitoring%4ResponderResult.evtx"
            $SaveLogs.Add("Microsoft-Exchange-ActiveMonitoring", $Logs)
            
            $Logs = @()
            $Logs += "Microsoft-Exchange-ManagedAvailability%4InvokeNowRequest.evtx"
            $Logs += "Microsoft-Exchange-ManagedAvailability%4InvokeNowResult.evtx"
            $Logs += "Microsoft-Exchange-ManagedAvailability%4Monitoring.evtx"
            $Logs += "Microsoft-Exchange-ManagedAvailability%4RecoveryActionLogs.evtx"
            $Logs += "Microsoft-Exchange-ManagedAvailability%4RecoveryActionResults.evtx"
            $Logs += "Microsoft-Exchange-ManagedAvailability%4RemoteActionLogs.evtx"
            $Logs += "Microsoft-Exchange-ManagedAvailability%4StartupNotification.evtx"
            $Logs += "Microsoft-Exchange-ManagedAvailability%4ThrottlingConfig.evtx"
            $SaveLogs.Add("Microsoft-Exchange-ManagedAvailability", $Logs)
        }
        if($PassedInfo.HighAvailabilityLogs)
        {
            Write-ScriptDebug("Adding High Availability Logs")
            $Logs = @()
            $Logs += "Microsoft-Exchange-HighAvailability%4BlockReplication.evtx"
            $Logs += "Microsoft-Exchange-HighAvailability%4Debug.evtx"
            $Logs += "Microsoft-Exchange-HighAvailability%4Operational.evtx"
            $Logs += "Microsoft-Exchange-HighAvailability%4TruncationDebug.evtx"
            $Logs += "Microsoft-Exchange-HighAvailability%4SeedingDebug.evtx"    
            $Logs += "Microsoft-Exchange-HighAvailability%4Network.evtx"
            $Logs += "Microsoft-Exchange-HighAvailability%4Seeding.evtx"
            $Logs += "Microsoft-Exchange-HighAvailability%4Monitoring.evtx"
            $Logs += "Microsoft-Exchange-HighAvailability%4AppLogMirror.evtx"
            $SaveLogs.Add("Microsoft-Exchange-HighAvailability", $Logs)
            
            $Logs = @()
            $Logs += "Microsoft-Exchange-MailboxDatabaseFailureItems%4Operational.evtx"
            $Logs += "Microsoft-Exchange-MailboxDatabaseFailureItems%4Debug.evtx"
            $SaveLogs.Add("Microsoft-Exchange-MailboxDatabaseFailureItems", $Logs)

            $Logs = @()
            $Logs += "Microsoft-Windows-FailoverClustering%4Operational.evtx"
            $Logs += "Microsoft-Windows-FailoverClustering%4Diagnostic.evtx"
            $Logs += $env:SystemRoot + "\Cluster\Reports\Cluster.log"
            $SaveLogs.Add("Microsoft-Windows-FailoverClustering", $Logs)
        }

        foreach($directory in $SaveLogs.Keys)
        {
            $validLogs = @()
            Write-ScriptDebug("Working on directory: {0}" -f $directory)
            foreach($log in $SaveLogs[$directory])
            {
                $path = $log 
                if(!($log.StartsWith("C:\")))
                {
                    $path = "{0}\System32\Winevt\Logs\{1}" -f $env:SystemRoot, $log 
                }
                if(Test-Path $path)
                {
                    $validLogs += $path 
                }
                else 
                {
                    Write-ScriptDebug("Failed to find path: '{0}'" -f $path)
                }
            }
            $zipFolder = $true 
            if($directory -notlike "ROOT*")
            {
                $saveLocation = "{0}\{1}" -f $baseSaveLocation, $directory 
            }
            else 
            {
                $zipFolder = $false 
                $saveLocation = $baseSaveLocation
            }
            if($validLogs -ne $null)
            {
                Copy-BulkItems -CopyToLocation $saveLocation -ItemsToCopyLocation $validLogs 
                Remove-EventLogChar -location $saveLocation 
                if($zipFolder)
                {
                    Zip-Folder -Folder $saveLocation
                }
            }
        }
    }

    Function Get-ThisServerObject {

        foreach($srv in $PassedInfo.ServerObjects)
        {
            if($srv.ServerName -eq $env:COMPUTERNAME)
            {
                $Script:localServerObject = $srv 
            }
        }
        if($Script:localServerObject -eq $null -or $Script:localServerObject.ServerName -ne $env:COMPUTERNAME)
        {
            #Something went wrong.... 
            Write-ScriptHost -WriteString ("Something went wrong trying to find the correct Server Object for this server. Stopping this instance of Execution")
            exit 
        }
    }
 
    Function Set-RootCopyDirectory{
        if($Script:RootFilePath -eq $null)
        {
            $stringValue = $PassedInfo.RootFilePath
        }
        else 
        {
            $stringValue = $Script:RootFilePath    
        }
        $str = "{0}{1}" -f $stringValue, $env:COMPUTERNAME
        return $str
    }

    #Template Master https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Get-ExchangeInstallDirectory/Get-ExchangeInstallDirectory.ps1
    Function Get-ExchangeInstallDirectory
    {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory=$false)][bool]$InvokeCommandReturnWriteArray,
        [Parameter(Mandatory=$false)][scriptblock]$VerboseFunctionCaller,
        [Parameter(Mandatory=$false)][scriptblock]$HostFunctionCaller
        )
        
        #Function Version 1.0
        Function Write-VerboseWriter {
        param(
        [Parameter(Mandatory=$true)][string]$WriteString 
        )
            if($InvokeCommandReturnWriteArray)
            {
                $hashTable = @{"Verbose"=("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString)}
                Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope 1 
            }
            elseif($VerboseFunctionCaller -eq $null)
            {
                Write-Verbose $WriteString
            }
            else 
            {
                &$VerboseFunctionCaller $WriteString
            }
        }
            
        Function Write-HostWriter {
        param(
        [Parameter(Mandatory=$true)][string]$WriteString 
        )
            if($InvokeCommandReturnWriteArray)
            {
                $hashTable = @{"Host"=("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString)}
                Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope 1 
            }
            elseif($HostFunctionCaller -eq $null)
            {
                Write-Host $WriteString
            }
            else
            {
                &$HostFunctionCaller $WriteString    
            }
        }
            
        $passedVerboseFunctionCaller = $false
        $passedHostFunctionCaller = $false
        if($VerboseFunctionCaller -ne $null){$passedVerboseFunctionCaller = $true}
        if($HostFunctionCaller -ne $null){$passedHostFunctionCaller = $true}
        $stringArray = @()
        Write-VerboseWriter("Calling: Get-ExchangeInstallDirectory")
        Write-VerboseWriter("Passed: [bool]InvokeCommandReturnWriteArray: {0} | [scriptblock]VerboseFunctionCaller: {1} | [scriptblock]HostFunctionCaller: {2}" -f $InvokeCommandReturnWriteArray, 
        $passedVerboseFunctionCaller, 
        $passedHostFunctionCaller)
        
        $installDirectory = [string]::Empty
        if(Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup')
        {
            Write-VerboseWriter("Detected v14")
            $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath 
        }
        elseif(Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup')
        {
            Write-VerboseWriter("Detected v15")
            $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath	
        }
        else 
        {
            Write-HostWriter -WriteString ("Something went wrong trying to find Exchange Install path on this server: {0}" -f $env:COMPUTERNAME)  
        }
        Write-VerboseWriter("Returning: {0}" -f $installDirectory)
        if($InvokeCommandReturnWriteArray)
        {
            $hashTable = @{"ReturnObject"=$installDirectory}
            $stringArray += $hashTable
            return $stringArray
        }
        return $installDirectory
    }

    Function Set-InstanceRunningVars
    {
        $Script:RootCopyToDirectory = Set-RootCopyDirectory
        #Set the local Server Object Information 
        Get-ThisServerObject 
        
        $Script:TotalBytesSizeCopied = 0 
        $Script:TotalBytesSizeCompressed = 0 
        $Script:AdditionalFreeSpaceCushionGB = $PassedInfo.StandardFreeSpaceInGBCheckSize
        $Script:CurrentFreeSpaceGB = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
        $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:CurrentFreeSpaceGB
        $Script:localExinstall = Get-ExchangeInstallDirectory -VerboseFunctionCaller ${Function:Write-ScriptDebug} -HostFunctionCaller ${Function:Write-ScriptHost}
        #shortcut to Exbin directory (probably not really needed)
        $Script:localExBin = $Script:localExinstall + "Bin\"

    }
    #Template Master https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Save-DataToFile/Save-DataToFile.ps1
    Function Save-DataToFile {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory=$false)][object]$DataIn,
        [Parameter(Mandatory=$true)][string]$SaveToLocation,
        [Parameter(Mandatory=$false)][bool]$FormatList = $true,
        [Parameter(Mandatory=$false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory=$false)][bool]$SaveXMLFile = $true,
        [Parameter(Mandatory=$false)][scriptblock]$VerboseFunctionCaller
        )
        
        #Function Version 1.1
        Function Write-VerboseWriter {
        param(
        [Parameter(Mandatory=$true)][string]$WriteString 
        )
            if($InvokeCommandReturnWriteArray)
            {
            $hashTable = @{"Verbose"=("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString)}
            Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope 1 
            }
            elseif($VerboseFunctionCaller -eq $null)
            {
                Write-Verbose $WriteString
            }
            else 
            {
                &$VerboseFunctionCaller $WriteString
            }
        }
        
        $passedVerboseFunctionCaller = $false
        if($VerboseFunctionCaller -ne $null){$passedVerboseFunctionCaller = $true}
        Write-VerboseWriter("Calling: Save-DataToFile")
        Write-VerboseWriter("Passed: [string]SaveToLocation: {0} | [bool]FormatList: {1} | [bool]SaveTextFile: {2} | [bool]SaveXMLFile: {3} | [scriptblock]VerboseFunctionCaller: {4}" -f $SaveToLocation,
        $FormatList,
        $SaveTextFile,
        $SaveXMLFile,
        $passedVerboseFunctionCaller)
        
        $xmlSaveLocation = "{0}.xml" -f $SaveToLocation
        $txtSaveLocation = "{0}.txt" -f $SaveToLocation
        
        if($DataIn -ne [string]::Empty -and $DataIn -ne $null)
        {
            if($SaveXMLFile)
            {
                $DataIn | Export-Clixml $xmlSaveLocation -Encoding UTF8
            }
            if($SaveTextFile)
            {
                if($FormatList)
                {
                    $DataIn | Format-List * | Out-File $txtSaveLocation
                }
                else 
                {
                    $DataIn | Format-Table -AutoSize | Out-File $txtSaveLocation    
                }
            }
            
        }
        else
        {
            Write-VerboseWriter("DataIn was an empty string. Not going to save anything.")
        }
    }

    Function Save-DataInfoToFile {
        param(
        [Parameter(Mandatory=$false)][object]$DataIn,
        [Parameter(Mandatory=$true)][string]$SaveToLocation,
        [Parameter(Mandatory=$false)][bool]$FormatList = $true,
        [Parameter(Mandatory=$false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory=$false)][bool]$SaveXMLFile = $true
        )
            [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
            Save-DataToFile -DataIn $DataIn -SaveToLocation (Add-ServerNameToFileName $SaveToLocation) -FormatList $FormatList -VerboseFunctionCaller ${Function:Write-ScriptDebug} -SaveTextFile $SaveTextFile -SaveXMLFile $SaveXMLFile
            $timer.Stop()
            Write-ScriptDebug("Took {0} seconds to save out the data." -f $timer.Elapsed.TotalSeconds)
    }

    ###################################
    #                                 #
    #         Logman Functions        #
    #                                 #
    ###################################
    
    Function Start-Logman {
    param(
    [Parameter(Mandatory=$true)][string]$LogmanName,
    [Parameter(Mandatory=$true)][string]$ServerName
    )
        Write-ScriptHost -WriteString ("Starting Data Collection {0} on server {1}" -f $LogmanName,$ServerName)
        logman start -s $ServerName $LogmanName
    }
    
    Function Stop-Logman {
    param(
    [Parameter(Mandatory=$true)][string]$LogmanName,
    [Parameter(Mandatory=$true)][string]$ServerName
    )
        Write-ScriptHost -WriteString ("Stopping Data Collection {0} on server {1}" -f $LogmanName,$ServerName)
        logman stop -s $ServerName $LogmanName
    }
    
    
    Function Copy-LogmanData{
    param(
    [Parameter(Mandatory=$true)]$ObjLogman
    )
        switch ($ObjLogman.LogmanName)
        {
            $PassedInfo.ExperfwizLogmanName {$folderName = "ExPerfWiz_Data"; break}
            $PassedInfo.ExmonLogmanName {$folderName = "ExmonTrace_Data"; break}
            default {$folderName = "Logman_Data"; break}
        }
    
        $strDirectory = $ObjLogman.RootPath
        $copyTo = $Script:RootCopyToDirectory + "\" + $folderName
        New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true
        if(Test-Path $strDirectory)
        {
            $wildExt = "*" + $objLogman.Ext
            $filterDate = $objLogman.StartDate
            
            $date = (Get-Date).AddDays(0-$PassedInfo.DaysWorth)
            $copyFromDate = "$($Date.Month)/$($Date.Day)/$($Date.Year)"
            
            Write-ScriptDebug("Copy From Date: {0}" -f $filterDate)
            
            if([DateTime]$filterDate -lt [DateTime]$copyFromDate)
            {
                $filterDate = $copyFromDate
                Write-ScriptDebug("Updating Copy From Date to: '{0}'" -f $filterDate)
            }

            $childItems = Get-ChildItem $strDirectory | ?{($_.Name -like $wildExt) -and ($_.CreationTime -ge $filterDate)}
            $items = @()
            foreach($childItem in $childItems)
            {
                $items += $childItem.VersionInfo.FileName
            }
            if($items -ne $null)
            {
                Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items 
                Zip-Folder -Folder $copyTo
            }
            else 
            {
                Write-ScriptHost -WriteString ("Failed to find any files in the directory: '{0}' that was greater than or equal to this time: {1}" -f $strDirectory, $filterDate) -ForegroundColor "Yellow"
                Write-ScriptHost -WriteString  ("Going to try to see if there are any files in this directory for you..." ) -NoNewline $true
                $files = Get-ChildItem $strDirectory | ?{$_.Name -like $wildExt}
                if($files -ne $null)
                {
                    #only want to get lastest data 
                    $newestFilesTime = ($files | Sort CreationTime -Descending)[0].CreationTime.AddDays(-1)
                    $newestFiles = $files | ?{$_.CreationTime -ge $newestFilesTime}

                    $items = @() 
                    foreach($newestFile in $newestFiles)
                    {
                        $items += $newestFile.VersionInfo.FileName
                    }
                    if($items -ne $null)
                    {
                        Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
                        Zip-Folder -Folder $copyTo
                    }
                }
                else 
                {
                    Write-ScriptHost -WriteString ("Failed to find any files in the directory: '{0}'" -f $strDirectory) -ForegroundColor "Yellow"
                    $tempFile = $copyTo + "\NoFiles.txt"    
                    New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
                }
            }
        }
        else 
        {
            Write-ScriptHost -WriteString  ("Doesn't look like this Directory is valid. {0}" -f $strDirectory) -ForegroundColor "Yellow"
            $tempFile = $copyTo + "\NotValidDirectory.txt"
            New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
        }
    
    }

    
    Function Get-LogmanData {
    param(
    [Parameter(Mandatory=$true)][string]$LogmanName,
    [Parameter(Mandatory=$true)][string]$ServerName
    )
        $objLogman = Get-LogmanObject -LogmanName $LogmanName -ServerName $ServerName
        if($objLogman -ne $null)
        {
            switch ($objLogman.Status) 
            {
                "Running" {
                            Write-ScriptHost -WriteString ("Looks like logman {0} is running...." -f $LogmanName)
                            Write-ScriptHost -WriteString ("Going to stop {0} to prevent corruption...." -f $LogmanName)
                            Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                            Copy-LogmanData -ObjLogman $objLogman
                            Write-ScriptHost -WriteString ("Starting Logman {0} again for you...." -f $LogmanName)
                            Start-Logman -LogmanName $LogmanName -ServerName $ServerName
                            Write-ScriptHost -WriteString ("Done starting Logman {0} for you" -f $LogmanName)
                            break;
                            }
                "Stopped" {
                            Write-ScriptHost -WriteString ("Doesn't look like Logman {0} is running, so not going to stop it..." -f $LogmanName)
                            Copy-LogmanData -ObjLogman $objLogman
                            break;
                        }
                Default {
                            Write-ScriptHost -WriteString  ("Don't know what the status of Logman '{0}' is in" -f $LogmanName)
                            Write-ScriptHost -WriteString  ("This is the status: {0}" -f $objLogman.Status)
                            Write-ScriptHost -WriteString ("Going to try stop it just in case...")
                            Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                            Copy-LogmanData -ObjLogman $objLogman
                            Write-ScriptHost -WriteString ("Not going to start it back up again....")
                            Write-ScriptHost -WriteString ("Please start this logman '{0}' if you need to...." -f $LogmanName) -ForegroundColor "Yellow"
                            break; 
                        }
            }
        }
        else 
        {
            Write-ScriptHost -WriteString ("Can't find {0} on {1} ..... Moving on." -f $LogmanName, $ServerName)    
        }
    
    }
    
    Function Get-LogmanStatus {
    param(
    [Parameter(Mandatory=$true)]$RawLogmanData 
    )
        $status = "Status:"
        $stop = "Stopped"
        $run = "Running"
            
        if(-not($RawLogmanData[2].Contains($status)))
        {
            $i = 0
            while((-not($RawLogmanData[$i].Contains($status))) -and ($i -lt ($RawLogmanData.count - 1)))
            {
                $i++
            }
        }
        else {$i = 2}
        $strLine = $RawLogmanData[$i]
    
        if($strLine.Contains($stop)){$currentStatus = $stop}
        elseif($strLine.Contains($run)){$currentStatus = $run}
        else{$currentStatus = "unknown"}
        return $currentStatus
    }
    
    Function Get-LogmanRootPath {
    param(
    [Parameter(Mandatory=$true)]$RawLogmanData
    )
        $rootPath = "Root Path:"
        if(-not($RawLogmanData[3].Contains($rootPath)))
        {
            $i = 0
            while((-not($RawLogmanData[$i].Contains($rootPath))) -and ($i -lt ($RawLogmanData.count - 1)))
            {
                $i++
            }
        }
        else {$i = 3}
    
        $strRootPath = $RawLogmanData[$i]
        $replace = $strRootPath.Replace("Root Path:", "")
        [int]$index = $replace.IndexOf(":") - 1
        $strReturn = $replace.SubString($index)
        return $strReturn
    }
    
    Function Get-LogmanStartDate {
    param(
    [Parameter(Mandatory=$true)]$RawLogmanData
    )
        $strStart_Date = "Start Date:"
        if(-not($RawLogmanData[11].Contains($strStart_Date)))
        {
            $i = 0
            while((-not($RawLogmanData[$i].Contains($strStart_Date))) -and ($i -lt ($RawLogmanData.count - 1)))
            {
                $i++
            }
            #Circular Log collection doesn't contain Start Date
            if(-not($RawLogmanData[$i].Contains($strStart_Date)))
            {
                $strReturn = (Get-Date).AddDays(-1).ToString()
                return $strReturn
            }
        }
        else {$i = 11}
        $strLine = $RawLogmanData[$i]
    
        [int]$index = $strLine.LastIndexOf(" ") + 1 
        $strReturn = $strLine.SubString($index)
        return $strReturn
    }
    
    Function Get-LogmanExt {
    param(
    [Parameter(Mandatory=$true)]$RawLogmanData 
    )
        $strLocation = "Output Location:"
        if(-not($RawLogmanData[15].Contains($strLocation)))
        {
            $i = 0
            while((-not($RawLogmanData[$i].Contains($strLocation))) -and ($i -lt ($RawLogmanData.Count - 1)))
            {
                $i++
            }
        }
        else{ $i = 15}
    
        $strLine = $RawLogmanData[$i]
        [int]$index = $strLine.LastIndexOf(".")
        if($index -ne -1)
        {
            $strExt = $strLine.SubString($index)
        }
        else {
            $strExt = $null
        }
        return $strExt
    }
    
    Function Get-LogmanObject {
    param(
    [Parameter(Mandatory=$true)][string]$LogmanName,
    [Parameter(Mandatory=$true)][string]$ServerName
    )
        $rawDataResults = logman -s $ServerName $LogmanName
        if($rawDataResults[$rawDataResults.Count - 1].Contains("Set was not found."))
        {
            return $null
        }
        else 
        {
            $objLogman = New-Object -TypeName psobject
            $objLogman | Add-Member -MemberType NoteProperty -Name LogmanName -Value $LogmanName
            $objLogman | Add-Member -MemberType NoteProperty -Name Status -Value (Get-LogmanStatus -RawLogmanData $rawDataResults)
            $objLogman | Add-Member -MemberType NoteProperty -Name RootPath -Value (Get-LogmanRootPath -RawLogmanData $rawDataResults)
            $objLogman | Add-Member -MemberType NoteProperty -Name StartDate -Value (Get-LogmanStartDate -RawLogmanData $rawDataResults)
            $objLogman | Add-Member -MemberType NoteProperty -Name Ext -Value (Get-LogmanExt -RawLogmanData $rawDataResults)
            $objLogman | Add-Member -MemberType NoteProperty -Name RestartLogman -Value $false
            $objLogman | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerName
            $objLogman | Add-Member -MemberType NoteProperty -Name RawData -Value $rawDataResults
            $objLogman | Add-Member -MemberType NoteProperty -Name SaveRootLocation -Value $FilePath
    
            return $objLogman
        }
    
    }

    Function  Save-LogmanExperfwizData
    {
        Get-LogmanData -LogmanName $PassedInfo.ExperfwizLogmanName -ServerName $env:COMPUTERNAME
    }

    Function Save-LogmanExmonData
    {
        Get-LogmanData -LogmanName $PassedInfo.ExmonLogmanName -ServerName $env:COMPUTERNAME
    }

    Function Remote-Main {
        Write-ScriptDebug("Function Enter: Remote-Main")
        

        Set-InstanceRunningVars

        $cmdsToRun = @() 
        #############################################
        #                                           #
        #              Exchange 2013 +              #
        #                                           #
        #############################################
        $copyInfo = "-LogPath '{0}' -CopyToThisLocation '{1}'"
        if($Script:localServerObject.Version -ge 15)
        {
            Write-ScriptDebug("Server Version greater than 15")
            if($PassedInfo.EWSLogs)
            {
                if($Script:localServerObject.Mailbox)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\EWS"),($Script:RootCopyToDirectory + "\EWS_BE_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){ $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)}
                    else {$cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)}
                    
                }
                if($Script:localServerObject.CAS)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Ews"),($Script:RootCopyToDirectory + "\EWS_Proxy_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){ $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)}
                    else{$cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)}
                    
                }
            }

            if($PassedInfo.RPCLogs)
            {
                if($Script:localServerObject.Mailbox)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\RPC Client Access"), ($Script:RootCopyToDirectory + "\RCA_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){ $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else{$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                    
                }
                if($Script:localServerObject.CAS)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\RpcHttp"), ($Script:RootCopyToDirectory + "\RCA_Proxy_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){ $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else{$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                    
                }

                if(-not($Script:localServerObject.Edge))
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\RpcHttp"), ($Script:RootCopyToDirectory + "\RPC_Http_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info }
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
            }

            if($Script:localServerObject.CAS -and $PassedInfo.EASLogs)
            {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Eas"), ($Script:RootCopyToDirectory + "\EAS_Proxy_Logs"))
                if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
            }
            
            if($PassedInfo.AutoDLogs)
            {
                if($Script:localServerObject.Mailbox)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\Autodiscover"), ($Script:RootCopyToDirectory + "\AutoD_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else { $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
                if($Script:localServerObject.CAS)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Autodiscover"), ($Script:RootCopyToDirectory + "\AutoD_Proxy_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else { $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info }
                }
            }

            if($PassedInfo.OWALogs)
            {
                if($Script:localServerObject.Mailbox)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\OWA"), ($Script:RootCopyToDirectory + "\OWA_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
                if($Script:localServerObject.CAS)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\OwaCalendar"), ($Script:RootCopyToDirectory + "\OWA_Proxy_Calendar_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else { $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}

                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Owa"), ($Script:RootCopyToDirectory + "\OWA_Proxy_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info }
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
            }

            if($PassedInfo.ADDriverLogs)
            {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\ADDriver"), ($Script:RootCopyToDirectory + "\AD_Driver_Logs"))
                if($PassedInfo.CollectAllLogsBasedOnDaysWorth){ $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
            }

            if($PassedInfo.MapiLogs)
            {
                if($Script:localServerObject.Mailbox -and $Script:localServerObject.Version -eq 15)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\MAPI Client Access"), ($Script:RootCopyToDirectory + "\MAPI_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
                elseif($Script:localServerObject.Mailbox)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\MapiHttp\Mailbox"), ($Script:RootCopyToDirectory + "\MAPI_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth) {$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info} 
                }

                if($Script:localServerObject.CAS)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Mapi"), ($Script:RootCopyToDirectory + "\MAPI_Proxy_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
            }

            if($PassedInfo.ECPLogs)
            {
                if($Script:localServerObject.Mailbox)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\ECP"), ($Script:RootCopyToDirectory + "\ECP_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
                if($Script:localServerObject.CAS)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Ecp"), ($Script:RootCopyToDirectory + "\ECP_Proxy_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){$cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else {$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
            }

            if($Script:localServerObject.Mailbox -and $PassedInfo.SearchLogs)
            {
                $info = ($copyInfo -f ($Script:localExBin + "Search\Ceres\Diagnostics\Logs"), ($Script:RootCopyToDirectory + "\Search_Diag_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info 
                $info = ($copyInfo -f ($Script:localExBin + "Search\Ceres\Diagnostics\ETLTraces"), ($Script:RootCopyToDirectory + "\Search_Diag_ETLs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }
            
            if($PassedInfo.DailyPerformanceLogs)
            {
                #Daily Performace Logs are always by days worth 
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\Diagnostics\DailyPerformanceLogs"), ($Script:RootCopyToDirectory + "\Daily_Performance_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info 
            }

            if($PassedInfo.ManagedAvailability)
            {
                $info = ($copyInfo -f ($Script:localExinstall + "\Logging\Monitoring"),($Script:RootCopyToDirectory + "\ManagedAvailabilityMonitoringLogs"))
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info                
            }
        }
        
        ############################################
        #                                          #
        #              Exchange 2010               #
        #                                          #
        ############################################
        if($Script:localServerObject.Version -eq 14)
        {
            if($Script:localServerObject.CAS)
            {
                if($PassedInfo.RPCLogs)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\RPC Client Access"), ($Script:RootCopyToDirectory + "\RCA_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){ $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info}
                    else{$cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info}
                }
                if($PassedInfo.EWSLogs)
                {
                    $info = ($copyInfo -f ($Script:localExinstall + "Logging\EWS"),($Script:RootCopyToDirectory + "\EWS_BE_Logs"))
                    if($PassedInfo.CollectAllLogsBasedOnDaysWorth){ $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)}
                    else {$cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)}
                }
            }
        }

        ############################################
        #                                          #
        #          All Exchange Versions           #
        #                                          #
        ############################################
        if($PassedInfo.AnyTransportSwitchesEnabled -and $Script:localServerObject.TransportInfoCollect)
        {
            if($PassedInfo.MessageTrackingLogs -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.CASOnly)))
            {
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.MessageTrackingLogPath), ($Script:RootCopyToDirectory + "\Message_Tracking_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if($PassedInfo.HubProtocolLogs -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.CASOnly)))
            {
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\Hub_Receive_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\Hub_Send_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info 
            }
            if($PassedInfo.HubConnectivityLogs -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.CASOnly)))
            {
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.ConnectivityLogPath), ($Script:RootCopyToDirectory + "\Hub_Connectivity_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }
            if($PassedInfo.QueueInformationThisServer -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.CASOnly)))
            {
                $create = $Script:RootCopyToDirectory + "\Queue_Data"
                New-Folder -NewFolder $create -IncludeDisplayCreate $true
                $saveLocation = $create + "\Current_Queue_Info"
                Save-DataInfoToFile -dataIn ($Script:localServerObject.TransportInfo.QueueData) -SaveToLocation $saveLocation
                if($Script:localServerObject.Version -ge 15 -and $Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath -ne $null)
                {
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath), ($Script:RootCopyToDirectory + "\Queue_V15_Data"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                }
            }
            if($PassedInfo.ReceiveConnectors)
            {
                $create = $Script:RootCopyToDirectory + "\Connectors"
                New-Folder -NewFolder $create -IncludeDisplayCreate $true
                $saveLocation = ($create + "\{0}_Receive_Connectors") -f $env:COMPUTERNAME
                Save-DataInfoToFile -dataIn ($Script:localServerObject.TransportInfo.ReceiveConnectorData) -SaveToLocation $saveLocation
            }
            if($PassedInfo.TransportConfig)
            {
                if($Script:localServerObject.Version -ge 15 -and (-not($Script:localServerObject.Edge)))
                {
                    $items = @()
                    $items += $Script:localExBin + "\EdgeTransport.exe.config" 
                    $items += $Script:localExBin + "\MSExchangeFrontEndTransport.exe.config" 
                    $items += $Script:localExBin + "\MSExchangeDelivery.exe.config" 
                    $items += $Script:localExBin + "\MSExchangeSubmission.exe.config"

                }
                else 
                {
                    $items = @()
                    $items += $Script:localExBin + "\EdgeTransport.exe.config"
                }

                Copy-BulkItems -CopyToLocation ($Script:RootCopyToDirectory + "\Transport_Configuration") -ItemsToCopyLocation $items
            }
            #Exchange 2013+ only 
            if($Script:localServerObject.Version -ge 15 -and (-not($Script:localServerObject.Edge)))
            {
                if($PassedInfo.FrontEndConnectivityLogs -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.MailboxOnly)))
                {
                    Write-ScriptDebug("Collecting FrontEndConnectivityLogs")
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.ConnectivityLogPath), ($Script:RootCopyToDirectory + "\FE_Connectivity_Logs"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                }
                if($PassedInfo.FrontEndProtocolLogs -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.MailboxOnly)))
                {
                    Write-ScriptDebug("Collecting FrontEndProtocolLogs")
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\FE_Receive_Protocol_Logs"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\FE_Send_Protocol_Logs"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                }
                if($PassedInfo.MailboxConnectivityLogs -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.CASOnly)))
                {
                    Write-ScriptDebug("Collecting MailboxConnectivityLogs")
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath + "\Delivery"), ($Script:RootCopyToDirectory + "\MBX_Delivery_Connectivity_Logs"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath + "\Submission"), ($Script:RootCopyToDirectory + "\MBX_Submission_Connectivity_Logs"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                }
                if($PassedInfo.MailboxProtocolLogs -and (-not ($Script:localServerObject.Version -eq 15 -and $Script:localServerObject.CASOnly)))
                {
                    Write-ScriptDebug("Collecting MailboxProtocolLogs")
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\MBX_Receive_Protocol_Logs"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                    $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\MBX_Send_Protocol_Logs"))
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                }
            }

        }

        if($PassedInfo.ImapLogs)
        {
            Write-ScriptDebug("Collecting IMAP Logs")
            $info = ($copyInfo -f ($Script:localServerObject.ImapLogsLocation), ($Script:RootCopyToDirectory + "\Imap_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if($PassedInfo.PopLogs)
        {
            Write-ScriptDebug("Collecting POP Logs")
            $info = ($copyInfo -f ($Script:localServerObject.PopLogsLocation), ($Script:RootCopyToDirectory + "\Pop_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info 
        }

        if($PassedInfo.IISLogs -and (Set-IISDirectoryInfo))
        {
            foreach($directory in $Script:IISLogDirectory.Split(";"))
            {
                $copyTo = "{0}\IIS_{1}_Logs" -f $Script:RootCopyToDirectory, ($directory.Substring($directory.LastIndexOf("\") + 1))
                $info = ($copyInfo -f $directory, $copyTo) 
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            $info = ($copyInfo -f ($env:SystemRoot +"\System32\LogFiles\HTTPERR"), ($Script:RootCopyToDirectory + "\HTTPERR_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info 
        }

        if($PassedInfo.ServerInfo)
        {
            $cmdsToRun += "Save-ServerInfoData"
        }

        if($PassedInfo.Experfwiz)
        {
            $cmdsToRun += "Save-LogmanExperfwizData"
        }

        if($PassedInfo.Exmon)
        {
            $cmdsToRun += "Save-LogmanExmonData"
        }

        $cmdsToRun += "Save-WindowsEventLogs"

        #Execute the cmds 
        foreach($cmd in $cmdsToRun)
        {
            Write-ScriptDebug("cmd: {0}" -f $cmd)
            Invoke-Expression $cmd
        }
 
        if((-not($PassedInfo.ExchangeServerInfo)) -and $env:COMPUTERNAME -ne ($PassedInfo.HostExeServerName))
        {
            #Zip it all up 
            Zip-Folder -Folder $Script:RootCopyToDirectory -ZipItAll $true -AddCompressedSize $false 
        }
        
    }

    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try 
    {
        $Script:VerboseFunctionCaller = ${Function:Write-ScriptDebug}
        $Script:HostFunctionCaller = ${Function:Write-ScriptHost}
        if($PassedInfo.ByPass -ne $true)
        {
            Remote-Main
        }
        else 
        {
            Write-ScriptDebug("Loading common functions")
        }
        
    }
    catch 
    {
        Write-ScriptHost -WriteString ("An error occurred in Remote-Functions") -ForegroundColor "Red"
        Write-ScriptHost -WriteString ("Error Exception: {0}" -f $Error[0].Exception) -ForegroundColor "Red"
        Write-ScriptHost -WriteString ("Error Stack: {0}" -f $Error[0].ScriptStackTrace) -ForegroundColor "Red"
    }
    finally
    {
        $ErrorActionPreference = $oldErrorAction
        Write-ScriptDebug("Exiting: Remote-Functions")
        Write-ScriptDebug("[double]TotalBytesSizeCopied: {0} | [double]TotalBytesSizeCompressed: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3} | [double]FreeSpaceMinusCopiedAndCompressedGB: {4}" -f $Script:TotalBytesSizeCopied,
        $Script:TotalBytesSizeCompressed, 
        $Script:AdditionalFreeSpaceCushionGB, 
        $Script:CurrentFreeSpaceGB, 
        $Script:FreeSpaceMinusCopiedAndCompressedGB)
    }
}

Function Get-ExchangeObjectServerData{
param(
[Parameter(Mandatory=$true)][array]$Servers 
)
    Write-ScriptDebug("Enter Function: Get-ExchangeObjectServerData")
    $serverObjects = @()
    foreach($server in $Servers)
    {
        $obj = Get-ExchangeBasicServerObject -ServerName $server 

        if($obj.Hub)
        {
            if($obj.Version -ge 15)
            {
                $hubInfo = Get-TransportService $server 
            }
            else 
            {
                $hubInfo = Get-TransportServer $server
            }
            $obj | Add-Member -MemberType NoteProperty -Name TransportServerInfo -Value $hubInfo
        }
        if($obj.CAS)
        {
            if($obj.Version -ge 16)
            {
                $casInfo = Get-ClientAccessService $server
            }
            else 
            {
                $casInfo = Get-ClientAccessServer $server 
            }
            $obj | Add-Member -MemberType NoteProperty -Name CAServerInfo -Value $casInfo
        }
        if($obj.Mailbox)
        {
            $obj | Add-Member -MemberType NoteProperty -Name MailboxServerInfo -Value (Get-MailboxServer $server)
        }
        if($obj.Version -ge 15)
        {
            $obj | Add-Member -MemberType NoteProperty -Name HealthReport -Value (Get-HealthReport $server) 
            $obj | Add-Member -MemberType NoteProperty -Name ServerComponentState -Value (Get-ServerComponentState $server)
            $obj | Add-Member -MemberType NoteProperty -Name serverMonitoringOverride -Value (Get-serverMonitoringOverride $server)
            $obj | Add-Member -MemberType NoteProperty -Name ServerHealth -Value (Get-ServerHealth $server)
        }

        $serverObjects += $obj 
    }

    return $serverObjects 
}

#Template Master: https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Start-JobManager/Start-JobManager.ps1
Function Start-JobManager {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][array]$ServersWithArguments,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [Parameter(Mandatory=$false)][string]$JobBatchName,
    [Parameter(Mandatory=$false)][bool]$DisplayReceiveJob = $true,
    [Parameter(Mandatory=$false)][bool]$DisplayReceiveJobInVerboseFunction, 
    [Parameter(Mandatory=$false)][bool]$DisplayReceiveJobInCorrectFunction,
    [Parameter(Mandatory=$false)][bool]$NeedReturnData = $false,
    [Parameter(Mandatory=$false)][scriptblock]$VerboseFunctionCaller,
    [Parameter(Mandatory=$false)][scriptblock]$HostFunctionCaller
    )
    
    #Function Version 1.3
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
    
    Function Write-HostWriter {
    param(
    [Parameter(Mandatory=$true)][string]$WriteString 
    )
        if($HostFunctionCaller -eq $null)
        {
            Write-Host $WriteString
        }
        else
        {
            &$HostFunctionCaller $WriteString    
        }
    }
    
    $passedVerboseFunctionCaller = $false
    $passedHostFunctionCaller = $false
    if($VerboseFunctionCaller -ne $null){$passedVerboseFunctionCaller = $true}
    if($HostFunctionCaller -ne $null){$passedHostFunctionCaller = $true}
    
    Function Write-ReceiveJobData {
    param(
    [Parameter(Mandatory=$true)][array]$ReceiveJobData
    )
        $returnJob = [string]::Empty
        foreach($job in $ReceiveJobData)
        {
            if($job["Verbose"])
            {
                Write-VerboseWriter($job["Verbose"])
            }
            elseif($job["Host"])
            {
                Write-HostWriter($job["Host"])
            }
            elseif($job["ReturnObject"])
            {
                $returnJob = $job["ReturnObject"]
            }
            else 
            {
                Write-VerboseWriter("Unable to determine the key for the return type.")    
            }
        }
        return $returnJob
    }
    
    Function Start-Jobs {
        Write-VerboseWriter("Calling Start-Jobs")
        foreach($serverObject in $ServersWithArguments)
        {
            $server = $serverObject.ServerName
            $argumentList = $serverObject.ArgumentList
            Write-VerboseWriter("Starting job on server {0}" -f $server)
            Invoke-Command -ComputerName $server -ScriptBlock $ScriptBlock -ArgumentList $argumentList -AsJob -JobName $server | Out-Null
        }
    }
    
    Function Confirm-JobsPending {
        $jobs = Get-Job
        if($jobs -ne $null)
        {
            return $true 
        }
        return $false
    }
    
    Function Wait-JobsCompleted {
        Write-VerboseWriter("Calling Wait-JobsCompleted")
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        $returnData = @{}
        while(Confirm-JobsPending)
        {
            $completedJobs = Get-Job | Where-Object {$_.State -ne "Running"}
            if($completedJobs -eq $null)
            {
                Start-Sleep 1 
                continue 
            }
    
            foreach($job in $completedJobs)
            {
                $receiveJobNull = $false 
                $jobName = $job.Name 
                Write-VerboseWriter("Job {0} received. State: {1} | HasMoreData: {2}" -f $job.Name, $job.State,$job.HasMoreData)
                if($NeedReturnData -eq $false -and $DisplayReceiveJob -eq $false -and $job.HasMoreData -eq $true)
                {
                    Write-VerboseWriter("This job has data and you provided you didn't want to return it or display it.")
                }
                $receiveJob = Receive-Job $job 
                Remove-Job $job
                if($receiveJob -eq $null)
                {
                    $receiveJobNull = $True 
                    Write-VerboseWriter("Job {0} didn't have any receive job data" -f $jobName)
                }
                if($DisplayReceiveJobInVerboseFunction -and(-not($receiveJobNull)))
                {
                    Write-VerboseWriter("[JobName: {0}] : {1}" -f $jobName, $receiveJob)
                }
                elseif($DisplayReceiveJobInCorrectFunction -and (-not ($receiveJobNull)))
                {
                    $returnJobData = Write-ReceiveJobData -ReceiveJobData $receiveJob
                    if($returnJobData -ne $null)
                    {
                        $returnData.Add($jobName, $returnJobData)
                    }
                }
                elseif($DisplayReceiveJob -and (-not($receiveJobNull)))
                {
                    Write-HostWriter $receiveJob
                }
                if($NeedReturnData -and (-not($DisplayReceiveJobInCorrectFunction)))
                {
                    $returnData.Add($job.Name, $receiveJob)
                }
            }
        }
        $timer.Stop()
        Write-VerboseWriter("Waiting for jobs to complete took {0} seconds" -f $timer.Elapsed.TotalSeconds)
        if($NeedReturnData)
        {
            return $returnData
        }
        return $null 
    }
    
    [System.Diagnostics.Stopwatch]$timerMain = [System.Diagnostics.Stopwatch]::StartNew()
    Write-VerboseWriter("Calling Start-JobManager")
    Write-VerboseWriter("Passed: [bool]DisplayReceiveJob: {0} | [string]JobBatchName: {1} | [bool]DisplayReceiveJobInVerboseFunction: {2} | [bool]NeedReturnData:{3} | [scriptblock]VerboseFunctionCaller: {4} | [scriptblock]HostFunctionCaller: {5}" -f $DisplayReceiveJob,
    $JobBatchName,
    $DisplayReceiveJobInVerboseFunction,
    $NeedReturnData,
    $passedVerboseFunctionCaller,
    $passedHostFunctionCaller)
    
    Start-Jobs
    $data = Wait-JobsCompleted
    $timerMain.Stop()
    Write-VerboseWriter("Exiting: Start-JobManager | Time in Start-JobManager: {0} seconds" -f $timerMain.Elapsed.TotalSeconds)
    if($NeedReturnData)
    {
        return $data
    }
    return $null
}

Function Write-ExchangeDataOnMachines {

    Function Write-ExchangeData {
        param(
        [Parameter(Mandatory=$true)][object]$PassedInfo
        )

                $server = $PassedInfo.ServerObject 
                $location = $PassedInfo.Location 
                Function Write-Data{
                param(
                [Parameter(Mandatory=$true)][object]$DataIn, 
                [Parameter(Mandatory=$true)][string]$FilePathNoEXT
                )
                    $DataIn | Format-List * > "$FilePathNoEXT.txt"
                    $DataIn | Export-Clixml "$FilePathNoEXT.xml"
                }
                $exchBin = "{0}\Bin" -f $PassedInfo.InstallDirectory
                $configFiles = Get-ChildItem $exchBin | Where-Object{$_.Name -like "*.config"}
                $copyTo = "{0}\Config" -f $location 
                $configFiles | ForEach-Object{ Copy-Item $_.VersionInfo.FileName $copyTo}

                $copyServerComponentStatesRegistryTo = "{0}\regServerComponentStates.TXT" -f $location 
                reg query HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\ServerComponentStates /s > $copyServerComponentStatesRegistryTo

                Write-Data -DataIn $server.ExchangeServer -FilePathNoEXT ("{0}\{1}_ExchangeServer" -f $location, $env:COMPUTERNAME)

                Get-Command exsetup | ForEach-Object{$_.FileVersionInfo} > ("{0}\{1}_GCM.txt" -f $location, $env:COMPUTERNAME)

                if($server.Hub)
                {
                    Write-Data -DataIn $server.TransportServerInfo -FilePathNoEXT ("{0}\{1}_TransportServer" -f $location, $env:COMPUTERNAME)
                }
                if($server.CAS)
                {
                    Write-Data -DataIn $server.CAServerInfo -FilePathNoEXT ("{0}\{1}_ClientAccessServer" -f $location, $env:COMPUTERNAME)
                }
                if($server.Mailbox)
                {
                    Write-Data -DataIn $server.MailboxServerInfo -FilePathNoEXT ("{0}\{1}_MailboxServer" -f $location, $env:COMPUTERNAME)
                }
                if($server.Version -ge 15)
                {
                    Write-Data -DataIn $server.HealthReport -FilePathNoEXT ("{0}\{1}_HealthReport" -f $location, $env:COMPUTERNAME)
                    Write-Data -DataIn $server.ServerComponentState -FilePathNoEXT ("{0}\{1}_ServerComponentState" -f $location, $env:COMPUTERNAME)
                    Write-Data -DataIn $server.serverMonitoringOverride -FilePathNoEXT ("{0}\{1}_serverMonitoringOverride" -f $location, $env:COMPUTERNAME)
                    Write-Data -DataIn $server.ServerHealth -FilePathNoEXT ("{0}\{1}_ServerHealth" -f $location, $env:COMPUTERNAME)                    
                }

                #Exchange Web App Pools 
                $windir = $env:windir
                $appCmd = "{0}\system32\inetsrv\appcmd.exe" -f $windir
                if(Test-Path $appCmd)
                {
                    $appPools = &$appCmd list apppool 
                    $exchangeAppPools = @()
                    foreach($appPool in $appPools)
                    {
                        $startIndex = $appPool.IndexOf('"') + 1
                        $appPoolName = $appPool.SubString($startIndex,
                            ($appPool.SubString($startIndex).IndexOf('"')))
                        if($appPoolName.StartsWith("MSExchange"))
                        {
                            $exchangeAppPools += $appPoolName
                        }
                    }

                    $configFileListLocation = @() 
                    foreach($exchAppPool in $exchangeAppPools)
                    {
                        $config = &$appCmd list apppool $exchAppPool /text:CLRConfigFile
                        $allResult = &$appCmd list apppool $exchAppPool /text:*
                        if(($config -ne $null -and $config -ne [string]::Empty) -and 
                            (Test-Path $config) -and (!($configFileListLocation.Contains($config.ToLower()))))
                        {
                            $configFileListLocation += $config.ToLower()
                        }
                        $saveLocation = "{0}\WebAppPools\{1}_{2}.txt" -f $location, $env:COMPUTERNAME, $exchAppPool
                        $allResult | Format-List * > $saveLocation 
                    }

                    foreach($configFile in $configFileListLocation)
                    {
                        $content = Get-Content $configFile
                        $saveLocation = "{0}\WebAppPools\{1}_{2}" -f $location, $env:COMPUTERNAME,
                            $configFile.Substring($configFile.LastIndexOf("\") + 1)
                        $content > $saveLocation
                    }
                }

        }


    $exchangeServerData = Get-ExchangeObjectServerData -Servers $Script:ValidServers 
    #if single server or Exchange 2010 where invoke-command doesn't work 
    if($Script:ValidServers.count -gt 1)
    {
        #Need to have install directory run through the loop first as it could be different on each server
        $serversObjectListInstall = @() 
        foreach($server in $exchangeServerData)
        {
            $serverObject = New-Object PSCustomObject 
            $serverObject | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName
            $serverObject | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $true
            $serversObjectListInstall += $serverObject
        }
        $serverInstallDirectories = Start-JobManager -ServersWithArguments $serversObjectListInstall -ScriptBlock ${Function:Get-ExchangeInstallDirectory} -VerboseFunctionCaller ${Function:Write-ScriptDebug} -NeedReturnData $true -DisplayReceiveJobInCorrectFunction $true -JobBatchName "Exchange Install Directories for Write-ExchangeDataOnMachines"
    
    
        $serverListCreateDirectories = @() 
        $serverListDumpData = @() 
        $serverListZipData = @() 
    
        foreach($server in $exchangeServerData)
        {
            $location = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $server.ServerName 

            #Create Directory 
            $serverCreateDirectory = New-Object PSCustomObject 
            $serverCreateDirectory | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName
            $argumentObject = New-Object PSCustomObject 
            [array]$value = "{0}{1}\Exchange_Server_Data\Config" -f $Script:RootFilePath, $server.ServerName
            $value += "{0}{1}\Exchange_Server_Data\WebAppPools" -f $Script:RootFilePath, $server.ServerName
            $argumentObject | Add-Member -MemberType NoteProperty -Name NewFolders -Value $value
            $serverCreateDirectory | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $argumentObject
            $serverListCreateDirectories += $serverCreateDirectory

            #Write Data 
            $argumentList = New-Object PSCustomObject 
            $argumentList | Add-Member -MemberType NoteProperty -Name ServerObject -Value $server
            $argumentList | Add-Member -MemberType NoteProperty -Name Location -Value $location
            $argumentList | Add-Member -MemberType NoteProperty -Name InstallDirectory -Value $serverInstallDirectories[$server.ServerName]
            $serverDumpData = New-Object PSCustomObject 
            $serverDumpData | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName 
            $serverDumpData | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $argumentList
            $serverListDumpData += $serverDumpData

            #Zip data if not local cause we might have more stuff to run 
            if($server.ServerName -ne $env:COMPUTERNAME)
            {
                $folder = "{0}{1}" -f $Script:RootFilePath, $server.ServerName
                $parameters = $folder, $true, $false
                $serverZipData = New-Object PSCustomObject 
                $serverZipData | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName
                $serverZipData | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $parameters  
                $serverListZipData += $serverZipData 
            }
        }

        Write-ScriptDebug("Getting New-Folder string to create Script Block")
        $newFolderString = (${Function:New-Folder}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
        Write-ScriptDebug("Creating script block")
        $newFolderScriptBlock = [scriptblock]::Create($newFolderString)
        Write-ScriptDebug("Calling job for folder creation")
        Start-JobManager -ServersWithArguments $serverListCreateDirectories -ScriptBlock $newFolderScriptBlock -VerboseFunctionCaller ${Function:Write-ScriptDebug} -DisplayReceiveJobInCorrectFunction $true -JobBatchName "Creating folders for Write-ExchangeDataOnMachines"
        Write-ScriptDebug("Calling job for Exchange Data Write")
        Start-JobManager -ServersWithArguments $serverListDumpData -ScriptBlock ${Function:Write-ExchangeData} -VerboseFunctionCaller ${Function:Write-ScriptDebug} -DisplayReceiveJob $false -JobBatchName "Write the data for Write-ExchangeDataOnMachines"
        Write-ScriptDebug("Calling job for Zipping the data")
        Start-JobManager -ServersWithArguments $serverListZipData -ScriptBlock ${Function:Compress-Folder} -VerboseFunctionCaller ${Function:Write-ScriptDebug} -JobBatchName "Zipping up the data for Write-ExchangeDataOnMachines"

    }
    else 
    {
        if($exinstall -eq $null)
        {
            $exinstall = Get-ExchangeInstallDirectory -VerboseFunctionCaller ${Function:Write-ScriptDebug} -HostFunctionCaller ${Function:Write-ScriptHost}
        }
        $location = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $exchangeServerData.ServerName
        [array]$createFolders = @(("{0}\Config" -f $location),("{0}\WebAppPools" -f $location))
        New-Folder -NewFolders $createFolders -IncludeDisplayCreate $true
        $passInfo = New-Object PSCustomObject 
        $passInfo | Add-Member -MemberType NoteProperty -Name ServerObject -Value $exchangeServerData 
        $passInfo | Add-Member -MemberType NoteProperty -Name Location -Value $location
        $passInfo | Add-Member -MemberType NoteProperty -Name InstallDirectory -Value $exinstall 
        Write-ScriptDebug("Writing out the Exchange data")
        Write-ExchangeData -PassedInfo $passInfo 
        $folder = "{0}{1}" -f $Script:RootFilePath, $exchangeServerData.ServerName
                
    }
}
Function Write-DataOnlyOnceOnLocalMachine {
    Write-ScriptDebug("Enter Function: Write-DataOnlyOnceOnLocalMachine")
    Write-ScriptDebug("Writting only once data")

    $RootCopyToDirectory = Set-RootCopyDirectory

    if($GetVdirs -and (-not($Script:EdgeRoleDetected)))
    {
        $target = $RootCopyToDirectory  + "\ConfigNC_msExchVirtualDirectory_All.CSV"
        $data = (Get-VdirsLDAP)
        $data | Sort-Object -Property Server | Export-Csv $target -NoTypeInformation
    }

    if($OrganizationConfig)
    {
        $target = $RootCopyToDirectory + "\OrganizationConfig"
        $data = Get-OrganizationConfig
        Save-DataInfoToFile -dataIn (Get-OrganizationConfig) -SaveToLocation $target
    }

    if($DAGInformation -and (-not($Script:EdgeRoleDetected)))
    {
        $data = Get-DAGInformation
        if($data -ne $null)
        {
            $dagName = $data.DAGInfo.Name 
            $create =  $RootCopyToDirectory  + "\" + $dagName + "_DAG_MDB_Information"
            New-Folder -NewFolder $create -IncludeDisplayCreate $true 
            $saveLocation = $create + "\{0}"
                            
            Save-DataInfoToFile -dataIn ($data.DAGInfo) -SaveToLocation ($saveLocation -f ($dagName +"_DAG_Info"))
            
            Save-DataInfoToFile -dataIn ($data.DAGNetworkInfo) -SaveToLocation ($saveLocation -f ($dagName + "DAG_Network_Info"))
            
            foreach($mdb in $data.AllMdbs)
            {
                Save-DataInfoToFile -dataIn ($mdb.MDBInfo) -SaveToLocation ($saveLocation -f ($mdb.MDBName + "_DB_Info"))
                Save-DataInfoToFile -dataIn ($mdb.MDBCopyStatus) -SaveToLocation ($saveLocation -f ($mdb.MDBName + "_DB_CopyStatus"))
            }
    
            Zip-Folder -Folder $create -AddCompressedSize $false 
        }
    }

    if($SendConnectors)
    {
        $create = $RootCopyToDirectory + "\Connectors"
        New-Folder -NewFolder $create -IncludeDisplayCreate $true
        $saveLocation = $create + "\Send_Connectors"
        Save-DataInfoToFile -dataIn (Get-SendConnector) -SaveToLocation $saveLocation
    }

    Zip-Folder -Folder $RootCopyToDirectory -ZipItAll $true -AddCompressedSize $false 
    Write-ScriptDebug("Exiting Function: Write-DataOnlyOnceOnLocalMachine")
}

Function Start-WriteExchangeDataOnMachines {
    if($ExchangeServerInfo)
    {
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-ExchangeDataOnMachines
        $timer.Stop()
        Write-ScriptDebug("Write-ExchangeDataOnMachines total time took {0} seconds" -f $timer.Elapsed.TotalSeconds)
    }
}

##################Main###################
Function Main {

    <#
    Added the ability to call functions from within a bundled function so i don't have to duplicate work. 
    Loading the functions into memory by using the '.' allows me to do this, 
    providing that the calling of that function doesn't do anything of value when doing this. 
    #>
    $obj = New-Object PSCustomObject 
    $obj | Add-Member -MemberType NoteProperty -Name ByPass -Value $true 
    . Remote-Functions -PassedInfo $obj 
    Start-Sleep 1
    Write-Disclaimer
    Test-PossibleCommonScenarios
    Test-NoSwitchesProvided
    if(-not (Confirm-Administrator))
    {
        Write-ScriptHost -WriteString ("Hey! The script needs to be executed in elevated mode. Start the Exchange Mangement Shell as an Administrator.") -ForegroundColor "Yellow"
        exit 
    }
    if(-not(Confirm-ExchangeShell -LoadExchangeVariables $false))
    {
        Write-ScriptHost -WriteString ("It appears that you are not on an Exchange 2010 or newer server. Sorry I am going to quit.") -ShowServer $false 
        exit
    }

    $Script:RootFilePath = "{0}\{1}\" -f $FilePath, (Get-Date -Format yyyyMd)
    if((Confirm-LocalEdgeServer) -and $Servers -ne $null)
    {
        #If we are on an Exchange Edge Server, we are going to treat it like a single server on purpose as we recommend that the Edge Server is a non domain joined computer. 
        #Because it isn't a domain joined computer, we can't use remote execution
        Write-ScriptHost -WriteString ("Determined that we are on an Edge Server, we can only use locally collection for this role.") -ForegroundColor "Yellow"
        $Script:EdgeRoleDetected = $true 
        $Servers = $null
    }

    if($Servers -ne $null)
    {
        
        #possible to return null or only a single server back (localhost)
        $Script:ValidServers = Test-RemoteExecutionOfServers -ServerList $Servers
        if($Script:ValidServers -ne $null)
        {
            $Script:ValidServers = Test-DiskSpace -Servers $Script:ValidServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize
            Verify-LocalServerIsUsed $Script:ValidServers

            $argumentList = Get-ArgumentList -Servers $Script:ValidServers
            #I can do a try catch here, but i also need to do a try catch in the remote so i don't end up failing here and assume the wrong failure location
            try 
            {
                Invoke-Command -ComputerName $Script:ValidServers -ScriptBlock ${Function:Remote-Functions} -ArgumentList $argumentList -ErrorAction Stop
            }
            catch 
            {
                Write-Error "An error has occurred attempting to call Invoke-Command to do a remote collect all at once. Please notify ExToolsFeedback@microsoft.com of this issue. Stopping the script."
                exit
            }
            
            Start-WriteExchangeDataOnMachines
            Write-DataOnlyOnceOnLocalMachine
            $LogPaths = Get-RemoteLogLocation -Servers $Script:ValidServers -RootPath $Script:RootFilePath
            if((-not($SkipEndCopyOver)) -and (Test-DiskSpaceForCopyOver -LogPathObject $LogPaths -RootPath $Script:RootFilePath))
            {
                Write-ScriptHost -ShowServer $false -WriteString (" ") 
                Write-ScriptHost -ShowServer $false -WriteString ("Copying over the data may take some time depending on the network")
                foreach($svr in $LogPaths)
                {
                    #Don't want to do the local host
                    if($svr.ServerName -ne $env:COMPUTERNAME)
                    {
                        $remoteCopyLocation = "\\{0}\{1}" -f $svr.ServerName, ($svr.ZipFolder.Replace(":","$"))
                        Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Copying File {1}...." -f $svr.ServerName, $remoteCopyLocation) 
                        Copy-Item -Path $remoteCopyLocation -Destination $Script:RootFilePath
                        Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Done copying file" -f $svr.ServerName)
                    }
                    
                }

            }
            else 
            {
                Write-ScriptHost -ShowServer $false -WriteString (" ")
                Write-ScriptHost -ShowServer $false -WriteString ("Please collect the following files from these servers and upload them: ")
                foreach($svr in $LogPaths)
                {
                    Write-ScriptHost -ShowServer $false -WriteString ("Server: {0} Path: {1}" -f $svr.ServerName, $svr.ZipFolder) 
                }
            }
        }
        else 
        {
            #We have failed to do invoke-command on all the servers.... so we are going to do the same logic locally
            Write-ScriptHost -ShowServer $false -WriteString ("Failed to do remote collection for all the servers in the list...") -ForegroundColor "Yellow"
            #want to test local server's free space first before moving to just collecting the data 
            if((Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize) -eq $null)
            {
                Write-ScriptHost -ShowServer $false -WriteString ("Failed to have enough space available locally as well. We can't continue with the data collection") -ForegroundColor "Yellow" 
                exit 
            }
            if((Enter-YesNoLoopAction -Question "Do you want to collect from the local server only?" -YesAction {return $true} -NoAction {return $false}))
            {
                Remote-Functions -PassedInfo (Get-ArgumentList -Servers $env:COMPUTERNAME)
                $Script:ValidServers = @($env:COMPUTERNAME)
                Start-WriteExchangeDataOnMachines
                Write-DataOnlyOnceOnLocalMachine
            }
            
        }
    }

    else 
    {
        if((Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize) -eq $null)
        {
            exit
        }
        if(-not($Script:EdgeRoleDetected))
        {
            Write-ScriptHost -ShowServer $false -WriteString ("Note: Remote Collection is now possible for Windows Server 2012 and greater on the remote machine. Just use the -Servers paramater with a list of Exchange Server names") -ForegroundColor "Yellow"
            Write-ScriptHost -ShowServer $false -WriteString ("Going to collect the data locally")
        }
        Remote-Functions -PassedInfo (Get-ArgumentList -Servers $env:COMPUTERNAME)
        $Script:ValidServers = @($env:COMPUTERNAME)
        Start-WriteExchangeDataOnMachines
        Write-DataOnlyOnceOnLocalMachine 
    }

    Write-FeedBack
        
}

Main 