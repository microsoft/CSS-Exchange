#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Confirm-ExchangeShell/Confirm-ExchangeShell.ps1
Function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][bool]$LoadExchangeShell = $true,
    [Parameter(Mandatory=$false)][bool]$LoadExchangeVariables = $true,
    [Parameter(Mandatory=$false)][bool]$ByPassLocalExchangeServerTest = $false,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.6
    <#
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-HostWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
        
    $passed = $false 
    Write-VerboseWriter("Calling: Confirm-ExchangeShell")
    Write-VerboseWriter("Passed: [bool]LoadExchangeShell: {0} | [bool]LoadExchangeVariables: {1} | [bool]ByPassLocalExchangeServerTest: {2}" -f $LoadExchangeShell,
    $LoadExchangeVariables, $ByPassLocalExchangeServerTest)
    #Test that we are on Exchange 2010 or newer
    if(($isLocalExchangeServer = (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup')) -or
    ($isLocalExchangeServer = (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup')) -or
    $ByPassLocalExchangeServerTest)
    {
        Write-VerboseWriter("We are on Exchange 2010 or newer")
        if((Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\EdgeTransportRole') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'))
        {
            Write-VerboseWriter("We are on Exchange Edge Transport Server")
            $IsEdgeTransport = $true
        }
        try 
        {
            if(((Get-PSSession | Where-Object {($_.Availability -eq 'Available') -and
                ($_.ConfigurationName -eq 'Microsoft.Exchange')}).Count -eq 0) -and
                ((Get-Module -Name RemoteExchange).Count -eq 1))
            {
                Write-VerboseWriter("Removing RemoteExchange module")
                Remove-Module -Name RemoteExchange
                $currentPSModules = Get-Module
                foreach ($PSModule in $currentPSModules)
                {
                    if(($PSModule.ModuleType -eq "Script") -and
                        ($PSModule.ModuleBase -like "*\Microsoft\Exchange\RemotePowerShell\*"))
                    {
                        Write-VerboseWriter("Removing module {0} for implicit remoting" -f $PSModule.Name)
                        Remove-Module -Name $PSModule.Name
                    }
                }
            }
    
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
            if($LoadExchangeShell -and
                $isLocalExchangeServer)
            {
                Write-HostWriter "Loading Exchange PowerShell Module..."
                try
                {
                    if($watchErrors)
                    {
                        $currentErrors = $Error.Count
                    }
                    if($IsEdgeTransport)
                    {
                        [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exshell.psc1" -ErrorAction Stop
                        ForEach($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn)
                        {
                            Write-VerboseWriter("Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name)
                            Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                        }
                        Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                        $passed = $true #We are just going to assume this passed.
                    }
                    else
                    {
                        Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                        Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                        $passed = $true #We are just going to assume this passed.
                    }
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
                $passed -and
                $isLocalExchangeServer)
            {
                #Diff from master not using Get-ExchangeInstallDirectory because of required functions
                if($ExInstall -eq $null -or $ExBin -eq $null)
                {
                    if(Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup')
                    {
                        $Global:ExInstall = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath
                    }
                    else
                    {
                        $Global:ExInstall = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
                    }
        
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