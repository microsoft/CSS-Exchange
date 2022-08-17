# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1
. $PSScriptRoot\Invoke-CatchActionErrorLoop.ps1

function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity,

        [Parameter(Mandatory = $false)]
        [bool]$LoadExchangeShell = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IgnoreToolsIdentity = $false,

        [Parameter(Mandatory = $false)]
        [bool]$AllowPSSessionUsage = $false,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CatchActionFunction
    )

    begin {
        function Test-GetExchangeServerCmdletError {
            param(
                [Parameter(Mandatory = $true)]
                [object]$ThisError
            )

            if ($ThisError.FullyQualifiedErrorId -ne "CommandNotFoundException") {
                Write-Warning "Failed to find '$Identity' as an Exchange Server."
                return $true
            }
            return $false
        }
        $activeExchangePSSessionFound = $false
        $currentErrors = $Error.Count
        $passed = $false
        $edgeTransportKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed: LoadExchangeShell: $LoadExchangeShell | Identity: $Identity | IgnoreToolsIdentity: $IgnoreToolsIdentity | AllowPSSessionUsage: $AllowPSSessionUsage"
        $params = @{
            Identity    = $Identity
            ErrorAction = "Stop"
        }

        $toolsServer = (Test-Path $setupKey) -and (!(Test-Path $edgeTransportKey)) -and `
        ($null -eq (Get-ItemProperty -Path $setupKey -Name "Services" -ErrorAction SilentlyContinue))

        $exchangePSSession = Get-PSSession -ErrorAction SilentlyContinue |
            Where-Object { ($_.ConfigurationName -eq "Microsoft.Exchange") -and ($_.State -eq "Opened") } |
            Select-Object -First 1

        if ($toolsServer) {
            Write-Verbose "Tools Server: $env:ComputerName"
            if ($env:ComputerName -eq $Identity -and
                $IgnoreToolsIdentity) {
                Write-Verbose "Removing Identity from Get-ExchangeServer cmdlet"
                $params.Remove("Identity")
            } else {
                Write-Verbose "Didn't remove Identity"
            }
        } elseif (($exchangePSSession.Count -eq 1) -and
            ($AllowPSSessionUsage)) {
            Write-Verbose "Exchange PowerShell session found: $($exchangePSSession.Name)"
            $activeExchangePSSessionFound = $true
            if ($env:ComputerName -ne (($exchangePSSession.ComputerName).Split("."))[0]) {
                Write-Verbose "Removing Identity from Get-ExchangeServer cmdlet"
                $params.Remove("Identity")
            } else {
                Write-Verbose "PowerShell session is established to the local computer and will not be removed"
            }
        }

        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
    }
    process {
        try {
            $currentErrors = $Error.Count
            Get-ExchangeServer @params | Out-Null
            Write-Verbose "Exchange PowerShell Module already loaded."
            $passed = $true
            Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
        } catch {
            Write-Verbose "Failed to run Get-ExchangeServer"
            Invoke-CatchActionError $CatchActionFunction
            if ($activeExchangePSSessionFound -eq $false) {
                if (Test-GetExchangeServerCmdletError $_) { return }
            }
            if (-not ($LoadExchangeShell)) { return }

            #Test 32 bit process, as we can't see the registry if that is the case.
            if (-not ([System.Environment]::Is64BitProcess)) {
                Write-Warning "Open a 64 bit PowerShell process to continue"
                return
            }

            if (Test-Path "$setupKey") {
                $currentErrors = $Error.Count
                Write-Verbose "We are on Exchange 2013 or newer"

                try {
                    if (Test-Path $edgeTransportKey) {
                        Write-Verbose "We are on Exchange Edge Transport Server"
                        [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exshell.psc1" -ErrorAction Stop

                        foreach ($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                            Write-Verbose ("Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name)
                            Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                        }

                        Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                    } else {
                        Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                        Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                    }

                    Write-Verbose "Imported Module. Trying Get-Exchange Server Again"
                    try {
                        Get-ExchangeServer @params | Out-Null
                        $passed = $true
                        Write-Verbose "Successfully loaded Exchange Management Shell"
                        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
                    } catch {
                        Write-Verbose "Failed to run Get-ExchangeServer again"
                        Invoke-CatchActionError $CatchActionFunction
                        if (Test-GetExchangeServerCmdletError $_) { return }
                    }
                } catch {
                    Write-Warning "Failed to Load Exchange PowerShell Module..."
                    Invoke-CatchActionError $CatchActionFunction
                }
            } elseif ($activeExchangePSSessionFound) {
                Write-Verbose "Active Exchange PSSession that needs to be imported found"
                try {
                    Import-PSSession -Session $exchangePSSession -DisableNameChecking -ErrorAction Stop
                    Get-ExchangeServer @params | Out-Null
                    $passed = $true
                    Write-Verbose "Successfully imported PSSession: $($exchangePSSession.Name)"
                    Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
                } catch {
                    Write-Warning "Failed to import PSSession: $($exchangePSSession.Name)"
                    Invoke-CatchActionError $CatchActionFunction
                }
            } else {
                Write-Verbose "Not on an Exchange or Tools server"
            }
        }
    }
    end {

        $currentErrors = $Error.Count
        $returnObject = [PSCustomObject]@{
            ShellLoaded = $passed
            Major       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMajor" -ErrorAction SilentlyContinue).MsiProductMajor)
            Minor       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMinor" -ErrorAction SilentlyContinue).MsiProductMinor)
            Build       = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMajor" -ErrorAction SilentlyContinue).MsiBuildMajor)
            Revision    = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMinor" -ErrorAction SilentlyContinue).MsiBuildMinor)
            EdgeServer  = $passed -and (Test-Path $setupKey) -and (Test-Path $edgeTransportKey)
            ToolsOnly   = $passed -and $toolsServer
            RemoteShell = $passed -and (!(Test-Path $setupKey))
        }

        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

        return $returnObject
    }
}
