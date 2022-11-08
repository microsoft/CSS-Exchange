# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1
. $PSScriptRoot\Invoke-CatchActionErrorLoop.ps1

# Confirm that either Remote Shell or EMS is loaded from an Edge Server, Exchange Server, or a Tools box.
# It does this by also initializing the session and running Get-EventLogLevel. (Server Management RBAC right)
# All script that require Confirm-ExchangeShell should be at least using Server Management RBAC right for the user running the script.
function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$LoadExchangeShell = $true,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed: LoadExchangeShell: $LoadExchangeShell"
        $currentErrors = $Error.Count
        $passed = $false
        $edgeTransportKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        $remoteShell = (!(Test-Path $setupKey))
        $toolsServer = (Test-Path $setupKey) -and (!(Test-Path $edgeTransportKey)) -and `
        ($null -eq (Get-ItemProperty -Path $setupKey -Name "Services" -ErrorAction SilentlyContinue))
        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
    }
    process {
        try {
            $currentErrors = $Error.Count
            $isEMS = Get-EventLogLevel -ErrorAction Stop |
                Select-Object -First 1 |
                ForEach-Object { if ($_.GetType().Name -eq "EventCategoryObject") { return $true } return $false }
            Write-Verbose "Exchange PowerShell Module already loaded."
            $passed = $true
            Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
        } catch {
            Write-Verbose "Failed to run Get-EventLogLevel"
            Invoke-CatchActionError $CatchActionFunction
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

                    Write-Verbose "Imported Module. Trying Get-EventLogLevel Again"
                    try {
                        $isEMS = Get-EventLogLevel -ErrorAction Stop |
                            Select-Object -First 1 |
                            ForEach-Object { if ($_.GetType().Name -eq "EventCategoryObject") { return $true } return $false }
                        $passed = $true
                        Write-Verbose "Successfully loaded Exchange Management Shell"
                        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
                    } catch {
                        Write-Verbose "Failed to run Get-EventLogLevel again"
                        Invoke-CatchActionError $CatchActionFunction
                    }
                } catch {
                    Write-Warning "Failed to Load Exchange PowerShell Module..."
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
            RemoteShell = $passed -and $remoteShell
            EMS         = $isEMS
        }

        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

        return $returnObject
    }
}
