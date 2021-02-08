#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ExchangeInformation/Confirm-ExchangeShell/Confirm-ExchangeShell.ps1

Function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][bool]$LoadExchangeShell = $true,
        [Parameter(Mandatory = $false)][scriptblock]$CatchActionFunction
    )
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellFunctions/master/src/Common/Write-HostWriters/Write-HostWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellFunctions/master/src/Common/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>

    Function Invoke-CatchActionErrorLoop {
        param(
            [int]$CurrentErrors
        )

        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $CurrentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    }

    $passed = $false
    $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
    Write-VerboseWriter("Calling: Confirm-ExchangeShell")
    Write-VerboseWriter("Passed: [bool]LoadExchangeShell: {0}" -f $LoadExchangeShell)

    try {
        $currentErrors = $Error.Count
        Get-ExchangeServer -ErrorAction Stop | Out-Null
        Write-VerboseWriter("Exchange PowerShell Module already loaded.")
        $passed = $true
        Invoke-CatchActionErrorLoop -CurrentErrors $currentErrors
    } catch {
        Write-VerboseWriter("Failed to run Get-ExchangeServer")

        if ($null -ne $CatchActionFunction) {
            & $CatchActionFunction
        }

        if (!$LoadExchangeShell) {
            return [PSCustomObject]@{
                ShellLoaded = $false
            }
        }

        #Test 32 bit process, as we can't see the registry if that is the case.
        if (![System.Environment]::Is64BitProcess) {
            Write-HostWriter("Open a 64 bit PowerShell process to continue")
            return [PSCustomObject]@{
                ShellLoaded = $false
            }
        }

        $currentErrors = $Error.Count

        if (Test-Path "$setupKey") {
            Write-VerboseWriter("We are on Exchange 2013 or newer")

            try {
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole') {
                    Write-VerboseWriter("We are on Exchange Edge Transport Server")
                    [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exshell.psc1" -ErrorAction Stop

                    foreach ($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                        Write-VerboseWriter("Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name)
                        Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                    }

                    Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                } else {
                    Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                    Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                }

                Write-VerboseWriter("Imported Module. Trying Get-Exchange Server Again")
                Get-ExchangeServer -ErrorAction Stop | Out-Null
                $passed = $true
                Write-VerboseWriter("Successfully loaded Exchange Management Shell")
                Invoke-CatchActionErrorLoop -CurrentErrors $currentErrors
            } catch {
                Write-HostWriter("Failed to Load Exchange PowerShell Module...")
                if ($null -ne $CatchActionFunction) {
                    & $CatchActionFunction
                }
            }
        } else {
            Write-VerboseWriter ("Not on an Exchange or Tools server")
        }
    }

    $currentErrors = $Error.Count
    $returnObject = [PSCustomObject]@{
        ShellLoaded = $passed
        Major       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMajor" -ErrorAction SilentlyContinue).MsiProductMajor)
        Minor       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMinor" -ErrorAction SilentlyContinue).MsiProductMinor)
        Build       = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMajor" -ErrorAction SilentlyContinue).MsiBuildMajor)
        Revision    = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMinor" -ErrorAction SilentlyContinue).MsiBuildMinor)
        ToolsOnly   = $passed -and (Test-Path $setupKey) -and ($null -eq (Get-ItemProperty -Path $setupKey -Name "Services" -ErrorAction SilentlyContinue))
        RemoteShell = $passed -and (!(Test-Path $setupKey))
    }

    Invoke-CatchActionErrorLoop -CurrentErrors $currentErrors

    return $returnObject
}
