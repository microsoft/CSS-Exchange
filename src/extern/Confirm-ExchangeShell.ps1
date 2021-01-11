#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/ExchangeInformation/Confirm-ExchangeShell/Confirm-ExchangeShell.ps1
#v21.01.08.2133
Function Confirm-ExchangeShell {
    #TODO: Fix this
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Because it is required to find stuff at times.')]
    [CmdletBinding()]
    [OutputType("System.Boolean")]
    param(
        [Parameter(Mandatory = $false)][bool]$LoadExchangeShell = $true,
        [Parameter(Mandatory = $false)][scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.08.2133

    $passed = $false
    Write-VerboseWriter("Calling: Confirm-ExchangeShell")
    Write-VerboseWriter("Passed: [bool]LoadExchangeShell: {0}" -f $LoadExchangeShell)

    try {
        $currentErrors = $Error.Count
        Get-ExchangeServer -ErrorAction Stop | Out-Null
        Write-VerboseWriter("Exchange PowerShell Module already loaded.")
        $passed = $true

        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $currentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    } catch {
        Write-VerboseWriter("Failed to run Get-ExchangeServer")

        if ($null -ne $CatchActionFunction) {
            & $CatchActionFunction
        }

        if (!$LoadExchangeShell) {
            return $false
        }

        #Test 32 bit process, as we can't see the registry if that is the case.
        if (![System.Environment]::Is64BitProcess) {
            Write-HostWriter("Open a 64 bit PowerShell process to continue")
            return $false
        }

        $currentErrors = $Error.Count

        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup') {
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

                if ($null -ne $CatchActionFunction -and
                    $currentErrors -ne $Error.Count) {
                    $i = 0
                    while ($i -lt ($Error.Count - $currentErrors)) {
                        & $CatchActionFunction $Error[$i]
                        $i ++
                    }
                }
            } catch {
                Write-HostWriter("Failed to Load Exchange PowerShell Module...")
                if ($null -ne $CatchActionFunction) {
                    & $CatchActionFunction
                }
            }
        }
    }

    Write-VerboseWriter("Returned: {0}" -f $passed)
    return $passed
}
