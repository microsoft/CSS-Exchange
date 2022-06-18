# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Set-TokenChecking.ps1
. $PSScriptRoot\Set-SSLFlag.ps1
. $PSScriptRoot\..\DataCollection\Get-SSLFlag.ps1
. $PSScriptRoot\..\DataCollection\Test-EPPrerequisites.ps1

function Configure-ExtendedProtection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Work in progress - future adjustment')]
    param()

    Test-EPPrerequisites -Confirm:$true

    $FEWebSiteName = 'Default Web Site'
    $BEWebSiteName = 'Exchange Back End'

    # List of all vDirs where Extended Protection needs to be enabled.
    $FEVDirNames = @("API", "ECP", "EWS", "MAPI", "Microsoft-Server-ActiveSync", "OAB", "Powershell", "OWA", "RPC")
    $BEVDirNames = @("API", "ECP", "EWS", "Microsoft-Server-ActiveSync", "OAB", "Powershell", "OWA", "RPC", "PushNotifications", "RPCWithCert", "MAPI/emsmdb", "MAPI/nspi")

    # If Rollback scenario then set the extended protection to None.
    if ($Rollback -and (-not $PSCmdlet.ParameterSetName.Equals("VDirOverride"))) {
        $FEExtendedProtection = "None"
        $BEExtendedProtection = "None"
    }

    [string[]]$FailedServers = @()
    [string[]]$PassedServers = @()

    # Loop all the Exchange servers
    foreach ($server in $ExchangeServers) {
        # Run the TokenChecking logic on all the Exchange Servers with supported server roles.
        if ($server.ServerRole -like "*Mailbox*" -or  $server.ServerRole -like "*ClientAccess*") {
            Write-Host ("Running ConfigureExtendedProtection on Exchange server: {0}" -f $server)

            try {
                $flag = 0

                if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("FEExtendedProtection")) {
                    $flag = 1
                }

                if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BEExtendedProtection")) {
                    $flag = 2
                }

                if ($flag -eq 0 -or $flag -eq 1) {
                    if ($PSCmdlet.ParameterSetName.Equals("VDirOverride")) {
                        $FEVDirNames = $VirtualDirectoryName
                    }

                    foreach ($vdirname in $FEVDirNames) {
                        Set-TokenChecking -Server $server -Website_Name $FEWebSiteName -VDirName $vdirname -TokenChecking $FEExtendedProtection

                        if ($EnforceSSL) {
                            # Check for SSL flags
                            $sslflag = Get-SSLFlag -Server $server -Website_Name $FEWebSiteName -VDirName $vdirname

                            # If it's not set then set the SSL flag to true
                            if ($sslflag -eq '0' -and $sslflag -eq 0) {
                                Write-Host ("Enabling require SSL on Exchange server: {0}, {1}, VDir: {2}" -f $server, $FEWebSiteName, $vdirname)
                                Set-SSLFlag -Server $server -Website_Name $FEWebSiteName -VDirName $vdirname
                            }
                        }
                    }
                }

                if ($flag -eq 0 -or $flag -eq 2) {
                    if ($PSCmdlet.ParameterSetName.Equals("VDirOverride")) {
                        $BEVDirNames = $VirtualDirectoryName
                    }

                    foreach ($vdirname in $BEVDirNames)	{
                        Set-TokenChecking -Server $server -Website_Name $BEWebSiteName -VDirName $vdirname -TokenChecking $BEExtendedProtection

                        if ($EnforceSSL) {
                            # Check for SSL flags
                            $sslflag = Get-SSLFlag -Server $server -Website_Name $BEWebSiteName -VDirName $vdirname

                            # If it's not set then set the SSL flag to true
                            if ($sslflag -eq '0' -and $sslflag -eq 0) {
                                Write-Host ("Enabling require SSL on Exchange server: {0}, {1}, VDir: {2}" -f $server, $BEWebSiteName, $vdirname)
                                Set-SSLFlag -Server $server -Website_Name $BEWebSiteName -VDirName $vdirname
                            }
                        }
                    }
                }
            } catch {
                # Add to failed servers list
                $FailedServers += $server.ToString()
                continue
            }
            $PassedServers += $server.ToString()
        } else {
            Write-Host ("Skipping server {0} as it does not match the supported ServerRole." -f $server)
        }
    }

    Write-Host ("ConfigureExtendedProtection Passed on: {0}" -f $([string]::Join(",", $PassedServers)))
    Write-Host ("ConfigureExtendedProtection Failed on: {0}" -f $([string]::Join(",", $FailedServers)))
}
