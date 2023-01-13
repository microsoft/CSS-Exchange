# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Retrieves the replication status for all naming contexts of all DCs.
.DESCRIPTION
    Similar to "repadmin /ShowRepl * /csv", this function retrieves the replication status
    for each replicated naming context on every DC. The approach used here does not rely
    on the presence of repadmin or other tools. The status of up to 10 DCs is retrieved in
    parallel to improve performance in environments where multiple DCs are offline or
    unreachable.
.NOTES
    This function is intended to be self-contained and must not rely on other files in the
    CSS-Exchange repository. The goal is to allow this function to be consumed by tools
    that are external to CSS-Exchange.
.EXAMPLE
    Get-ADReplicationStatus -Verbose | Select -ExcludeProperty RunSpaceId | ft
#>
function Get-ADReplicationStatus {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'CNAME resolution failure should not throw or Write-Error')]
    [CmdletBinding()]
    param ()

    begin {
        $jobsQueued = New-Object 'System.Collections.Generic.Queue[object]'

        function Add-JobQueueJob {
            [CmdletBinding()]
            param (
                [Parameter()]
                [PSCustomObject]
                $JobParameters
            )

            $jobsQueued.Enqueue($JobParameters)
        }

        function Wait-QueuedJob {
            [CmdletBinding()]
            [OutputType([System.Object[]])]
            param (

            )

            begin {
                $jobsRunning = @()
                $jobQueueMaxConcurrency = 10
            }

            process {
                $totalJobCount = $jobsQueued.Count
                $jobsCompleted = 0

                while ($jobsQueued.Count -gt 0 -or $jobsRunning.Count -gt 0) {
                    Write-Progress -Activity "Getting Active Directory replication status" -Status "$jobsCompleted / $totalJobCount" -PercentComplete ($jobsCompleted * 100 / $totalJobCount)

                    if ($jobsRunning.Count -lt $jobQueueMaxConcurrency -and $jobsQueued.Count -gt 0) {
                        $jobArgs = $jobsQueued.Dequeue()
                        $newJob = Start-Job @jobArgs
                        $jobsRunning += $newJob
                        Write-Verbose "$($jobArgs.Name) job started."
                        continue
                    }

                    $justFinished = @($jobsRunning | Where-Object { $_.State -ne "Running" })
                    if ($justFinished.Count -gt 0) {
                        foreach ($job in $justFinished) {
                            $result = Receive-Job $job
                            Write-Verbose "$($job.Name) job finished."
                            Remove-Job $job -Force
                            $jobsCompleted++
                            $result
                        }

                        $jobsRunning = @($jobsRunning | Where-Object { -not $justFinished.Contains($_) })
                    }

                    Start-Sleep 1
                }

                Write-Progress -Activity "Getting Active Directory replication status" -Completed
            }
        }

        function Get-ADReplicationStatusForOneServer {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]
                $Server,

                [Parameter(Mandatory = $true)]
                [string]
                $IsGC
            )

            begin {
                function Get-ReplLink {
                    [CmdletBinding()]
                    param (
                        [Parameter(Mandatory = $true)]
                        [byte[]]
                        $Bytes
                    )

                    $linkData = @{
                        dwVersion           = [System.BitConverter]::ToInt32($Bytes, 0)
                        cb                  = [System.BitConverter]::ToUInt32($Bytes, 8)
                        consecutiveFailures = [System.BitConverter]::ToUInt32($Bytes, 12)
                        timeLastSuccess     = [DateTime]::FromFileTime([System.BitConverter]::ToInt64($Bytes, 16) * 10 * 1000 * 1000)
                        timeLastAttempt     = [DateTime]::FromFileTime([System.BitConverter]::ToInt64($Bytes, 24) * 10 * 1000 * 1000)
                        ulResultLastAttempt = [System.BitConverter]::ToUInt32($Bytes, 32)
                        cbOtherDraOffset    = [System.BitConverter]::ToUInt32($Bytes, 36)
                        cbOtherDra          = [System.BitConverter]::ToUInt32($Bytes, 40)
                        ulReplicaFlags      = [System.BitConverter]::ToUInt32($Bytes, 44)
                    }

                    $otherDra = @{
                        cb                    = [System.BitConverter]::ToUInt32($Bytes, $linkData.cbOtherDraOffset)
                        cbpSzServerOffset     = [System.BitConverter]::ToUInt32($Bytes, $linkData.cbOtherDraOffset + 4)
                        cbpSzAnnotationOffset = [System.BitConverter]::ToUInt32($Bytes, $linkData.cbOtherDraOffset + 8)
                        cbpGuidInstanceOffset = [System.BitConverter]::ToUInt32($Bytes, $linkData.cbOtherDraOffset + 12)
                    }

                    $otherDraServerStart = $linkData.cbOtherDraOffset + $otherDra.cbpSzServerOffset
                    $otherDraServerEnd = Get-UnicodeNullIndex $Bytes $otherDraServerStart
                    $otherDraServerLength = $otherDraServerEnd - $otherDraServerStart
                    $otherDraServer = [System.Text.Encoding]::Unicode.GetString($Bytes, $otherDraServerStart, $otherDraServerLength)

                    [PSCustomObject]@{
                        OtherDraServer      = $otherDraServer
                        ConsecutiveFailures = $linkData.consecutiveFailures
                        TimeLastSuccess     = $linkData.timeLastSuccess
                        TimeLastAttempt     = $linkData.timeLastAttempt
                        ResultLastAttempt   = $linkData.ulResultLastAttempt
                    }
                }

                function Get-UnicodeNullIndex {
                    [CmdletBinding()]
                    param(
                        [Parameter(Mandatory = $true)]
                        [byte[]]
                        $Bytes,

                        [Parameter(Mandatory = $true)]
                        [int]
                        $StartIndex
                    )

                    for ($i = $StartIndex; $i -lt $Bytes.Length; $i += 2) {
                        if ($Bytes[$i] -eq 0 -and $Bytes[$i + 1] -eq 0) {
                            return $i
                        }
                    }
                }

                $resultObject = [PSCustomObject]@{
                    ReplLinks = New-Object System.Collections.ArrayList
                    Errors    = New-Object System.Collections.ArrayList
                }
            }

            process {
                try {
                    $baseDN = "$(if ($IsGC) { "GC" } else { "LDAP" })://$Server"
                    $rootDseDn = "$baseDN/RootDSE"
                    $rootDSE = [ADSI]($rootDseDn)
                    [void]($rootDSE | Out-String) # This will throw if the server is down and generates a better error than attempting to index into a property

                    # Do we need to verify that the dnsHostName on the rootDSE is the server we specified here?
                    $namingContexts = New-Object System.Collections.ArrayList
                    if ($IsGC) {
                        # Always use 389 to get partitions
                        $partitionsPath = "LDAP://$Server/CN=Partitions,$($rootDSE.Properties["configurationNamingContext"][0].ToString())"
                        $partitionsContainer = New-Object System.DirectoryServices.DirectoryEntry($partitionsPath)
                        $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher($partitionsContainer, "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))", @("nCName"), "OneLevel")
                        $domainSearcher.PageSize = 100
                        $domainResults = $domainSearcher.FindAll()
                        foreach ($result in $domainResults) {
                            [void]$namingContexts.Add($result.Properties["nCName"][0].ToString())
                        }
                    }

                    foreach ($nc in $rootDSE.Properties["namingContexts"]) {
                        if (-not $namingContexts.Contains($nc.ToString())) {
                            [void]$namingContexts.Add($nc.ToString())
                        }
                    }

                    foreach ($namingContext in $namingContexts) {
                        $ncDN = "$baseDN/$namingContext"
                        $nc = [ADSI]($ncDN)

                        foreach ($val in $nc.Properties["repsFrom"]) {
                            $repLink = Get-ReplLink $val | ForEach-Object {
                                [PSCustomObject]@{
                                    Server              = $Server
                                    NamingContext       = $namingContext
                                    OtherDraServer      = $_.OtherDraServer
                                    ConsecutiveFailures = $_.ConsecutiveFailures
                                    TimeLastSuccess     = $_.TimeLastSuccess
                                    TimeLastAttempt     = $_.TimeLastAttempt
                                    ResultLastAttempt   = $_.ResultLastAttempt
                                }
                            }

                            [void]$resultObject.ReplLinks.Add($repLink)
                        }
                    }
                } catch {
                    $errorToShow = $_
                    if ($null -ne $_.Exception) {
                        if ($null -ne $_.Exception.InnerException) {
                            $errorToShow = $_.Exception.InnerException.Message
                        } else {
                            $errorToShow = $_.Exception.Message
                        }
                    }

                    [void]$resultObject.Errors.Add("Failed to get AD replication information from server $Server. Error: $errorToShow")
                }
            }

            end {
                $resultObject
            }
        }
    }

    process {
        $rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
        $sitesContainerPath = ("CN=Sites," + $rootDSE.configurationNamingContext)
        $sitesContainer = [ADSI]("LDAP://" + $sitesContainerPath)
        $ntDsaSearcher = New-Object System.DirectoryServices.DirectorySearcher($sitesContainer, "(objectClass=nTDSDSA)", @("distinguishedName", "options"))
        $ntDsaSearcher.PageSize = 100
        $ntDsaResults = $ntDsaSearcher.FindAll()

        foreach ($result in $ntDsaResults) {
            $isGC = $false
            if ($result.Properties.Contains("options") -and $result.Properties["options"].Count -gt 0 -and $result.Properties["options"][0] -band 1 -eq 1) {
                $isGC = $true
            }

            $ntDsaDN = $result.Properties["distinguishedName"][0].ToString()
            $parentDN = $ntDsaDN.Substring($ntDsaDN.IndexOf(",") + 1)
            $parentObject = [ADSI]("LDAP://" + $parentDN)
            $serverSearcher = New-Object System.DirectoryServices.DirectorySearcher($parentObject, "(objectClass=*)", @("cn", "dNSHostName"), "Base")
            $serverResult = $serverSearcher.FindOne()
            $fqdn = $serverResult.Properties["dNSHostName"][0].ToString()

            Add-JobQueueJob @{
                Name         = $fqdn
                ScriptBlock  = ${Function:Get-ADReplicationStatusForOneServer}
                ArgumentList = @($fqdn, $isGC)
            }
        }

        Wait-QueuedJob | ForEach-Object {
            $_.Errors | ForEach-Object {
                Write-Warning $_
            }

            $_.ReplLinks | ForEach-Object {
                try {
                    # Convert GUID._msdcs CNAME to server FQDN
                    $_.OtherDraServer = [System.Net.Dns]::GetHostByName($_.OtherDraServer).Hostname
                } catch {
                    # Do nothing, we'll just keep the _msdcs name
                }

                $_
            }
        }
    }
}
