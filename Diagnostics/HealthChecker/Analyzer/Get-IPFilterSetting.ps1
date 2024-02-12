# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-IPFilterSetting {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$ApplicationHostConfig
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $locationPaths = $ApplicationHostConfig.configuration.location.path | Where-Object { $_ -ne "" }
        $ipFilterSettings = @{}
    }
    process {
        foreach ($appKey in $locationPaths) {
            Write-Verbose "Working on appKey: $appKey"

            if (-not ($ipFilterSettings.ContainsKey($appKey))) {
                $ipFilterSettings.Add($appKey, (New-Object System.Collections.Generic.List[object]))
            }

            $currentKey = $appKey
            $continue = $true

            do {
                Write-Verbose "Working on currentKey: $currentKey"
                $location = $ApplicationHostConfig.SelectNodes("/configuration/location[@path = '$currentKey']")

                if ($null -ne $location) {
                    $ipSecurity = $location.'system.webServer'.security.ipSecurity

                    if ($null -ne $ipSecurity) {
                        $clear = $null -ne $ipSecurity.clear
                        $ipFilterSettings[$appKey].Add($ipSecurity)
                    }
                } else {
                    Write-Verbose "Couldn't find location. This shouldn't occur."
                }

                if ($clear) {
                    Write-Verbose "Clear was set, don't need to know what else was set."
                    $continue = $false
                } else {
                    $index = $currentKey.LastIndexOf("/")

                    if ($index -eq -1) {
                        $continue = $false

                        # look at the global configuration applicationHost.config
                        $ipSecurity = $ApplicationHostConfig.configuration.'system.webServer'.security.ipSecurity

                        # Need to check for if it is an empty string, if it is, we don't need to worry about it.
                        if ($null -ne $ipSecurity -and
                            $ipSecurity.GetType().Name -ne "string") {
                            $add = $null -ne ($ipSecurity | Get-Member | Where-Object { $_.MemberType -eq "Property" -and $_.Name -ne "allowUnlisted" })

                            if ($add) {
                                $ipFilterSettings[$appKey].Add($ipSecurity)
                            }
                        } else {
                            Write-Verbose "No ipSecurity set globally"
                        }
                    } else {
                        $currentKey = $currentKey.Substring(0, $index)
                    }
                }
            } while ($continue)
        }
    }
    end {
        return $ipFilterSettings
    }
}
