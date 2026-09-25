# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Test-CommandExists.ps1
. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1

function Invoke-IISConfigurationQuery {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $appCmd = Join-Path -Path $env:windir -ChildPath 'System32\inetsrv\AppCmd.exe'
    if (-not (Test-Path -LiteralPath $appCmd -ErrorAction Stop)) {
        throw 'The IIS configuration command is unavailable.'
    }
    $output = @(& $appCmd @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "IIS configuration query failed: $($output -join ' ')"
    }
    return $output
}

function Get-IISLogDirectory {
    [CmdletBinding()]
    param(
        [Alias('NewerThan')][datetime]$LogStartDate = (Get-Date).AddDays(-3),
        [datetime]$LogEndDate = (Get-Date),
        [switch]$IncludeAdditionalLocations
    )

    Write-Verbose("Function Enter: Get-IISLogDirectory")
    if ($LogStartDate -gt $LogEndDate) {
        throw 'The start of the log collection window must not follow its end.'
    }

    $directories = New-Object 'System.Collections.Generic.List[string]'
    $knownPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    function ConvertTo-IISLogPath {
        param([string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path)) { throw 'The configured log path is empty.' }
        $expanded = [System.Environment]::ExpandEnvironmentVariables($Path).Replace('/', '\')
        if ($expanded -match '%[^%]+%') { throw "An environment variable in '$Path' could not be resolved." }
        if ($expanded -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+(?:\\|$))') {
            throw "The configured log path '$Path' is not an absolute local or UNC path."
        }
        $normalized = [System.IO.Path]::GetFullPath($expanded)
        if ($normalized.Length -gt [System.IO.Path]::GetPathRoot($normalized).Length) {
            $normalized = $normalized.TrimEnd('\')
        }
        return $normalized
    }

    function Add-IISLogPath {
        param([string]$Path)
        try {
            $normalized = ConvertTo-IISLogPath -Path $Path
            if ($knownPaths.Add($normalized)) {
                $directories.Add($normalized)
                Write-Verbose "IIS log directory: '$normalized'."
            }
        } catch {
            Invoke-CatchActions
            Write-Warning "Unable to use IIS log path '$Path': $($_.Exception.Message)"
        }
    }

    function Get-IISLogSetting {
        param([string]$Property, [string]$Filter, [string]$Name, [string[]]$AllowedValues)
        try {
            $result = @(Invoke-IISConfigurationQuery -Arguments @('list', 'config', '-section:system.applicationHost/log', "/text:$Property"))
            if ($result.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$result[0]) -or [string]$result[0] -match '^\s*ERROR\s*\(') {
                throw "Unexpected response for '$Property'."
            }
            $value = ([string]$result[0]).Trim()
            if ($AllowedValues.Count -gt 0 -and $AllowedValues -notcontains $value) { throw "Unknown value '$value' for '$Property'." }
            return $value
        } catch {
            Invoke-CatchActions
            Write-Verbose "Native IIS query failed for '$Property'; trying WebAdministration."
        }

        try {
            Import-Module -Name WebAdministration -ErrorAction Stop
            $propertyValue = Get-WebConfigurationProperty -PSPath 'MACHINE/WebRoot/AppHost' -Filter $Filter -Name $Name -ErrorAction Stop
            if ($null -ne $propertyValue -and $null -ne $propertyValue.PSObject.Properties['Value']) {
                $propertyValue = $propertyValue.Value
            }
            $value = [string]$propertyValue
            if ([string]::IsNullOrWhiteSpace($value) -or ($AllowedValues.Count -gt 0 -and $AllowedValues -notcontains $value)) {
                throw "No valid value was returned for '$Property'."
            }
            return $value.Trim()
        } catch {
            Invoke-CatchActions
            Write-Warning "Unable to read IIS setting '$Property'. Log discovery may be incomplete: $($_.Exception.Message)"
        }
    }

    try {
        if (-not (Test-CommandExists -command 'Get-Website')) {
            Import-Module -Name WebAdministration -ErrorAction Stop
        }
        foreach ($site in Get-Website -ErrorAction Stop) {
            try {
                $root = ConvertTo-IISLogPath -Path ([string]$site.LogFile.Directory)
                Add-IISLogPath -Path ([System.IO.Path]::Combine($root, "W3SVC$($site.Id)"))
            } catch {
                Invoke-CatchActions
                Write-Warning "Unable to determine the log path for IIS site '$($site.Name)': $($_.Exception.Message)"
            }
        }
    } catch {
        Invoke-CatchActions
        Write-Warning "Unable to read IIS sites with Get-Website; trying the native IIS configuration API."
        try {
            $siteOutput = Invoke-IISConfigurationQuery -Arguments @('list', 'config', '-section:system.applicationHost/sites', '/config:*')
            [xml]$configuration = $siteOutput -join [System.Environment]::NewLine
            $sitesNode = $configuration.SelectSingleNode('//sites')
            if ($null -eq $sitesNode) { throw 'No IIS sites configuration was returned.' }
            $defaultsNode = $sitesNode.SelectSingleNode('siteDefaults/logFile')
            foreach ($siteNode in $sitesNode.SelectNodes('site')) {
                $logNode = $siteNode.SelectSingleNode('logFile')
                $root = ''
                if ($null -ne $logNode) { $root = $logNode.GetAttribute('directory') }
                if ([string]::IsNullOrWhiteSpace($root) -and $null -ne $defaultsNode) { $root = $defaultsNode.GetAttribute('directory') }
                $siteId = 0
                if (-not [int]::TryParse($siteNode.GetAttribute('id'), [ref]$siteId) -or $siteId -lt 1 -or [string]::IsNullOrWhiteSpace($root)) {
                    Write-Warning 'An IIS site has no valid identifier or effective log directory; its logs could not be located.'
                    continue
                }
                Add-IISLogPath -Path ([System.IO.Path]::Combine($root, "W3SVC$siteId"))
            }
        } catch {
            Invoke-CatchActions
            Write-Warning 'IIS site configuration could not be read. Trying the standard IIS log root as an unverified fallback.'
            Add-IISLogPath -Path '%SystemDrive%\inetPub\logs\LogFiles'
        }
    }

    $searchAdditional = $IncludeAdditionalLocations -or $directories.Count -eq 0
    foreach ($path in $directories) {
        try {
            $files = @(Get-ChildItem -LiteralPath $path -File -ErrorAction Stop |
                    Where-Object { $_.LastWriteTime -ge $LogStartDate -and $_.LastWriteTime -le $LogEndDate } |
                    Select-Object -First 1)
            if ($files.Count -eq 0) { $searchAdditional = $true }
        } catch [System.Management.Automation.ItemNotFoundException] {
            $searchAdditional = $true
        } catch {
            Invoke-CatchActions
            $searchAdditional = $true
            Write-Warning "Unable to inspect IIS logs in '$path'; this does not mean the directory is empty: $($_.Exception.Message)"
        }
    }

    if ($searchAdditional) {
        $mode = Get-IISLogSetting -Property 'centralLogFileMode' -Filter 'system.applicationHost/log' -Name 'centralLogFileMode' -AllowedValues @('Site', 'CentralW3C', 'CentralBinary')
        foreach ($centralMode in @('CentralW3C', 'CentralBinary')) {
            if (-not $IncludeAdditionalLocations -and $centralMode -ne $mode) { continue }
            $element = 'centralW3CLogFile'
            if ($centralMode -eq 'CentralBinary') { $element = 'centralBinaryLogFile' }
            $root = Get-IISLogSetting -Property "$element.directory" -Filter "system.applicationHost/log/$element" -Name 'directory'
            if ([string]::IsNullOrWhiteSpace($root)) { continue }
            try {
                $centralPath = [System.IO.Path]::Combine((ConvertTo-IISLogPath -Path $root), 'W3SVC')
                if ($centralMode -eq $mode -or (Test-Path -LiteralPath $centralPath -PathType Container -ErrorAction Stop)) {
                    Add-IISLogPath -Path $centralPath
                }
            } catch {
                Invoke-CatchActions
                Write-Warning "Unable to inspect additional IIS log path '$root': $($_.Exception.Message)"
            }
        }
    }

    Write-Verbose("Function Exit: Get-IISLogDirectory")
    return $directories.ToArray()
}
