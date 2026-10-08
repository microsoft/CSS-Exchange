# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    . $PSScriptRoot\..\Get-IISLogDirectory.ps1

    function Get-Website {
        [CmdletBinding()]
        param()
    }

    function Get-WebConfigurationProperty {
        [CmdletBinding()]
        param([string]$PSPath, [string]$Filter, [string]$Name)
    }
}

Describe 'IIS log discovery preserves primary paths and adds verified locations' {
    BeforeEach {
        Invoke-ErrorMonitoring
        $script:now = [datetime]'2026-09-16T12:00:00'
        $script:sites = @(
            [PSCustomObject]@{ Name = 'First'; Id = 1; LogFile = [PSCustomObject]@{ Directory = 'C:\Lab Logs' } },
            [PSCustomObject]@{ Name = 'Second'; Id = 2; LogFile = [PSCustomObject]@{ Directory = 'C:\Lab Logs' } }
        )
        $script:files = @{
            'C:\Lab Logs\W3SVC1' = @([PSCustomObject]@{ LastWriteTime = $script:now.AddMinutes(-5) })
            'C:\Lab Logs\W3SVC2' = @([PSCustomObject]@{ LastWriteTime = $script:now.AddMinutes(-5) })
        }
        $script:settings = @{
            centralLogFileMode               = 'Site'
            'centralW3CLogFile.directory'    = 'E:\Central Logs'
            'centralBinaryLogFile.directory' = 'F:\Binary Logs'
        }
        $script:existingCentral = @('E:\Central Logs\W3SVC', 'F:\Binary Logs\W3SVC')
        $script:nativeUnavailable = $false
        $script:moduleUnavailable = $false
        $script:siteFailure = $false
        $script:webWrapped = $false
        $script:webSettings = $script:settings.Clone()
        $script:siteXml = '<system.applicationHost><sites><site name="First" id="1"><logFile directory="E:\Custom Site Logs" /></site><site name="Second" id="2" /><siteDefaults><logFile directory="F:\Default Site Logs" /></siteDefaults></sites></system.applicationHost>'
        Mock -CommandName Get-Date -MockWith { $script:now }
        Mock -CommandName Test-CommandExists -MockWith { -not $script:moduleUnavailable }
        Mock -CommandName Invoke-CatchActions -MockWith {}
        Mock -CommandName Import-Module -ParameterFilter { $Name -eq 'WebAdministration' } -MockWith {
            if ($script:moduleUnavailable) { throw 'Module unavailable.' }
        }
        Mock -CommandName Get-Website -MockWith {
            if ($script:siteFailure) { throw 'Site configuration unavailable.' }
            $script:sites
        }
        Mock -CommandName Get-ChildItem -MockWith { param($LiteralPath) $script:files[[string]$LiteralPath] }
        Mock -CommandName Test-Path -MockWith { param($LiteralPath) $script:existingCentral -contains $LiteralPath }
        Mock -CommandName Invoke-IISConfigurationQuery -MockWith {
            param($Arguments)
            if ($script:nativeUnavailable) { throw 'Native configuration unavailable.' }
            if ($Arguments -contains '-section:system.applicationHost/sites') { return $script:siteXml }
            $property = @($Arguments | Where-Object { $_.StartsWith('/text:') })[0].Substring(6)
            $script:settings[$property]
        }
        Mock -CommandName Get-WebConfigurationProperty -MockWith {
            param($Filter, $Name)
            $key = $Name
            if ($Name -eq 'directory') { $key = "$($Filter.Substring($Filter.LastIndexOf('/') + 1)).directory" }
            if ($script:webWrapped) { return [PSCustomObject]@{ Value = $script:webSettings[$key] } }
            $script:webSettings[$key]
        }
    }

    It 'keeps the normal fresh per-site paths without additional configuration reads' {
        $result = @(Get-IISLogDirectory)
        $result | Should -HaveCount 2
        $result | Should -Contain 'C:\Lab Logs\W3SVC1'
        $result | Should -Contain 'C:\Lab Logs\W3SVC2'
        Should -Invoke -CommandName Invoke-IISConfigurationQuery -Times 0 -Exactly
    }

    It 'adds <Mode> when a site is empty even if the other site is active' -ForEach @(
        @{ Mode = 'CentralW3C'; Expected = 'E:\Central Logs\W3SVC' },
        @{ Mode = 'CentralBinary'; Expected = 'F:\Binary Logs\W3SVC' }
    ) {
        $script:files['C:\Lab Logs\W3SVC2'] = @()
        $script:settings.centralLogFileMode = $Mode
        $result = @(Get-IISLogDirectory)
        $result | Should -Contain $Expected
        $result | Should -Contain 'C:\Lab Logs\W3SVC1'
    }

    It 'uses the actual requested window rather than a separate age cutoff' {
        $script:files.Values | ForEach-Object { $_[0].LastWriteTime = $script:now.AddHours(-1) }
        $script:settings.centralLogFileMode = 'CentralW3C'
        @(Get-IISLogDirectory -LogStartDate $script:now.AddMinutes(-30) -LogEndDate $script:now) | Should -Contain 'E:\Central Logs\W3SVC'
    }

    It 'honors the end of a historical window as well as its start' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        @(Get-IISLogDirectory -LogStartDate $script:now.AddDays(-2) -LogEndDate $script:now.AddDays(-1)) | Should -Contain 'E:\Central Logs\W3SVC'
    }

    It 'accepts the original NewerThan parameter as an alias' {
        $script:files.Values | ForEach-Object { $_[0].LastWriteTime = $script:now.AddHours(-1) }
        $script:settings.centralLogFileMode = 'CentralW3C'
        @(Get-IISLogDirectory -NewerThan $script:now.AddMinutes(-30)) | Should -Contain 'E:\Central Logs\W3SVC'
    }

    It 'includes files exactly on the window boundaries' {
        $script:files['C:\Lab Logs\W3SVC1'][0].LastWriteTime = $script:now.AddDays(-3)
        $script:files['C:\Lab Logs\W3SVC2'][0].LastWriteTime = $script:now
        $null = Get-IISLogDirectory
        Should -Invoke -CommandName Invoke-IISConfigurationQuery -Times 0 -Exactly
    }

    It 'does not let fresh per-site leftovers suppress explicitly requested additional discovery' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        @(Get-IISLogDirectory -IncludeAdditionalLocations) | Should -Contain 'E:\Central Logs\W3SVC'
    }

    It 'includes retained central logs after switching back to Site' {
        $result = @(Get-IISLogDirectory -IncludeAdditionalLocations)
        $result | Should -Contain 'E:\Central Logs\W3SVC'
        $result | Should -Contain 'F:\Binary Logs\W3SVC'
        $result | Should -Contain 'C:\Lab Logs\W3SVC1'
    }

    It 'does not guess that absent inactive central directories contain logs' {
        $script:existingCentral = @()
        @(Get-IISLogDirectory -IncludeAdditionalLocations) | Should -HaveCount 2
    }

    It 'uses the IIS PowerShell API after native failure, wrapped: <Wrapped>' -ForEach @(@{ Wrapped = $true }, @{ Wrapped = $false }) {
        $script:nativeUnavailable = $true
        $script:webWrapped = $Wrapped
        $script:webSettings.centralLogFileMode = 'CentralW3C'
        @(Get-IISLogDirectory -IncludeAdditionalLocations) | Should -Contain 'E:\Central Logs\W3SVC'
    }

    It 'rejects multiline scalar responses and uses the IIS API' {
        $script:settings.centralLogFileMode = @('CentralW3C', 'Unexpected second line')
        $script:webSettings.centralLogFileMode = 'CentralBinary'
        $script:files = @{}
        @(Get-IISLogDirectory) | Should -Contain 'F:\Binary Logs\W3SVC'
    }

    It 'rejects an ERROR scalar response and uses the IIS API' {
        $script:settings.centralLogFileMode = 'ERROR ( configuration unavailable )'
        $script:webSettings.centralLogFileMode = 'CentralBinary'
        $script:files = @{}
        @(Get-IISLogDirectory) | Should -Contain 'F:\Binary Logs\W3SVC'
    }

    It 'warns if both APIs cannot determine the logging mode' {
        $script:nativeUnavailable = $true
        $script:webSettings.centralLogFileMode = $null
        $null = Get-IISLogDirectory -IncludeAdditionalLocations -WarningVariable queryWarnings -WarningAction SilentlyContinue
        ($queryWarnings -join ' ') | Should -Match 'centralLogFileMode'
    }

    It 'does not silently substitute a default for an unreadable central path' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        $script:settings['centralW3CLogFile.directory'] = $null
        $script:webSettings['centralW3CLogFile.directory'] = $null
        $result = @(Get-IISLogDirectory -IncludeAdditionalLocations -WarningVariable queryWarnings -WarningAction SilentlyContinue)
        ($queryWarnings -join ' ') | Should -Match 'centralW3CLogFile.directory'
        $result | Should -Not -Contain "$env:SystemDrive\inetPub\logs\LogFiles\W3SVC"
    }

    It 'recovers explicit and inherited per-site directories when Get-Website fails' {
        $script:siteFailure = $true
        $result = @(Get-IISLogDirectory -WarningAction SilentlyContinue)
        $result | Should -Contain 'E:\Custom Site Logs\W3SVC1'
        $result | Should -Contain 'F:\Default Site Logs\W3SVC2'
    }

    It 'recovers per-site overrides without WebAdministration' {
        $script:moduleUnavailable = $true
        @(Get-IISLogDirectory -WarningAction SilentlyContinue) | Should -Contain 'E:\Custom Site Logs\W3SVC1'
    }

    It 'labels the standard-root fallback as unverified if site configuration is unavailable' {
        $script:siteFailure = $true
        $script:nativeUnavailable = $true
        $result = @(Get-IISLogDirectory -WarningVariable queryWarnings -WarningAction SilentlyContinue)
        $result | Should -Contain "$env:SystemDrive\inetPub\logs\LogFiles"
        ($queryWarnings -join ' ') | Should -Match 'unverified fallback'
    }

    It 'expands environment variables in per-site paths' {
        $script:sites[0].LogFile.Directory = '%SystemRoot%\IIS Logs'
        @(Get-IISLogDirectory) | Should -Contain "$env:SystemRoot\IIS Logs\W3SVC1"
    }

    It 'preserves absolute drive roots when appending the central subdirectory' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        $script:settings['centralW3CLogFile.directory'] = 'E:\'
        @(Get-IISLogDirectory -IncludeAdditionalLocations) | Should -Contain 'E:\W3SVC'
    }

    It 'preserves a configured UNC server and share' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        $script:settings['centralW3CLogFile.directory'] = '\\LogServer\Share\IIS Logs\'
        @(Get-IISLogDirectory -IncludeAdditionalLocations) | Should -Contain '\\LogServer\Share\IIS Logs\W3SVC'
    }

    It 'warns about unresolved path variables' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        $script:settings['centralW3CLogFile.directory'] = '%ELC_UNDEFINED_VARIABLE%\Logs'
        $null = Get-IISLogDirectory -IncludeAdditionalLocations -WarningVariable queryWarnings -WarningAction SilentlyContinue
        ($queryWarnings -join ' ') | Should -Match 'environment variable'
    }

    It 'rejects drive-relative paths instead of searching the current directory on that drive' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        $script:settings['centralW3CLogFile.directory'] = 'E:Logs'
        $null = Get-IISLogDirectory -IncludeAdditionalLocations -WarningVariable queryWarnings -WarningAction SilentlyContinue
        ($queryWarnings -join ' ') | Should -Match 'not an absolute'
    }

    It 'warns on unreadable site files without reporting that the directory is empty' {
        Mock -CommandName Get-ChildItem -ParameterFilter { $LiteralPath -eq 'C:\Lab Logs\W3SVC1' } -MockWith { throw 'Access denied.' }
        $result = @(Get-IISLogDirectory -WarningVariable queryWarnings -WarningAction SilentlyContinue)
        $result | Should -Contain 'C:\Lab Logs\W3SVC1'
        ($queryWarnings -join ' ') | Should -Match 'does not mean the directory is empty'
    }

    It 'deduplicates paths ignoring case and trailing directory separators' {
        $script:settings.centralLogFileMode = 'CentralW3C'
        $script:settings['centralBinaryLogFile.directory'] = 'e:\Central Logs\'
        $script:existingCentral = @('E:\Central Logs\W3SVC')
        $result = @(Get-IISLogDirectory -IncludeAdditionalLocations)
        @($result | Where-Object { $_ -ieq 'E:\Central Logs\W3SVC' }) | Should -HaveCount 1
    }

    It 'rejects an inverted collection window' {
        { Get-IISLogDirectory -LogStartDate $script:now -LogEndDate $script:now.AddHours(-1) } | Should -Throw '*window*'
    }
}
