# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Shared\Write-ErrorInformation.ps1
function Get-UnifiedContentInformation {
    [CmdletBinding()]
    param()
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $cleanupFolderValue = [string]::Empty
        $antiMalwareFilePath = [string]::Empty
        $success = $false
        $validSetting = $false
        $foundAntiMalwareFile = $false

        try {
            $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction Stop).MsiInstallPath
        } catch {
            Write-VerboseErrorInformation
            Write-Verbose "Failed to determine Exchange Install path"
            return
        }

        try {
            $appConfig = [System.Configuration.ConfigurationManager]::OpenExeConfiguration("$installDirectory`Bin\EdgeTransport.exe")
            $temporaryStoragePath = "$($appConfig.AppSettings.Settings["TemporaryStoragePath"].Value)\UnifiedContent"
        } catch {
            Write-VerboseErrorInformation
            Write-Verbose "Failed to determine TemporaryStoragePath"
            return
        }

        $defaultUnifiedContentPath = "$installDirectory`TransportRoles\data\Temp\UnifiedContent"
        $antiMalwareFilePath = "$installDirectory`Bin\Monitoring\Config\AntiMalware.xml"
        $foundAntiMalwareFile = Test-Path $antiMalwareFilePath

        if (-not ($foundAntiMalwareFile)) {
            Write-Verbose "Failed to find the AntiMalware.xml file"
            return
        }

        try {
            $loadAntiMalwareFile = New-Object System.Xml.XmlDocument
            $loadAntiMalwareFile.PreserveWhitespace = $true
            $loadAntiMalwareFile.Load($antiMalwareFilePath)
            $cleanupFolderValue = $loadAntiMalwareFile.Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths
        } catch {
            Write-VerboseErrorInformation
            Write-Verbose "Failed to determine value of CleanupFolderResponderFolderPaths"
        }

        $paths = @("D:\ExchangeTemp\TransportCts\UnifiedContent", "C:\Windows\Temp\UnifiedContent", $defaultUnifiedContentPath)
        $splitCleanupFolderValue = $cleanupFolderValue.Split(";")

        if ($defaultUnifiedContentPath -ne $temporaryStoragePath) {
            Write-Verbose "TemporaryStoragePath does not equal default installed Temporary Unified Content Path based off of install location."
            Write-Verbose "Adding both locations to make sure the Unified Content is removed by maintenance."
            $paths += $temporaryStoragePath
        }

        $failed = $false
        $expectedCleanupFolderValue = [string]::Empty

        foreach ($expectedPath in $paths) {
            $expectedCleanupFolderValue += "$expectedPath;"
            if (-not ($splitCleanupFolderValue.ToLower().Contains($expectedPath.ToLower()))) {
                Write-Verbose "Failed to find expected path $expectedPath"
                $failed = $true
            } else {
                Write-Verbose "Found expected path $expectedPath"
            }
        }

        $validSetting = $failed -eq $false
        $success = $true
    } end {
        return [PSCustomObject]@{
            Success                    = $success
            FoundAntiMalwareFile       = $foundAntiMalwareFile
            ValidSetting               = $validSetting
            LoadAntiMalwareFile        = $loadAntiMalwareFile
            AntiMalwareFilePath        = $antiMalwareFilePath
            CleanupFolderValue         = $cleanupFolderValue
            ExpectedCleanupFolderValue = $expectedCleanupFolderValue.TrimEnd(";")
        }
    }
}
