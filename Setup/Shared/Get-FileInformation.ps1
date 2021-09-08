# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-FileInformation {
    [CmdletBinding()]
    param(
        [IO.FileInfo]$File,
        [bool]$AllowFileSubjectOnly = $false
    )
    begin {
        $installerCOM = $null
        $installerCOM = New-Object -ComObject "WindowsInstaller.Installer"
        $subject = [string]::Empty
        $revNumber = [string]::Empty
    }
    process {

        if (-not($installerCOM) -and
            -not($AllowFileSubjectOnly)) {
            throw "Failed to create 'WindowsInstaller.Installer' COM object. This can lead to issues with validation of the script."
        }

        try {

            if ($installerCOM) {
                #This would be nice to have i think. Not fully sure how to call it however.
                #https://docs.microsoft.com/en-us/windows/win32/msi/installer-fileversion

                #https://docs.microsoft.com/en-us/windows/win32/msi/installer-summaryinformation
                $summaryInformation = $installerCOM.GetType().InvokeMember("SummaryInformation", [System.Reflection.BindingFlags]::GetProperty, $null, $installerCOM, @($File.FullName, 0))
                #https://docs.microsoft.com/en-us/windows/win32/msi/summaryinfo-summaryinfo
                $subject = $summaryInformation.GetType().InvokeMember("Property", [System.Reflection.BindingFlags]::GetProperty, $null, $summaryInformation, @(3))
                $revNumber = $summaryInformation.GetType().InvokeMember("Property", [System.Reflection.BindingFlags]::GetProperty, $null, $summaryInformation, @(9))
                return
            }

            <#
TODO: Fix this code. Clearly didn't finish it.
        $shellApplication = New-Object -ComObject "Shell.Application"

        if (-not($shellApplication)) {
            "Failed to create 'Shell.Application' COM Object. This can lead to issues with validation of the script." | Receive-Output -ForegroundColor Red
            exit
        }

        $fileItem = Get-Item $File
        $shellFolder = $shellApplication.NameSpace($fileItem.Directory.FullName)
        $subject = $shellFolder.GetDetailsOf($shellFolder.ParseName($fileItem.Name), 22)
#>
        } catch {
            Write-Host "$($_.Exception)"
            Write-Host "$($_.ScriptStackTrace)"
            throw "Failed to properly process file $($File.FullName) to get required MSI information"
        }
    }
    end {
        return [PSCustomObject]@{
            FilePath       = $File.FullName
            Subject        = $subject
            RevisionNumber = $revNumber.ToUpper()
        }
    }
}
