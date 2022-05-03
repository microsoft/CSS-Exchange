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

            <# TODO: Still need more testing (Making sure it produces same properties)
                try {
                    $shellApplication = New-Object -ComObject "Shell.Application"
                } catch {
                    "Failed to create 'Shell.Application' COM Object. This can lead to issues with validation of the script." | Receive-Output -ForegroundColor Red
                    break
                }
                # One $fileItem Example:
                # $localPackageChildItems = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer" -Recurse | Where-Object { $_.Property -eq "LocalPackage" };
                # $File = [IO.FileInfo]$localPackageChildItems[1].GetValue("LocalPackage");
                # $fileItem = Get-Item $File
                $fileItem = Get-Item $File
                $shellFolder = $shellApplication.NameSpace($fileItem.Directory.FullName)
                $FileInformation = @{}
                $info = 0..320 | ForEach-Object { $_ } | Select-Object @{l = 'no'; e = { $_ } }, @{l = 'variant'; e = { $($shellFolder.GetDetailsOf('', $_)) } }, @{l = 'value'; e = { $($shellFolder.GetDetailsOf($shellFolder.ParseName($fileItem.Name), $_)) } } | Where-Object { $_.value -ne '' -and $_.variant -ne '' }
                foreach ($item in $info) {
                    $FileInformation.Add($item.variant, $item.value)
                }
                $FileInformation = [PSCustomObject]$FileInformation
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
