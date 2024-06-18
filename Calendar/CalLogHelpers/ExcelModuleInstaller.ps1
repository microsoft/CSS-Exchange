# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# Excel Functions
# ===================================================================================================
function CheckExcelModuleInstalled {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param ()

    if (Get-Command -Module ImportExcel) {
        Write-Host "ImportExcel module is already installed."
    } else {
        # This is slow, to the tune of ~10 seconds, but much more complete.
        # Check if ImportExcel module is installed
        $moduleInstalled = Get-Module -ListAvailable | Where-Object { $_.Name -eq 'ImportExcel' }

        if ($moduleInstalled) {
            Write-Host "ImportExcel module is already installed."
        } else {
            # Check if running with administrator rights
            $isAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            if (-not $isAdministrator) {
                Write-Host "Please run the script as an administrator to install the ImportExcel module."
                exit
            }

            # Ask user if they want to install the module
            if ($PSCmdlet.ShouldProcess('ImportExcel module', 'Import')) {
                Write-Verbose "Installing ImportExcel module..."

                # Install ImportExcel module
                Install-Module -Name ImportExcel -Force -AllowClobber

                Write-Host "Done. ImportExcel module is now installed."
            }
        }
    }
}
