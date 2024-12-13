# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# ImportExcel Functions
# see https://github.com/dfinke/ImportExcel for information on the module.
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
            if (-not $script:IsAdministrator) {
                Write-Host "Please run the script as an administrator to install the ImportExcel module."
                exit
            }

            # Ask user if they want to install the module
            if ($PSCmdlet.ShouldProcess('ImportExcel module', 'Import')) {
                Write-Verbose "Installing ImportExcel module..."

                # Install ImportExcel module
                Install-Module -Name ImportExcel -Force -AllowClobber

                Write-Host -ForegroundColor Green "Done. ImportExcel module is now installed."
                Write-Host -ForegroundColor Yellow "Please rerun the Script to get your Calendar Logs."
                exit
            }
        }
    }
}
