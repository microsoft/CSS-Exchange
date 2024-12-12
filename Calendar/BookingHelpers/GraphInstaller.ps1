# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# Graph Modules installer Functions
# ===================================================================================================
function CheckGraphBookingsModuleInstalled {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param ()

    if (Get-Command -Module Microsoft.Graph.Bookings) {
        Write-Host "Microsoft.Graph.Bookings module is already installed."
    } else {
        # This is slow, to the tune of ~10 seconds, but much more complete.
        # Check if Microsoft.Graph.Bookings module is installed
        $ModuleInstalled = Get-Module -ListAvailable | Where-Object { $_.Name -eq 'Microsoft.Graph.Bookings' }

        if ($ModuleInstalled) {
            Write-Host "Microsoft.Graph.Bookings module is already installed."
        } else {
            # Check if running with administrator rights
            if (-not $script:IsAdministrator) {
                Write-Host "Please run the script as an administrator to install the Microsoft.Graph.Bookings module."
                exit
            }

            # Ask user if they want to install the module
            if ($PSCmdlet.ShouldProcess('Microsoft.Graph.Bookings module', 'Import')) {
                Write-Verbose "Installing Microsoft.Graph.Bookings module..."

                # Install Microsoft.Graph.Bookings module
                Install-Module -Name Microsoft.Graph.Bookings -Force -AllowClobber

                Write-Host "Done. Microsoft.Graph.Bookings module is now installed. Please re-run the script."
            }
        }
    }
}

function CheckGraphAuthModuleInstalled {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param ()

    if (Get-Command -Module Microsoft.Graph.Authentication) {
        Write-Host "Microsoft.Graph.Authentication module is already installed."
    } else {
        # This is slow, to the tune of ~10 seconds, but much more complete.
        # Check if Microsoft.Graph.Authentication module is installed
        $ModuleInstalled = Get-Module -ListAvailable | Where-Object { $_.Name -eq 'Microsoft.Graph.Authentication' }

        if ($ModuleInstalled) {
            Write-Host "Microsoft.Graph.Authentication module is already installed."
        } else {
            # Check if running with administrator rights
            if (-not $script:IsAdministrator) {
                Write-Host "Please run the script as an administrator to install the Microsoft.Graph.Authentication module."
                exit
            }

            # Ask user if they want to install the module
            if ($PSCmdlet.ShouldProcess('Microsoft.Graph.Authentication module', 'Import')) {
                Write-Verbose "Installing Microsoft.Graph.Authentication module..."

                # Install Microsoft.Graph.Authentication module
                Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber

                Write-Host "Done. Microsoft.Graph.Authentication module is now installed. Please re-run the script."
            }
        }
    }
}

function CheckGraphModulesInstalled {

    $ModuleAuthInstalled = ($null -ne (Get-Command -Module Microsoft.Graph.Authentication))
    $ModuleBookingsInstalled = ($null -ne (Get-Command -Module Microsoft.Graph.Bookings))

    Write-Verbose "Microsoft.Graph.Authentication module installed: $ModuleAuthInstalled"
    Write-Verbose "Microsoft.Graph.Bookings module installed: $ModuleBookingsInstalled"

    return [bool]($ModuleAuthInstalled -and $ModuleBookingsInstalled)
}
