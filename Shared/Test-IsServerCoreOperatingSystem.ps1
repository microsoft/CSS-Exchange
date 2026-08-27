# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    This function determines whether the script is running on a Windows Server Core installation.
    Server Core does not include the components required to launch a browser, which some callers, like the OAuth 2.0 authorization code
    flow depends on. It is detected via the "InstallationType" registry value, which is set to "Server Core"
    on a Server Core installation. Any failure (for example, on a non-Windows host where the registry path does not exist)
    is treated as "not Server Core" so that callers can safely fall back to the default authorization code flow.
#>
function Test-IsServerCoreOperatingSystem {
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    try {
        $installationType = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallationType" -ErrorAction Stop).InstallationType
        Write-Verbose "InstallationType registry value: '$installationType'"

        return ($installationType -eq "Server Core")
    } catch {
        Write-Verbose "Unable to determine the InstallationType - assuming this is not a Server Core installation"

        return $false
    }
}
