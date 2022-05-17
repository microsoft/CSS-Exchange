# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-WebRequestWithProxyDetection.ps1
. $PSScriptRoot\Confirm-Signature.ps1

function Invoke-ScriptUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([boolean])]
    param ()

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)
    $tempFullName = (Join-Path $env:TEMP $scriptName)

    if ($PSCmdlet.ShouldProcess("$scriptName", "Update script to latest version")) {
        try {
            Invoke-WebRequestWithProxyDetection "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName

            if (Confirm-Signature -File $tempFullName) {
                Write-Host "AutoUpdate: Signature validated."
                if (Test-Path $oldFullName) {
                    Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Move-Item $scriptFullName $oldFullName
                Move-Item $tempFullName $scriptFullName
                Write-Host "AutoUpdate: Succeeded."
                return $true
            } else {
                Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
            }
        } catch {
            Write-Verbose "AutoUpdate: Failed to download update: $($_.Exception.Message)"
        }
    }

    return $false
}
