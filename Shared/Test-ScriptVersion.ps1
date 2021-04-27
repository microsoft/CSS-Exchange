<#
    Determines if the script has an update available. Use the optional
    -AutoUpdate switch to make it update itself. Returns $true if an
    update was downloaded, $false otherwise. The result will always
    be $false if the -AutoUpdate switch is not used.
#>
function Test-ScriptVersion {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter()]
        [switch]
        $AutoUpdate
    )

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)

    $tempFullName = (Join-Path $env:TEMP $scriptName)

    $BuildVersion = ""
    try {
        $versionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $versionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
        $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
        if ($null -ne $latestVersion -and $latestVersion -ne $BuildVersion) {
            if ($AutoUpdate -and $BuildVersion -ne "") {
                if (Test-Path $tempFullName) {
                    Remove-Item $tempFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Write-Host "AutoUpdate: Downloading update."
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName -UseBasicParsing
                $sig = Get-AuthenticodeSignature $tempFullName
                if ($sig.Status -eq "Valid") {
                    Write-Host "AutoUpdate: File signed by" $sig.SignerCertificate.Subject
                    if (Test-Path $oldFullName) {
                        Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                    }
                    Move-Item $scriptFullName $oldFullName
                    Move-Item $tempFullName $scriptFullName
                    Write-Host "AutoUpdate: Succeeded."
                    return $true
                } else {
                    Write-Warning "Signature could not be verified: $tempFullName."
                    Write-Warning "Update was not applied."
                }
            } else {
                Write-Warning "$scriptName $BuildVersion is outdated. Please download the latest, version $latestVersion."
            }
        }
    } catch {
        # Work around empty catch block rule. The failure is intentionally silent.
        # For example, the script might be running on a computer with no internet access.
        "Version check failed" | Out-Null
    }

    return $false
}
