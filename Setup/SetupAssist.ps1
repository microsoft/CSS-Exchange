# SetupAssist.ps1

function IsAdministrator {
    $ident = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object System.Security.Principal.WindowsPrincipal($ident)
    return $prin.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function GetGroupMatches($whoamiOutput, $groupName) {
    $m = @($whoamiOutput | Select-String "(^\w+\\$($groupName))\W+Group")
    return $m.Matches | ForEach-Object { $_.Groups[1].Value }
}

# From https://stackoverflow.com/questions/47867949/how-can-i-check-for-a-pending-reboot
function Test-PendingReboot {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($null -ne $status) -and $status.RebootPending) {
            return $true
        }
    } catch { }

    return $false
}

if (IsAdministrator) {
    Write-Host "User is an administrator."
} else {
    Write-Warning "User is not an administrator."
}

$whoamiOutput = whoami /all

$g = GetGroupMatches $whoamiOutput "Domain Admins"

if ($g.Count -gt 0) {
    $g | ForEach-Object { Write-Host "User is a member of" $_ }
} else {
    Write-Warning "User is not a member of Domain Admins."
}

$g = GetGroupMatches $whoamiOutput "Schema Admins"

if ($g.Count -gt 0) {
    $g | ForEach-Object { Write-Host "User is a member of" $_ }
} else {
    Write-Warning "User is not a member of Schema Admins."
}

$g = GetGroupMatches $whoamiOutput "Enterprise Admins"

if ($g.Count -gt 0) {
    $g | ForEach-Object { Write-Host "User is a member of" $_ }
} else {
    Write-Warning "User is not a member of Enterprise Admins."
}

$g = GetGroupMatches $whoamiOutput "Organization Management"

if ($g.Count -gt 0) {
    $g | ForEach-Object { Write-Host "User is a member of" $_ }
} else {
    Write-Warning "User is not a member of Organization Management."
}

$p = Get-ExecutionPolicy
if ($p -ne "Unrestricted" -and $p -ne "Bypass") {
    Write-Warning "ExecutionPolicy is $p"
} else {
    Write-Host "ExecutionPolicy is $p"
}

$products = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products
$packageFiles = $products | ForEach-Object { Get-ItemProperty -Path "Registry::$($_.Name)\InstallProperties" -ErrorAction SilentlyContinue } | ForEach-Object { $_.LocalPackage }
$packagesMissing = @($packageFiles | Where-Object { (Test-Path $_) -eq $false })
if ($packagesMissing.Count -eq 0) {
    Write-Host "No installer packages missing."
} else {
    Write-Warning "$($packagesMissing.Count) installer packages are missing. Please use this script to repair the installer folder:"
    Write-Warning "https://gallery.technet.microsoft.com/office/Restore-the-Missing-d11de3a1"
}

$powershellProcesses = @(Get-Process -IncludeUserName powershell)
if ($powershellProcesses.Count -gt 1) {
    Write-Warning "More than one PowerShell process was found. Please close other instances of PowerShell."
    Write-Host ($powershellProcesses | Format-Table -AutoSize | Out-String)
} else {
    Write-Host "No other PowerShell instances were detected."
}

if (Test-PendingReboot) {
    Write-Warning "Reboot pending."
} else {
    Write-Host "No reboot pending."
}