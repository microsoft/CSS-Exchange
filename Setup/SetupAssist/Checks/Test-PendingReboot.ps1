# From https://stackoverflow.com/questions/47867949/how-can-i-check-for-a-pending-reboot
function Test-PendingReboot {
    if (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) {
        "Key set in: HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending. Remove it if reboot doesn't work" | Receive-Output -Diagnostic
        ("To Fix, only after reboot does work: `r`n`t" + `
                "Open regedit, find HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing.`r`n`t" + `
                "1. If you see PackagesPending, right click it, open Permissions, click on Advanced, change owner to your account. Close Advanced window.`r`n`t`t" + `
                "Give your account Full Control in Permissions window. Delete the key.`r`n`t" + `
                "2. Repeat step 1. with Reboot Pending") | Receive-Output -Diagnostic
        return $true
    }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) {
        "Key exists at: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired. Remove it if reboot doesn't work" | Receive-Output -Diagnostic
        return $true
    }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) {
        "Key set at: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager - PendingFileRenameOperations. Remove it if reboot doesn't work"  | Receive-Output -Diagnostic
        return $true
    }
    try {
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()

        if (($null -ne $status) -and $status.RebootPending) {
            return $true
        }
    } catch {
        "Bypass empty catch block" | Out-Null
    }

    return $false
}
