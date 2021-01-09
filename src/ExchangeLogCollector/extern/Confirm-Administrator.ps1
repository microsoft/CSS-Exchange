#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Common/Confirm-Administrator/Confirm-Administrator.ps1
#v21.01.08.2133
Function Confirm-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    } else {
        return $false
    }
}
