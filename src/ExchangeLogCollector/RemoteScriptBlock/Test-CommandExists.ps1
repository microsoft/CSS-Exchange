Function Test-CommandExists {
    param(
        [string]$command
    )
    $oldAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"

    try {
        if (Get-Command $command) {
            return $true
        }
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $oldAction
    }
}