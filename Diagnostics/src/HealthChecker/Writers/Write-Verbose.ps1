Function Write-Verbose {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {
        #write to the debug log and call Write-Verbose normally
        Write-DebugLog $Message
        Microsoft.PowerShell.Utility\Write-Verbose $Message
    }
}
