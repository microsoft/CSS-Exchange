Function Test-KnownMsiIssuesCheck {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )

    begin {
        $diagnosticContext = New-Object 'System.Collections.Generic.List[string]'
        $displayContext = New-Object 'System.Collections.Generic.List[PSCustomObject]'
        $foundKnownIssue = $true
        $actionPlan = New-Object 'System.Collections.Generic.List[string]'
        $errorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeErrorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeWarning = [string]::Empty
        $breadCrumb = 0
        $errorFound = $false
    }
    process {
        $diagnosticContext.Add("KnownMsiIssuesCheck $($breadCrumb; $breadCrumb++)")
        $contextOfError = $SetupLogReviewer.FirstErrorWithContextToLine(-1)

        if ($null -eq $contextOfError) {
            $diagnosticContext.Add("KnownMsiIssuesCheck - no known issue")
            $foundKnownIssue = $false
            return
        }
        $productError = $contextOfError | Select-String -Pattern "Couldn't remove product with code (.+). The installation source for this product is not available"
        $diagnosticContext.Add("KnownMsiIssuesCheck $($breadCrumb; $breadCrumb++)")

        if ($null -ne $productError) {
            $diagnosticContext.Add("Found MSI issue")
            $errorFound = $true
        }

        $installingProductError = $contextOfError | Select-String -Pattern "\[ERROR\] Installing product .+ failed\. The installation source for this product is not available"

        if ($null -ne $installingProductError) {
            $diagnosticContext.Add("Found MSI Issue - installing product")
            $errorFound = $true
        }

        if ($errorFound) {
            $contextOfError |
                Select-Object -First 10 |
                ForEach-Object { $writeErrorContext.Add($_) }
            $actionPlan.Add("Need to run FixInstallerCache.ps1 against $($SetupLogReviewer.LocalBuildNumber)")
            return
        }

        $diagnosticContext.Add("KnownMsiIssuesCheck - no known issue")
        $foundKnownIssue = $false
    }
    end {
        return [PSCustomObject]@{
            DiagnosticContext = $diagnosticContext
            DisplayContext    = $displayContext
            FoundKnownIssue   = $foundKnownIssue
            ActionPlan        = $actionPlan
            ErrorContext      = $errorContext
            WriteErrorContext = $writeErrorContext
            WriteWarning      = $writeWarning
        }
    }
}