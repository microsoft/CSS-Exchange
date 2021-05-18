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
        $contextOfError = $SetupLogReviewer.FirstErrorWithContextToLine(-1, 2)

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
        $diagnosticContext.Add("KnownMsiIssuesCheck $($breadCrumb; $breadCrumb++)")

        if ($null -ne $installingProductError) {
            $diagnosticContext.Add("Found MSI Issue - installing product")
            $errorFound = $true
        }

        $installFatalError = $contextOfError | Select-String -Pattern "\[ERROR\] Installing product .+\.msi failed\. Fatal error during installation\. Error code is 1603\."
        $diagnosticContext.Add("KnownMsiIssuesCheck $($breadCrumb; $breadCrumb++)")

        if ($null -ne $installFatalError) {
            $diagnosticContext.Add("Found MSI Issue - Fatal Error")
            $errorFound = $true
        }

        $installingNewProduct = $contextOfError | Select-String -Pattern "Installing a new product\. Package: .+\.msi\. Property values"
        $diagnosticContext.Add("KnownMsiIssuesCheck $($breadCrumb; $breadCrumb++)")

        if ($null -ne $installingNewProduct) {
            $diagnosticContext.Add("Found trying to install product")
            $objectReferenceNotSet = $contextOfError | Select-String -Pattern "\[ERROR\] Object reference not set to an instance of an object\."

            if ($null -ne $objectReferenceNotSet) {
                $diagnosticContext.Add("Found MSI Issue - Object Reference Not Set")
                $errorFound = $true
            }
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
