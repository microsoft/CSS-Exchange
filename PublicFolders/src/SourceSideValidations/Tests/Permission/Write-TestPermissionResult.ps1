function Write-TestPermissionResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $badPermissionCount = 0
    }

    process {
        if ($TestResult.TestName -eq "Permission" -and $TestResult.ResultType -eq "BadPermission") {
            $badPermissionCount++
        }
    }

    end {
        if ($badPermissionCount -gt 0) {
            Write-Host
            Write-Host $badPermissionCount "invalid permissions were found."
            Write-Host "The invalid permissions can be removed using the RemoveInvalidPermissions switch as follows:"
            Write-Host ".\SourceSideValidations.ps1 -Repair" -ForegroundColor Green
        }
    }
}