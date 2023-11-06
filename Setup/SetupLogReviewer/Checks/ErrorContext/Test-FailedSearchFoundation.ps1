# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
function Test-FailedSearchFoundation {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $searchInstallMode = $errorContext | Select-String -Pattern "was run: `"System.Exception: Failure configuring SearchFoundation through InstallConfig.ps1 - Old nodes belonging to the system 'Fsis', already exist in"

        if ($null -ne $searchInstallMode) {
            Write-Verbose "Found Search Foundation Install Mode Failure"
            $errorContext |
                Select-Object -Last ($errorContext.Count - ($searchInstallMode.LineNumber | Select-Object -Last 1) + 3) |
                New-ErrorContext
            New-ActionPlan @(
                "- Make sure the Microsoft Exchange Host Controller and Microsoft Exchange Search service is not running and not disabled.",
                "- Uninstall the Search Foundation",
                "       1. Remove all SubFolders under C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data\Nodes\Fsis",
                "       2. Open Powershell as Administrator and navigate to the folder C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Installer",
                "       3. Now uninstall the Search Foundation with this command: .\InstallConfig.ps1 -action U -DataFolder `"C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data`""
                "       4. Run Setup again."
            )
            return
        }

        $searchFoundation = $errorContext | Select-String -Pattern "was run: `"System.Exception: Failure configuring SearchFoundation through InstallConfig.ps1"

        if ($null -ne $searchFoundation) {
            Write-Verbose "Found Search Foundation failure"
            $errorContext |
                Select-Object -Last ($errorContext.Count - ($searchFoundation.LineNumber | Select-Object -Last 1) + 3) |
                New-ErrorContext

            New-ActionPlan @(
                "- Make sure the Microsoft Exchange Search Host Controller and Microsoft Exchange Search service is not disabled and started."
                "- Make sure that all 4 noderunner.exe processes are able to start and run. If they aren't able to troubleshoot that.",
                "- Try to manually configure the Search Foundation by following these steps, and troubleshoot why it might be failing before trying setup again:",
                "     1. Stop the Microsoft Exchange Search and Microsoft Exchange Search Host Controller services.",
                "     2. Remove all SubFolders under C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data\Nodes\Fsis",
                "     3. Open Powershell as Administrator and navigate to the folder C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Installer",
                "     4. Now uninstall the Search Foundation with this command: .\InstallConfig.ps1 -action U -DataFolder `"C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data`""
                "     5. Now install the Search Foundation with this command: .\InstallConfig.ps1 -action I -DataFolder `"C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data`""
            )
        }
    }
}
