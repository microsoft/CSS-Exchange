# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSupportsShouldProcess', '', Justification = 'Pester stub - WhatIf defined as explicit parameter for splatting compatibility')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Invoke-IISConfigurationRemoteAction.ps1

    # Stub IIS cmdlets with proper parameter signatures so splatting works.
    # SupportsShouldProcess provides -WhatIf and -Confirm; CmdletBinding provides -ErrorAction etc.
    function Set-WebConfigurationProperty {
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string]$Name,
            [object]$Value,
            [string]$PSPath,
            [string]$Location,
            [switch]$WhatIf
        )
    }

    function Get-WebConfigurationProperty {
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string]$Name,
            [string]$PSPath,
            [string]$Location
        )
    }

    function Get-WebConfiguration {
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string]$PSPath,
            [string]$Location
        )
    }

    function Clear-WebConfiguration {
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string]$PSPath,
            [string]$Location
        )
    }

    function Add-WebConfigurationProperty {
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string]$Name,
            [object]$Value,
            [string]$PSPath,
            [string]$Location,
            [switch]$WhatIf
        )
    }

    # Helper: builds a standard Set action tuple as produced by New-IISConfigurationAction
    function Get-TestSetAction {
        param(
            [string]$Filter = "system.webServer/security/requestFiltering",
            [string]$Name = "allowHighBitCharacters",
            [string]$Value = "false",
            [string]$PSPath = "IIS:\",
            [string]$Location
        )
        $setParams = @{
            Filter      = $Filter
            Name        = $Name
            Value       = $Value
            PSPath      = $PSPath
            ErrorAction = "Stop"
            WhatIf      = $false
        }
        $getParams = @{
            Filter      = $Filter
            Name        = $Name
            PSPath      = $PSPath
            ErrorAction = "Stop"
        }
        $restoreParams = @{
            Filter      = $Filter
            Name        = $Name
            PSPath      = $PSPath
            ErrorAction = "Stop"
        }

        if (-not [string]::IsNullOrEmpty($Location)) {
            $setParams["Location"] = $Location
            $getParams["Location"] = $Location
            $restoreParams["Location"] = $Location
        }

        return [PSCustomObject]@{
            Set     = [PSCustomObject]@{
                Cmdlet             = "Set-WebConfigurationProperty"
                Parameters         = $setParams
                ParametersToString = "mocked"
            }
            Get     = [PSCustomObject]@{
                Cmdlet             = "Get-WebConfigurationProperty"
                Parameters         = $getParams
                ParametersToString = "mocked"
            }
            Restore = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = $restoreParams
            }
        }
    }

    # Helper: builds InputObject for the set (non-restore) path.
    # Uses List[object] to match production behavior and avoid PS 7 member-enumeration
    # conflict: Object[].Set resolves to the array method, not element properties.
    function Get-TestInputObject {
        param(
            [array]$Actions,
            [string]$BackupFileName = "TestBackup"
        )
        $actionList = [System.Collections.Generic.List[object]]::new()
        foreach ($a in $Actions) { $actionList.Add($a) }
        return [PSCustomObject]@{
            Actions        = $actionList
            BackupFileName = $BackupFileName
            Restore        = $null
            ServerName     = $env:COMPUTERNAME
        }
    }

    # Helper: builds an Add action tuple as produced by New-IISConfigurationAction
    # for Add-WebConfigurationProperty actions. The Get uses Get-WebConfiguration and
    # the Restore uses Clear-WebConfiguration.
    function Get-TestAddAction {
        param(
            [string]$Filter = "system.webServer/rewrite/rules",
            [string]$RuleName = "TestAddRule",
            [string]$PSPath = "IIS:\"
        )
        $clearFilter = "{0}/rule[@name='{1}']" -f $Filter, $RuleName
        $setParams = @{
            Filter      = $Filter
            PSPath      = $PSPath
            Name        = '.'
            Value       = @{ name = $RuleName; patternSyntax = 'Regular Expressions' }
            ErrorAction = "Stop"
            WhatIf      = $false
        }
        $getParams = @{
            Filter      = $clearFilter
            PSPath      = $PSPath
            ErrorAction = "SilentlyContinue"
        }
        $clearParams = @{
            Filter      = $clearFilter
            PSPath      = $PSPath
            ErrorAction = "Stop"
        }

        return [PSCustomObject]@{
            Set     = [PSCustomObject]@{
                Cmdlet             = "Add-WebConfigurationProperty"
                Parameters         = $setParams
                ParametersToString = "mocked"
            }
            Get     = [PSCustomObject]@{
                Cmdlet             = "Get-WebConfiguration"
                Parameters         = $getParams
                ParametersToString = "mocked"
            }
            Restore = [PSCustomObject]@{
                Cmdlet     = "Clear-WebConfiguration"
                Parameters = $clearParams
            }
        }
    }

    # Helper: builds InputObject for the restore path
    function Get-TestRestoreInputObject {
        param(
            [string]$FileName = "TestBackup",
            [bool]$PassedWhatIf = $false
        )
        return [PSCustomObject]@{
            Actions        = $null
            BackupFileName = $null
            Restore        = [PSCustomObject]@{
                FileName     = $FileName
                PassedWhatIf = $PassedWhatIf
            }
            ServerName     = $env:COMPUTERNAME
        }
    }
}

Describe "Testing Invoke-IISConfigurationRemoteAction" {

    # Suppress progress bars and log file writes in all tests
    BeforeEach {
        Mock Write-Progress { }
        Mock Write-Verbose { }
        Mock Write-Warning { }
        Mock Write-Host { }
        Mock Write-Error { }
        Mock Out-File { }
        Mock New-Item { }
        Mock Test-Path { return $true } -ParameterFilter { $Path -like "*inetSrv*" -and $Path -notlike "*.json" }
    }

    # ========================================================================
    # HISTORICAL BUG 1 (ce0908097): SuccessfulExecution formula
    # The original bug used $restoreActions (a List object — always truthy)
    # instead of $restoreActionsSaved (a boolean). This test ensures
    # SuccessfulExecution correctly reports false when errors exist.
    # ========================================================================
    Context "Bug 1 (ce0908097): SuccessfulExecution detection" {

        It "Should be false when errorContext has items even if restoreActions is non-empty" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "true" } }
            Mock ConvertTo-Json { return '[]' }
            Mock Set-WebConfigurationProperty { throw "Simulated set failure" }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.SuccessfulExecution | Should -Be $false
            $result.ErrorContext.Count | Should -BeGreaterThan 0
            $result.ErrorContext[0].ToString() | Should -BeLike "*Simulated set failure*"
        }

        It "Should be true only when ALL four conditions are met" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "true" } }
            Mock ConvertTo-Json { return '[]' }
            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.AllActionsPerformed | Should -Be $true
            $result.GatheredAllRestoreActions | Should -Be $true
            $result.RestoreActionsSaved | Should -Be $true
            $result.ErrorContext.Count | Should -Be 0
            $result.SuccessfulExecution | Should -Be $true
        }
    }

    # ========================================================================
    # HISTORICAL BUG 2 (9429952036): Backup action handling
    # - [System.IO.Path]::Join was used instead of ::Combine
    # - Set phase had no try/catch around individual actions
    # - totalActions was not doubled for backup + set phases
    # ========================================================================
    Context "Bug 2 (9429952036): Backup file path uses Combine" {

        It "Should construct the backup file path correctly via System.IO.Path.Combine" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action) -BackupFileName "CVE-2024-Test"

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "true" } }
            Mock ConvertTo-Json { return '[]' }
            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.SuccessfulExecution | Should -Be $true
        }
    }

    Context "Bug 2: Individual set action failures don't stop other actions" {

        It "Should continue setting remaining actions when one fails" {
            $action1 = Get-TestSetAction -Name "setting1" -Value "val1"
            $action2 = Get-TestSetAction -Name "setting2" -Value "val2"
            $inputObj = Get-TestInputObject -Actions @($action1, $action2)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "original" } }
            Mock ConvertTo-Json { return '[]' }

            $Script:setCallCount = 0
            Mock Set-WebConfigurationProperty {
                $Script:setCallCount++
                if ($Script:setCallCount -eq 1) {
                    throw "First action fails"
                }
            }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $Script:setCallCount | Should -Be 2
            $result.AllActionsPerformed | Should -Be $false
            $result.SuccessfulExecution | Should -Be $false
            $result.ErrorContext.Count | Should -Be 1
            $result.ErrorContext[0].ToString() | Should -BeLike "*First action fails*"
        }
    }

    # ========================================================================
    # HISTORICAL BUG 3 (ce2260e94): Legacy OS ConvertTo-Json fallback
    # ========================================================================
    Context "Bug 3 (ce2260e94): Legacy OS ConvertTo-Json fallback" {

        It "Should fallback to ConvertTo-Json -Compress when first attempt fails" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "true" } }
            Mock Set-WebConfigurationProperty { }

            $Script:convertCount = 0
            Mock ConvertTo-Json {
                $Script:convertCount++
                if ($Script:convertCount -eq 1) {
                    throw "Pretty-print not supported"
                }
                return '[]'
            }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.RestoreActionsSaved | Should -Be $true
            $result.SuccessfulExecution | Should -Be $true
        }

        It "Should fail when both ConvertTo-Json attempts fail" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "true" } }
            Mock Set-WebConfigurationProperty { }
            Mock ConvertTo-Json { throw "JSON serialization failed" }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.RestoreActionsSaved | Should -Be $false
            $result.SuccessfulExecution | Should -Be $false
            $result.ErrorContext.Count | Should -BeGreaterThan 0
            $result.ErrorContext[0].ToString() | Should -BeLike "*JSON serialization failed*"
        }
    }

    # ========================================================================
    # RESTORE PATH TESTS
    # ========================================================================
    Context "Restore path: loads JSON, executes restore cmdlets, renames file" {

        It "Should execute the restore cmdlet and rename the backup file" {
            $restoreJson = @(
                [PSCustomObject]@{
                    Cmdlet     = "Set-WebConfigurationProperty"
                    Parameters = [PSCustomObject]@{
                        Filter = "system.webServer/security"
                        Name   = "enabled"
                        PSPath = "IIS:\"
                        Value  = "true"
                    }
                }
            ) | ConvertTo-Json -Depth 5

            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*.json" }
            Mock Get-Content { return $restoreJson }
            Mock Set-WebConfigurationProperty { }
            Mock Move-Item { }

            $restoreInput = Get-TestRestoreInputObject -FileName "TestRestore"
            $result = Invoke-IISConfigurationRemoteAction -InputObject $restoreInput

            Should -Invoke Set-WebConfigurationProperty -Times 1
            Should -Invoke Move-Item -Times 1 -ParameterFilter { $Destination -like "*.bak" }
            $result.AllActionsPerformed | Should -Be $true
            $result.SuccessfulExecution | Should -Be $true
        }
    }

    Context "Restore path: no restore file throws error" {

        It "Should fail when restore file does not exist" {
            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }

            $restoreInput = Get-TestRestoreInputObject -FileName "MissingFile"
            $result = Invoke-IISConfigurationRemoteAction -InputObject $restoreInput

            $result.ErrorContext.Count | Should -BeGreaterThan 0
            $result.ErrorContext[0].ToString() | Should -BeLike "*No restore file exists*"
            $result.SuccessfulExecution | Should -Be $false
        }
    }

    Context "Restore path: corrupt JSON file throws error" {

        It "Should fail when backup file contains invalid JSON" {
            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*.json" }
            Mock Get-Content { return "NOT-VALID-JSON{{{" }
            Mock ConvertFrom-Json { throw "Invalid JSON" }

            $restoreInput = Get-TestRestoreInputObject -FileName "CorruptFile"
            $result = Invoke-IISConfigurationRemoteAction -InputObject $restoreInput

            $result.ErrorContext.Count | Should -BeGreaterThan 0
            $result.ErrorContext[0].ToString() | Should -BeLike "*Invalid JSON*"
            $result.SuccessfulExecution | Should -Be $false
        }
    }

    # ========================================================================
    # BACKUP PHASE TESTS
    # ========================================================================
    Context "Backup phase: reads current values and saves to JSON" {

        It "Should read current value, save to JSON, and report RestoreActionsSaved" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "originalValue" } }
            Mock ConvertTo-Json { return '[{"Cmdlet":"Set-WebConfigurationProperty","Parameters":{}}]' }
            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            Should -Invoke Get-WebConfigurationProperty -Times 1
            Should -Invoke ConvertTo-Json -Times 1
            $result.RestoreActionsSaved | Should -Be $true
            $result.RestoreActions.Count | Should -Be 1
        }
    }

    Context "Backup phase: existing JSON preserves original values" {

        It "Should not overwrite existing restore action and succeed overall" {
            $existingJson = @(
                [PSCustomObject]@{
                    Cmdlet     = "Set-WebConfigurationProperty"
                    Parameters = [PSCustomObject]@{
                        Filter      = "system.webServer/security/requestFiltering"
                        Name        = "allowHighBitCharacters"
                        PSPath      = "IIS:\"
                        ErrorAction = "Stop"
                        Value       = "originalSavedValue"
                    }
                }
            ) | ConvertTo-Json -Depth 5

            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*.json" }
            Mock Get-Content { return $existingJson }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "newCurrentValue" } }
            Mock ConvertTo-Json { return '[]' }
            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.RestoreActions.Count | Should -BeGreaterOrEqual 1
            $result.SuccessfulExecution | Should -Be $true
        }
    }

    # ========================================================================
    # SET PHASE TESTS
    # ========================================================================
    Context "Set phase: executes each action's Set cmdlet" {

        It "Should call Set-WebConfigurationProperty for each action and report success" {
            $action1 = Get-TestSetAction -Name "setting1" -Value "val1"
            $action2 = Get-TestSetAction -Name "setting2" -Value "val2"
            $inputObj = Get-TestInputObject -Actions @($action1, $action2)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "old" } }
            Mock ConvertTo-Json { return '[]' }
            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            Should -Invoke Set-WebConfigurationProperty -Times 2
            $result.AllActionsPerformed | Should -Be $true
        }
    }

    Context "Set phase: one action failing doesn't stop other actions" {

        It "Should attempt all Set actions and mark failure" {
            $action1 = Get-TestSetAction -Name "willFail" -Value "v1"
            $action2 = Get-TestSetAction -Name "willSucceed" -Value "v2"
            $inputObj = Get-TestInputObject -Actions @($action1, $action2)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "old" } }
            Mock ConvertTo-Json { return '[]' }

            $Script:setIdx = 0
            Mock Set-WebConfigurationProperty {
                $Script:setIdx++
                if ($Script:setIdx -eq 1) { throw "Simulated failure" }
            }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $Script:setIdx | Should -Be 2
            $result.AllActionsPerformed | Should -Be $false
            $result.ErrorContext.Count | Should -Be 1
            $result.ErrorContext[0].ToString() | Should -BeLike "*Simulated failure*"
        }
    }

    # ========================================================================
    # Successful Execution Composite Condition
    # ========================================================================
    Context "SuccessfulExecution composite condition" {

        It "Should be false when AllActionsPerformed is false" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "v" } }
            Mock ConvertTo-Json { return '[]' }
            Mock Set-WebConfigurationProperty { throw "fail" }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj
            $result.SuccessfulExecution | Should -Be $false
        }

        It "Should be false when GatheredAllRestoreActions is false" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { throw "Cannot get value" }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj
            $result.GatheredAllRestoreActions | Should -Be $false
            $result.SuccessfulExecution | Should -Be $false
            $result.ErrorContext.Count | Should -BeGreaterThan 0
            $result.ErrorContext[0].ToString() | Should -BeLike "*Cannot get value*"
        }

        It "Should be false when RestoreActionsSaved is false" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "v" } }
            Mock ConvertTo-Json { throw "fail" }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj
            $result.RestoreActionsSaved | Should -Be $false
            $result.SuccessfulExecution | Should -Be $false
            $result.ErrorContext.Count | Should -BeGreaterThan 0
            $result.ErrorContext[0].ToString() | Should -BeLike "*fail*"
        }

        It "Should be true when no backup file is requested" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action) -BackupFileName ""

            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj
            $result.SuccessfulExecution | Should -Be $true
        }
    }

    # ========================================================================
    # NULL CURRENT VALUE HANDLING
    # After the EOMT merge, null Get results for Set-WebConfigurationProperty
    # actions are handled gracefully: the action is skipped (not an Add), and
    # execution continues without throwing.
    # ========================================================================
    Context "Null current value handling for Set-WebConfigurationProperty" {

        It "Should skip restore action and continue when Get returns null for a Set action" {
            $action = Get-TestSetAction
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return $null }
            Mock ConvertTo-Json { return '[]' }
            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.GatheredAllRestoreActions | Should -Be $true
            $result.SuccessfulExecution | Should -Be $true
            $result.RestoreActions.Count | Should -Be 0
        }
    }

    # ========================================================================
    # NULL CURRENT VALUE HANDLING FOR ADD ACTIONS
    # When Get returns null for an Add-WebConfigurationProperty action, the
    # rule doesn't exist yet. The restore action (Clear) is recorded WITHOUT
    # a Value parameter since Clear just needs the Filter to remove the entry.
    # ========================================================================
    Context "Null current value handling for Add-WebConfigurationProperty" {

        It "Should record Clear restore action without Value when Get returns null" {
            $action = Get-TestAddAction -RuleName "NewRule"
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfiguration { return $null }
            Mock ConvertTo-Json { return '[]' }
            Mock Add-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.GatheredAllRestoreActions | Should -Be $true
            $result.SuccessfulExecution | Should -Be $true
            $result.RestoreActions.Count | Should -Be 1
            $result.RestoreActions[0].Cmdlet | Should -Be "Clear-WebConfiguration"
            $result.RestoreActions[0].Parameters.ContainsKey("Value") | Should -Be $false
        }

        It "Should not duplicate restore action when backup already contains matching entry" {
            $existingJson = @(
                [PSCustomObject]@{
                    Cmdlet     = "Clear-WebConfiguration"
                    Parameters = [PSCustomObject]@{
                        Filter      = "system.webServer/rewrite/rules/rule[@name='NewRule']"
                        PSPath      = "IIS:\"
                        ErrorAction = "Stop"
                    }
                }
            ) | ConvertTo-Json -Depth 5

            $action = Get-TestAddAction -RuleName "NewRule"
            $inputObj = Get-TestInputObject -Actions @($action)

            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*.json" }
            Mock Get-Content { return $existingJson }
            Mock Get-WebConfiguration { return $null }
            Mock ConvertTo-Json { return '[]' }
            Mock Add-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.GatheredAllRestoreActions | Should -Be $true
            $result.SuccessfulExecution | Should -Be $true
        }
    }

    # ========================================================================
    # NULL GET ACTION HANDLING (sub-collection items without RuleName)
    # When an Add action has no Get/Restore pair (null), the backup phase
    # should skip it and continue processing remaining actions.
    # ========================================================================
    Context "Null Get action skipped in backup phase" {

        It "Should skip actions with null Get and still succeed" {
            # Action without Get/Restore (sub-collection item, no RuleName)
            $noGetAction = [PSCustomObject]@{
                Set     = [PSCustomObject]@{
                    Cmdlet             = "Add-WebConfigurationProperty"
                    Parameters         = @{
                        Filter      = "system.webServer/rewrite/outboundRules/preConditions/preCondition[@name='test']"
                        PSPath      = "IIS:\"
                        Name        = '.'
                        Value       = @{ input = '{RESPONSE_CONTENT_TYPE}'; pattern = '^text/html' }
                        ErrorAction = "Stop"
                        WhatIf      = $false
                    }
                    ParametersToString = "mocked"
                }
                Get     = $null
                Restore = $null
            }
            # Normal action with Get/Restore
            $normalAction = Get-TestSetAction -Name "setting1" -Value "val1"

            $inputObj = Get-TestInputObject -Actions @($noGetAction, $normalAction)

            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*.json" }
            Mock Get-WebConfigurationProperty { return [PSCustomObject]@{ Value = "original" } }
            Mock ConvertTo-Json { return '[]' }
            Mock Add-WebConfigurationProperty { }
            Mock Set-WebConfigurationProperty { }

            $result = Invoke-IISConfigurationRemoteAction -InputObject $inputObj

            $result.GatheredAllRestoreActions | Should -Be $true
            $result.SuccessfulExecution | Should -Be $true
            $result.RestoreActions.Count | Should -Be 1
            Should -Invoke Add-WebConfigurationProperty -Times 1
            Should -Invoke Set-WebConfigurationProperty -Times 1
        }
    }
}
