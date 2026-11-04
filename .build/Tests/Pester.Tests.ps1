# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Describe 'Pester runner branch selection' {
    BeforeAll {
        $Script:runnerPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Pester.ps1'

        if (-not ('PesterRunnerTestJob' -as [type])) {
            Add-Type -TypeDefinition @'
using System.Management.Automation;
public sealed class PesterRunnerTestJob : Job {
    public PesterRunnerTestJob(string name) : base("fixture", name) {
        SetJobState(JobState.Running);
        SetJobState(JobState.Completed);
    }
    public override string Location { get { return ""; } }
    public override string StatusMessage { get { return ""; } }
    public override bool HasMoreData { get { return false; } }
    public override void StopJob() { }
}
'@
        }

        function git {
            throw 'Unexpected git invocation without a mock.'
        }

        function Invoke-TestRunner {
            & $Script:runnerPath -NoProgress -Branch main *> $null
        }
    }

    BeforeEach {
        $Script:runnerState = @{
            ChangedFile   = '.github/skills/analyze-debug-files/SKILL.md'
            SelectedPaths = [System.Collections.Generic.List[string]]::new()
        }
        $state = $Script:runnerState
        Mock -CommandName git -MockWith ({
                switch ($args[0]) {
                    'log' { return '1111111111111111111111111111111111111111 Wed, 28 Oct 2026 07:46:41 -0500' }
                    'diff-tree' { return $state.ChangedFile }
                    'status' { return }
                }
                throw "Unexpected git arguments: $($args -join ' ')"
            }.GetNewClosure())
        Mock -CommandName Start-Job -MockWith ({
                param($ArgumentList, $Name)
                $state.SelectedPaths.Add([string]@($ArgumentList)[0])
                return [PesterRunnerTestJob]::new($Name)
            }.GetNewClosure())
        Mock -CommandName Receive-Job -MockWith {
            return [PSCustomObject]@{
                Result   = 'Passed'
                Duration = [TimeSpan]::FromMilliseconds(1)
            }
        }
        Mock -CommandName Remove-Job -MockWith {}
    }

    It 'skips documentation-only changes for <ChangedFile>, matching main' -ForEach @(
        @{ ChangedFile = '.github/skills/analyze-debug-files/SKILL.md' }
        @{ ChangedFile = '.github/skill-lib/README.md' }
        @{ ChangedFile = 'README.md' }
    ) {
        $Script:runnerState.ChangedFile = $ChangedFile
        Invoke-TestRunner

        $Script:runnerState.SelectedPaths.Count | Should -Be 0
    }

    It 'retains all test areas when <ChangedFile> changes' -ForEach @(
        @{ ChangedFile = '.build/Pester.ps1' }
        @{ ChangedFile = '.github/skills/analyze-debug-files/Get-DebugFileMetadata.ps1' }
    ) {
        $Script:runnerState.ChangedFile = $ChangedFile
        Invoke-TestRunner

        @($Script:runnerState.SelectedPaths | Where-Object {
                $_ -notmatch '[\\/]\.github[\\/]'
            }).Count | Should -BeGreaterThan 0
        @($Script:runnerState.SelectedPaths | Where-Object {
                (Split-Path -Path $_ -Leaf) -eq 'SkillDocContract.Tests.ps1'
            }).Count | Should -Be 1
        @($Script:runnerState.SelectedPaths | Where-Object {
                $_ -match '[\\/]\.github[\\/]examples[\\/]'
            }).Count | Should -Be 0
    }

    It 'retains all test areas without a branch filter even for documentation-only changes' {
        & $Script:runnerPath -NoProgress *> $null

        @($Script:runnerState.SelectedPaths | Where-Object {
                $_ -notmatch '[\\/]\.github[\\/]'
            }).Count | Should -BeGreaterThan 0
        @($Script:runnerState.SelectedPaths | Where-Object {
                (Split-Path -Path $_ -Leaf) -eq 'SkillDocContract.Tests.ps1'
            }).Count | Should -Be 1
        @($Script:runnerState.SelectedPaths | Where-Object {
                $_ -match '[\\/]\.github[\\/]examples[\\/]'
            }).Count | Should -Be 0
    }
}
