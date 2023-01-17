# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Show-ScriptDependencyTree {
    param(
        [Parameter()]
        [Hashtable]
        $DependencyTree,

        [Parameter()]
        [Hashtable]
        $Timestamps,

        [Parameter()]
        [int]
        $Depth
    )

    $indent = "  " * $Depth

    [PSCustomObject]@{
        Name   = "$indent$([IO.Path]::GetFileName($DependencyTree.ScriptFullName))"
        Commit = $Timestamps[$DependencyTree.ScriptFullName]
    }

    foreach ($dependency in $DependencyTree.Dependencies) {
        Show-ScriptDependencyTree -DependencyTree $dependency -Timestamps $Timestamps -Depth ($Depth + 1)
    }
}
