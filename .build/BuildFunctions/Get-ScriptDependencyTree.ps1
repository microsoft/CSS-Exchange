# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ScriptDependencyTree {
    param(
        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [Hashtable]
        $DependencyHashtable,

        [Parameter()]
        [int]
        $Depth
    )

    if ($Depth -gt 100) {
        throw "Recursion depth exceeded"
    }

    $dependencyTree = @{
        ScriptFullName = $File
        Dependencies   = @()
    }

    $dependencyTree.Dependencies = $DependencyHashtable[$File] | ForEach-Object {
        Get-ScriptDependencyTree -File $_ -DependencyHashtable $DependencyHashtable -Depth ($Depth + 1)
    }

    return $dependencyTree
}
