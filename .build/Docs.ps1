# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$repoRoot = Get-Item "$PSScriptRoot\.."
$docsDir = "$repoRoot\docs"
$markDownFiles = Get-Content "$repoRoot\mkdocs.yml" |
    Where-Object { $_ -like "*.md" } |
    ForEach-Object {
        if ($_.Contains(":")) {
            $_.Split(":")[1].Trim()
        } else {
            $_.Replace("-", "").Trim()
        }
    }
$allDocs = Get-ChildItem $docsDir -Recurse -File | Where-Object { $_.Extension -eq ".md" }
Write-Host "Checking to make sure all the docs are in the mkdocs.yml file."

foreach ($doc in $allDocs) {
    if ($doc.FullName -ne "$docsDir\index.md" -and
        -not($markDownFiles.Contains($doc.FullName.Split("\docs\")[1].Replace("\", "/")))) {
        throw "Failed to have all docs in mkdocs.yml: $($doc.FullName)"
    }
}
Write-Host "Success"
