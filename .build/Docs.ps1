# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$repoRoot = Get-Item "$PSScriptRoot\.."
$docsDir = "$repoRoot\docs"
#cspell:words mkdocs
$markDownFiles = Get-Content "$repoRoot\mkdocs.yml" | Select-String "(\S+\.md)" | ForEach-Object {
    $_.Matches.Groups[1].Value
}

$allDocs = Get-ChildItem $docsDir -Recurse -File | Where-Object { $_.Extension -eq ".md" }

Write-Host "Checking to make sure all the docs are in the mkdocs.yml file."

foreach ($doc in $allDocs) {
    $head = Get-Content $doc -Head 5
    if ($head -match "^hide:$" -and $head -match "- navigation$") {
        # If the doc is hidden from navigation, it need not be in the mkdocs.yml file.
        continue
    }

    if ($doc.FullName -ne "$docsDir\index.md" -and
        -not (Get-Content $doc -Raw | Select-String "^hide:\s+- navigation") -and
        -not($markDownFiles.Contains($doc.FullName.Split("\docs\")[1].Replace("\", "/")))) {
        throw "Failed to have all docs in mkdocs.yml: $($doc.FullName)"
    }
}
Write-Host "Success"
