# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    . $PSScriptRoot\..\ConvertTo-DebugReportScalar.ps1
}

Describe 'ConvertTo-DebugReportScalar' {
    It 'keeps untrusted syntax literal: <Text>' -ForEach @(
        @{ Text = '![image](https://example.invalid/image.png)' }
        @{ Text = '[link](https://example.invalid)' }
        @{ Text = 'https://example.invalid www.example.invalid' }
        @{ Text = '```outside``` **bold** _emphasis_ ~strike~' }
        @{ Text = '</code><img src=x><script>alert(1)</script>&' }
        @{ Text = "first`n# heading`r`n- list`tend" }
        @{ Text = 'file`|extra|cells.txt' }
    ) {
        $scalar = ConvertTo-DebugReportScalar -RedactedText $Text
        $html = (ConvertFrom-Markdown -InputObject $scalar).Html

        $html | Should -Not -Match '<(?:img|a|script|h[1-6]|ul|li|strong|em|del)\b'
        $scalar | Should -Match '\A<code>[^<>]*</code>\z'
        $innerText = $scalar.Substring(6, $scalar.Length - 13)
        [System.Net.WebUtility]::HtmlDecode($innerText) | Should -BeExactly $Text
    }

    It 'does not let a filename add cells to a Markdown table' {
        $scalar = ConvertTo-DebugReportScalar -RedactedText 'file`|extra|cells.txt'
        $markdown = "| File | Status |`n|---|---|`n| $scalar | Parsed |"
        $html = (ConvertFrom-Markdown -InputObject $markdown).Html

        @([regex]::Matches($html, '<td(?:\s[^>]*)?>')).Count | Should -Be 2
        $html | Should -Not -Match '<(?:img|a)\b'
    }

    It 'preserves empty text and Unicode' {
        ConvertTo-DebugReportScalar -RedactedText '' | Should -BeExactly '<code></code>'
        $text = 'caf' + [char]0xE9 + ' ' + [char]0x4E2D
        $scalar = ConvertTo-DebugReportScalar -RedactedText $text
        [System.Net.WebUtility]::HtmlDecode($scalar.Substring(6, $scalar.Length - 13)) |
            Should -BeExactly $text
    }
}
