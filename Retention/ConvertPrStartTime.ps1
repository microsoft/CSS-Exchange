# Example:
# .\ConvertPrStartTime.ps1 000000008AF3B39BE681D001
#
param($byteString)
$bytesReversed = ""
for ($x = $byteString.Length - 2; $x -gt 7; $x-=2) { $bytesReversed += $byteString.Substring($x, 2) }
[DateTime]::FromFileTimeUtc([Int64]::Parse($bytesReversed, "AllowHexSpecifier"))