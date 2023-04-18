# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-NewS256CodeChallengeVerifier {
    param()

    <#
        This function can be used to generate a new SHA256 code challenge and verifier following the PKCE specification.
        The Proof Key for Code Exchange (PKCE) extension describes a technique for public clients to mitigate the threat
        of having the authorization code intercepted. The technique involves the client first creating a secret,
        and then using that secret again when exchanging the authorization code for an access token.

        The function returns a PSCustomObject with the following properties:
        Verifier: The verifier that was generated
        CodeChallenge: The code challenge that was generated

        It returns $null if the code challenge and verifier generation fails.

        More information about the auth code flow with PKCE can be found here:
        https://www.rfc-editor.org/rfc/rfc7636
    #>

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    $bytes = [System.Byte[]]::new(64)
    ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
    $b64String = [Convert]::ToBase64String($bytes)
    $verifier = (($b64String.TrimEnd("=")).Replace("+", "-")).Replace("/", "_")

    $newMemoryStream = [System.IO.MemoryStream]::new()
    $newStreamWriter = [System.IO.StreamWriter]::new($newMemoryStream)
    $newStreamWriter.write($verifier)
    $newStreamWriter.Flush()
    $newMemoryStream.Position = 0
    $hash = Get-FileHash -InputStream $newMemoryStream | Select-Object Hash
    $hex = $hash.Hash

    $bytesArray = [byte[]]::new($hex.Length / 2)

    for ($i = 0; $i -lt $hex.Length; $i+=2) {
        $bytesArray[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
    }

    $base64Encoded = [Convert]::ToBase64String($bytesArray)
    $base64UrlEncoded = (($base64Encoded.TrimEnd("=")).Replace("+", "-")).Replace("/", "_")

    if ((-not([System.String]::IsNullOrEmpty($verifier))) -and
        (-not([System.String]::IsNullOrEmpty(($base64UrlEncoded))))) {
        Write-Verbose "Verifier and CodeChallenge generated successfully"
        return [PSCustomObject]@{
            Verifier      = $verifier
            CodeChallenge = $base64UrlEncoded
        }
    }

    Write-Verbose "Verifier and CodeChallenge generation failed"
    return $null
}
