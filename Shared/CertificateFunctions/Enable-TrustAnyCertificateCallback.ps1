# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Enable-TrustAnyCertificateCallback {
    param()

    <#
        This helper function can be used to ignore certificate errors. It works by setting the ServerCertificateValidationCallback
        to a callback that always returns true. This is useful when you are using self-signed certificates or certificates that are
        not trusted by the system.
    #>

    Add-Type -TypeDefinition @"
    namespace Microsoft.CSSExchange {
        public class CertificateValidator {
            public static bool TrustAnyCertificateCallback(
                object sender,
                System.Security.Cryptography.X509Certificates.X509Certificate cert,
                System.Security.Cryptography.X509Certificates.X509Chain chain,
                System.Net.Security.SslPolicyErrors sslPolicyErrors) {
                return true;
            }

            public static void IgnoreCertificateErrors() {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = TrustAnyCertificateCallback;
            }
        }
    }
"@
    [Microsoft.CSSExchange.CertificateValidator]::IgnoreCertificateErrors()
}
