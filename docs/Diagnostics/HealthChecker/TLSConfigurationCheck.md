# TLS Configuration Check

We check and validate Exchange servers TLS 1.0 - 1.2 configuration. We can detect mismatches in TLS versions for client and server. This is important because Exchange can be both a client and a server.

We also check for the SystemDefaultTlsVersions registry value which controls if .NET Framework will inherit its defaults from the Windows Schannel DisabledByDefault registry values or not.

An invalid TLS configuration can cause issues within Exchange for communication.

**Included in HTML Report?**

Yes

**Additional resources:**

https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-part-1-Getting-Ready-for-TLS-1-2/ba-p/607649

https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761

https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-3-Turning-Off-TLS-1-0-1-1/ba-p/607898