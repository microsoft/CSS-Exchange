# RPC Minimum Connection Timeout Check

**Description:**

By default, Outlook Anywhere opens two default connections to the Exchange CAS called `RPC_InData` and `RPC_OutData`. The Outlook Anywhere client to server used a default timeout of `12 minutes (720 seconds)` of inactivity and the server to the client timeout is `15 minutes (900 seconds)`.

These default Keep-Alive intervals are not aggressive enough for some of today's home networking devices and/or aggressive network devices on the Internet. Some of those devices are dropping TCP connections after as little as `5 minutes (300 seconds)` of inactivity.  When one or both of the two default connections are dropped, the connection to the Exchange server is essentially broken and not useable.

**Included in HTML Report?**

Yes

**Additional resources:**

[Outlook Anywhere Network Timeout Issue](https://docs.microsoft.com/archive/blogs/messaging_with_communications/outlook-anywhere-network-timeout-issue)
