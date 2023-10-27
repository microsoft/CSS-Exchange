# SMBv1 Check

To make sure that your Exchange organization is better protected against the latest threats (for example Emotet, TrickBot or WannaCry to name a few) we recommend disabling SMBv1 if it's enabled on your Exchange (2013/2016/2019) server.

There is no need to run the nearly 30-year-old SMBv1 protocol when Exchange 2013/2016/2019 is installed on your system. SMBv1 isn't safe and you lose key protections offered by later SMB protocol versions.

This check verifies that SMBv1 is not installed (if OS allows) and that its activation is blocked.

**Included in HTML Report?**

Yes

**Additional resources:**

[Exchange Server and SMBv1](https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-and-smbv1/ba-p/1165615)
