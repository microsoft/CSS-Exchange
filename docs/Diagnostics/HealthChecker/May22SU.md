# May 2022 Security Update

In order to protect against CVE-2022-21978 within your environment `/PrepareDomain` must be run against each domain that contains the MESO container within it.

Health Checker will query all the domains in the environment to see if it has a MESO container. If it does, it checks for a particular ACE or version number of the MESO container to see if we are secure. If we don't pass this check, it will provide what domains you need to run `/PrepareDomain` against.

In order to protect your environment from CVE-2022-21978, you must install the May 2022 SU or a newer SU/CU that contains this security fix. All SUs and CUs after May 2022 contain this fix. After you have installed this security fix, you must run `/PrepareDomain` or `/PrepareAllDomains` from the Exchange bin directory.

**Included in HTML Report?**

Yes

**Additional resources:**

[Exchange Team Blog - May SU 2022](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-may-2022-exchange-server-security-updates/ba-p/3301831)
