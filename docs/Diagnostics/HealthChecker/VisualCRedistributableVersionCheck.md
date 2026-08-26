# Visual C++ Redistributable Version Check

**Description:**

We check if the Visual C++ Redistributable versions required for the installed Exchange server role are installed and up to date. Exchange Server specifically requires the [Visual C++ 2012 (VC++ 11.0)](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170#visual-studio-2012-vc-110-update-4-no-longer-supported) and [Visual C++ 2013 (VC++ 12.0)](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170#visual-studio-2013-vc-120-no-longer-supported) Redistributable. These older versions are **not** replaced by newer Visual C++ Redistributable versions (e.g., the latest Visual C++ 2015-2022 Redistributable) and must remain installed.

When Health Checker reports that a version is "outdated", it means the installed version of that specific year's Redistributable (2012 or 2013) needs to be updated to the latest release within that same series.

**Included in HTML Report?**

Yes

**Additional resources:**

[Microsoft Visual C++ Redistributable Latest Supported Downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)

[Exchange Server 2019 prerequisites](https://docs.microsoft.com/exchange/plan-and-deploy/prerequisites?view=exchserver-2019)

[Exchange Server 2016 prerequisites](https://docs.microsoft.com/exchange/plan-and-deploy/prerequisites?view=exchserver-2016)

