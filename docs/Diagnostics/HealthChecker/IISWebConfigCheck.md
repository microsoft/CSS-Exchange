# IIS Web Configuration Check

**Description:**

After a CU or an SU install, sometimes there can be issues with the web.config or the SharedWebConfig.config file that causes issues with the virtual directories from working properly. Most of these issues are from SU installs where they are installed from double clicking on the msi file. This prevents the process from starting as administrator and can cause multiple issues.

This check detects to make sure all the default web.config and SharedWebConfig.config files exist and if they have any default variable values still set within it - `%ExchangeInstallDir%`.

If `Default Variable Detected` file is found, open up that file and replace the `%ExchangeInstallDir%` with the Exchange Install path from `(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath`

**Included in HTML Report?**

Yes, if issue detected
