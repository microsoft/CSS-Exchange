### Microsoft Support Emergency Response Tool (MSERT) to scan Microsoft Exchange Server

Microsoft Defender has included security intelligence updates to the latest version of the  [Microsoft Safety Scanner](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)  (MSERT.EXE) to detect and remediate the latest threats known to abuse the  [Exchange Server vulnerabilities](https://msrc-blog.microsoft.com/2021/03/05/microsoft-exchange-server-vulnerabilities-mitigations-march-2021/)  disclosed on March 2, 2021. Administrators can use this tool for servers not protected by Microsoft Defender for Endpoint or where exclusions are configured for the recommended folders below.

To use the Microsoft Support Emergency Response Tool (MSERT) to scan the Microsoft Exchange Server locations for known indicators from adversaries:

1.  Download MSERT from [Microsoft Safety Scanner Download – Windows security.](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)  **Note:**  In case you need to troubleshoot it, see [How to troubleshoot an error when you run the Microsoft Safety Scanner](https://support.microsoft.com/en-us/topic/how-to-troubleshoot-an-error-when-you-run-the-microsoft-safety-scanner-6cd5faa1-f7b4-afd2-85c7-9bed02860f1c).
2.  Read and accept the  **End user license agreement**, then click  **Next**.
3.  Read the  **Microsoft Safety Scanner Privacy Statement**, then click  **Next**.
4.  Select whether you want to do full scan, or customized scan.

-   **Full scan**  – The most effective way to thoroughly scan every file on the device. It is the most effective option although it might take a long time to complete depending on the directory size of your server.
-   **Customized scan**  – This can be configured to scan the following file paths where malicious files from the threat actor have been observed:  
  
_%IIS installation path%\aspnet_client\*_  
_%IIS installation path%\aspnet_client\system_web\*_  
_%Exchange Server installation path%\FrontEnd\HttpProxy\owa\auth\*_  
_%Exchange Server Installation%\FrontEnd\HttpProxy\ecp\auth\*_  
_Configured temporary ASP.NET files path_  

These remediation steps are effective against known attack patterns but are  **not guaranteed as complete mitigation for all possible exploitation**  of these vulnerabilities. Microsoft Defender will continue to monitor and provide the latest security updates.
