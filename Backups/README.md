## Purpose
The script is self-explanatory. You can test run diskshadow on a single Exchange database to ensure backups are working properly (i.e. all the Microsoft components). If the issue only happens with a 3rd-party backup solution, you can utilize operation mode 2 to enable just the logging while you execute a backup with the 3rd-party solution.

![Start Screen](/start_screen.PNG "Start Screen")

## More information
* https://blogs.technet.microsoft.com/exchange/2013/04/29/troubleshoot-your-exchange-2010-database-backup-functionality-with-vsstester-script/
* https://blogs.technet.microsoft.com/exchange/2015/03/26/vsstester-script-updated-troubleshoot-exchange-2013-and-2010-database-backups/

## Changelog
* v1.2 (2016-07-26)
  - added Exchange 2016 support
  - minor code cleanup
  - changes tested by Eric Scofield
* v1.1 (2015-03-26)
  - added Exchange 2013 support
  - bugfixes
  - better user input handling
  - formatting improvements
  - speed optimizations
  - execution option #3 (custom) is removed
* v1.0 (2013-04-29)
  - public release
  
## Contributing
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
