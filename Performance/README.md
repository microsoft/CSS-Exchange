## Running the script
    .\ExPerfAnalyzer.ps1 .\EXSERVER01_FULL_000001.BLG

## Registering script as a default handler
    .\ExPerfAnalyzer.ps1 -RegisterHandler
PowerShell must be running as an administrator for this command to work. The script will register itself as a shell handler for perfmon .blg files. You can then right-click any .blg file and select *ExPerfAnalyzer* to quickly parse the file.

## Inspiration
This script was inspired by [Performance Analysis of Logs (PAL)](https://github.com/clinthuffman/PAL) and PMA.VBS (an internal tool used by Windows support).

## FAQ
- **This takes forever to run.**

    It's faster than PAL.

- **Why don't I just use PAL?**

    You could, but PAL takes even longer to run and throws a lot of false positives.
	
- **What's the expected running time?**

	v0.2.2 and an Intel Core i7-4810MQ @ 2.8Ghz processed a 1GB perfmon sitting on an SSD in 11 seconds.

- **Can I edit this script however I'd like?**

    Yes, that's the magic of open source software!

- **Do you accept pull requests? Can I contribute to the script?**

    Of course!

## Contributing
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
