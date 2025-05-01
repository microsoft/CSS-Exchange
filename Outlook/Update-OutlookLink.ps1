# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME
)

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\Shared\Invoke-ScriptBlockHandler.ps1

# Define the lookup table for translations of "classic"
#cspell:disable
$translations = @{
    "af-za"      = "klassiek"
    "sq-al"      = "klasik"
    "am-et"      = "ነባር"
    "ar-sa"      = "كلاسيكي"
    "az-latn-az" = "klassik"
    "eu-es"      = "klasikoa"
    "bg-bg"      = "класическа версия"
    "ca-es"      = "clàssic"
    "hr-hr"      = "klasična verzija"
    "cs-cz"      = "klasický"
    "da-dk"      = "klassisk"
    "nl-nl"      = "klassieke versie"
    "en-us"      = "classic"
    "en-gb"      = "classic"
    "et-ee"      = "klassikaline"
    "fil-ph"     = "classic"
    "fi-fi"      = "perinteinen"
    "fr-fr"      = "classique"
    "fr-ca"      = "classique"
    "gl-es"      = "clásico"
    "ka-ge"      = "კლასიკური"
    "de-de"      = "klassisch"
    "el-gr"      = "κλασικό"
    "gu-in"      = "ક્લાસિક"
    "he-il"      = "קלאסי"
    "hi-in"      = "क्लासिक"
    "hu-hu"      = "klasszikus"
    "is-is"      = "sígilt"
    "id-id"      = "klasik"
    "it-it"      = "versione classica"
    "ja-jp"      = "クラシック"
    "kn-in"      = "ಕ್ಲಾಸಿಕ್"
    "kk-kz"      = "классикалық"
    "km-kh"      = "ក្លាស៊ីក"
    "kok-in"     = "क्लासीक"
    "ko-kr"      = "클래식"
    "lo-la"      = "ຄລາສສິກ"
    "lv-lv"      = "klasiskā versija"
    "lt-lt"      = "klasikinė"
    "mk-mk"      = "класична верзија"
    "ml-in"      = "ക്ലാസിക്"
    "mt-mt"      = "klassiku"
    "mr-in"      = "क्लासिक"
    "or-in"      = "କ୍ଲାସିକ୍"
    "fa-ir"      = "کلاسیک"
    "pl-pl"      = "klasyczny"
    "pt-pt"      = "clássico"
    "ro-ro"      = "clasic"
    "ru-ru"      = "классическая версия"
    "gd-gb"      = "clasaigeach"
    "sr-cyrl-ba" = "класични"
    "sk-sk"      = "klasická verzia"
    "sl-si"      = "klasična različica"
    "es-es"      = "clásico"
    "es-mx"      = "clásico"
    "sv-se"      = "klassisk"
    "ta-in"      = "கிளாசிக்"
    "tt-ru"      = "классик"
    "te-in"      = "క్లాసిక్"
    "th-th"      = "คลาสสิก"
    "tr-tr"      = "klasik"
    "uk-ua"      = "класична версія"
    "ur-pk"      = "کلاسک"
    "ug-cn"      = "كىلاسسىك"
    "vi-vn"      = "phiên bản cũ"
    "cy-gb"      = "clasurol"
    # General language codes
    "af"         = "klassiek"
    "sq"         = "klasik"
    "am"         = "ነባር"
    "ar"         = "كلاسيكي"
    "az"         = "klassik"
    "eu"         = "klasikoa"
    "bg"         = "класическа версия"
    "ca"         = "clàssic"
    "hr"         = "klasična verzija"
    "cs"         = "klasický"
    "da"         = "klassisk"
    "nl"         = "klassieke versie"
    "en"         = "classic"
    "et"         = "klassikaline"
    "fil"        = "classic"
    "fi"         = "perinteinen"
    "fr"         = "classique"
    "gl"         = "clásico"
    "ka"         = "კლასიკური"
    "de"         = "klassisch"
    "el"         = "κλασικό"
    "gu"         = "ક્લાસિક"
    "he"         = "קלאסי"
    "hi"         = "क्लासिक"
    "hu"         = "klasszikus"
    "is"         = "sígilt"
    "id"         = "klasik"
    "it"         = "versione classica"
    "ja"         = "クラシック"
    "kn"         = "ಕ್ಲಾಸಿಕ್"
    "kk"         = "классикалық"
    "km"         = "ក្លាស៊ីក"
    "kok"        = "क्लासीक"
    "ko"         = "클래식"
    "lo"         = "ຄລາສສິກ"
    "lv"         = "klasiskā versija"
    "lt"         = "klasikinė"
    "mk"         = "класична верзија"
    "ml"         = "ക്ലാസിക്"
    "mt"         = "klassiku"
    "mr"         = "क्लासिक"
    "or"         = "କ୍ଲାସିକ୍"
    "fa"         = "کلاسیک"
    "pl"         = "klasyczny"
    "pt"         = "clássico"
    "ro"         = "clasic"
    "ru"         = "классическая версия"
    "gd"         = "clasaigeach"
    "sr"         = "класични"
    "sk"         = "klasická verzia"
    "sl"         = "klasična različica"
    "es"         = "clásico"
    "sv"         = "klassisk"
    "ta"         = "கிளாசிக்"
    "tt"         = "классик"
    "te"         = "క్లాసిక్"
    "th"         = "คลาสสิก"
    "tr"         = "klasik"
    "uk"         = "класична версія"
    "ur"         = "کلاسک"
    "ug"         = "كىلاسسىك"
    "vi"         = "phiên bản cũ"
    "cy"         = "clasurol"
}
#cspell:enable

if (-not (Confirm-Administrator)) {
    Write-Error "This script is not running with elevated privileges. Exiting script. Please run the script with elevated privileges." -ErrorAction Stop
}

$scriptBlock = {
    # Function to get the Office Install Language
    function Get-OfficeInstallLanguage {
        try {
            # Define the registry path for Office
            $officeRegistryPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

            # Get the Office Install Language from the registry
            $installLanguage = Get-ItemProperty -Path $officeRegistryPath -Name "ClientCulture" | Select-Object -ExpandProperty ClientCulture

            if ($installLanguage) {
                return $installLanguage.ToLower()
            } else {
                Write-Host "Office Install Language not found. Defaulting to en-us."
                return "en-us"
            }
        } catch {
            Write-Host "Error retrieving Office Install Language: $_. Defaulting to en-us." -ForegroundColor Red
            return "en-us"
        }
    }

    # Function to get the translation for "classic"
    function Get-Translation {
        param (
            [string]$languageCode
        )

        # Try to find the full language code first
        if ($translations.ContainsKey($languageCode)) {
            return $translations[$languageCode]
        } else {
            # If not found, try to find the general language code (e.g., "en" for "en-gb")
            $generalLanguageCode = $languageCode.Split('-')[0]
            if ($translations.ContainsKey($generalLanguageCode)) {
                return $translations[$generalLanguageCode]
            } else {
                Write-Host "Translation for 'classic' not found for language $languageCode. Using default translation: classic."
                return "classic"
            }
        }
    }

    # Function to rename .lnk files
    function Rename-OutlookLnkFiles {
        param (
            [string[]]$directories,
            [string]$translation,
            [ref]$renamedFiles,
            [ref]$failedFiles
        )

        foreach ($directory in $directories) {
            try {
                # Search for all .lnk files that point to Outlook.exe and have the name "Outlook" or "Microsoft Outlook"
                $lnkFiles = Get-ChildItem -Path $directory -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Where-Object {
                    ($_.Name -eq "Outlook.lnk" -or $_.Name -eq "Microsoft Outlook.lnk") -and
                    (Select-String -Path $_.FullName -Pattern "Outlook.exe" -Quiet)
                }

                # Rename the .lnk files
                foreach ($lnkFile in $lnkFiles) {
                    try {
                        $newName = if ($lnkFile.Name -eq "Outlook.lnk") {
                            $lnkFile.DirectoryName + "\Outlook ($translation).lnk"
                        } else {
                            $lnkFile.DirectoryName + "\Microsoft Outlook ($translation).lnk"
                        }
                        Rename-Item -Path $lnkFile.FullName -NewName $newName -ErrorAction Stop
                        $renamedFiles.Value += "$($lnkFile.FullName) -> $newName`n"
                    } catch {
                        Write-Host "Error renaming file $($lnkFile.FullName): $_" -ForegroundColor Red
                        $failedFiles.Value += "$($lnkFile.FullName)`n"
                    }
                }
            } catch {
                Write-Host "Error searching for .lnk files in directory $directory : $_" -ForegroundColor Red
            }
        }
    }

    # Get the Office Install Language
    $officeLanguage = Get-OfficeInstallLanguage

    # Get the translation for "classic" based on the Office Install Language
    $translation = Get-Translation -languageCode $officeLanguage

    if ($translation) {
        # Define the directories to search using the current user's environment settings
        $directories = New-Object System.Collections.Generic.List[string]
        $directories.Add("$env:ProgramData\Microsoft\Windows\Start Menu\Programs")

        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { $_.Special -eq $false }

        if ($null -eq $profiles) {
            Write-Host "Failed to find the user profiles on the computer $env:COMPUTERNAME. Stopping the script."
            return
        }

        foreach ($localProfile in $profiles) {
            $localPath = $localProfile.LocalPath
            if ($null -ne $localPath) {
                $directories.Add("$localPath\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch")
                $directories.Add("$localPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs")
            }
        }

        # Initialize variables to store the summary of renamed and failed files
        $renamedFiles = [ref] ""
        $failedFiles = [ref] ""

        # Rename .lnk files in the specified directories
        Rename-OutlookLnkFiles -directories $directories -translation $translation -renamedFiles $renamedFiles -failedFiles $failedFiles

        # Output the summary of renamed files if there are any
        if ($renamedFiles.Value) {
            Write-Host ""
            Write-Host "Summary of renamed .lnk files:"
            Write-Host $renamedFiles.Value
        }

        # Output the summary of failed files if there are any
        if ($failedFiles.Value) {
            Write-Host ""
            Write-Host "Summary of .lnk files that failed to be renamed:"
            Write-Host $failedFiles.Value
            return
        }

        # Output message if no files were renamed and no errors occurred
        if (-not $renamedFiles.Value -and -not $failedFiles.Value) {
            Write-Host "No files were renamed and no errors occurred. Nothing changed."
        }
    } else {
        Write-Host "Translation for 'classic' not found for language $officeLanguage."
        return
    }
}

Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock $scriptBlock
