# Set registry shortcuts
$ErrorActionPreference = 'SilentlyContinue'
New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null
New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE | Out-Null
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null

do {
    Write-Host `n"Should the settings only apply to the " -NoNewline
    Write-Host "current user" -BackgroundColor Black -ForegroundColor Yellow -NoNewLine
    Write-Host ", or should they apply to " -NoNewline
    Write-Host "all users?" -BackgroundColor Black -ForegroundColor Yellow
    Write-Host `n"[1]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
    Write-Host " - For the current user"
    Write-Host "[2]" -NoNewline -BackgroundColor Black -ForegroundColor Yellow
    Write-Host " - For all users"
    $choice = Read-Host -Prompt "`n[Choice]"
        
    $validChoice = $true
        
    switch ($choice) {
        # Current user
        "1" {
            function Test-HKCURegistryPaths {
                $registryPaths = @(
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications",
                    "HKCU:\Software\Microsoft\input\TIPC",
                    "HKCU:\Software\Microsoft\TabletTip\1.7",
                    "HKCU:\Control Panel\International\User Profile",
                    "HKCU:\Software\Microsoft\Clipboard",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic\NonPackaged",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder\NonPackaged",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
                    "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps",
                    "HKCU:\Software\Policies\Microsoft\Edge",
                    "HKCU:\Software\Policies\Microsoft\Office\16.0\osm",
                    "HKCU:\Software\Policies\Microsoft\Office\16.0\Common",
                    "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback",
                    "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy",
                    "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry",
                    "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings",
                    "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search",
                    "HKCU:\Software\Microsoft\InputPersonalization",
                    "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore",
                    "HKCU:\Software\Microsoft\Personalization\Settings",
                    "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                    "HKCU:\Software\Policies\Microsoft\Windows\Explorer",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds",
                    "HKCU:\Software\Microsoft\Siuf\Rules",
                    "HKCU:\Software\Microsoft\MediaPlayer\Preferences"
                )
            
                foreach ($path in $registryPaths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    else {
                        ##
                    }
                }
            }
            
            Test-HKCURegistryPaths

            do {
                Write-Host `n"Which settings do you want to use?"
                Write-Host `n"[1]" -NoNewline
                Write-Host " - Recommended settings"
                Write-Host "[2]" -NoNewline
                Write-Host " - Recommended and " -NoNewline
                Write-Host "Somewhat recommended settings" -BackgroundColor Black -ForegroundColor Yellow
                Write-Host "[3]" -NoNewline
                Write-Host " - " -NoNewline
                Write-Host "All them" -BackgroundColor Black -ForegroundColor Red
                $choice = Read-Host -Prompt "`n[Choice]"
                    
                $validChoice = $true
                    
                switch ($choice) {
                    # Current User - Recommended settings
                    "1" {
                        #Privacy
                        $PrivacyRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SubscribedContent-353698Enabled" = 0 #Disable suggestions in the timeline
                                "SubscribedContent-338388Enabled" = 0 #Disable suggestions in Start
                                "SubscribedContent-338389Enabled" = 0 #Disable tips, tricks, and suggestions when using Windows
                                "SubscribedContent-338393Enabled" = 0 #Disable showing suggested content in the Settings app
                                "SubscribedContent-353694Enabled" = 0 #Disable showing suggested content in the Settings app
                                "SubscribedContent-353696Enabled" = 0 #Disable showing suggested content in the Settings app
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"  = @{
                                "ScoobeSystemSettingEnabled" = 0 #Disable the possibility of suggesting to finish the setup of the device
                            }
                            "HKCU:\Software\Microsoft\input\TIPC"                                    = @{
                                "Enabled" = 0 #Disable transmission of typing information
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"        = @{
                                "Enabled" = 0 #Disable and reset Advertising ID and info
                            }
                        }

                        foreach ($path in $PrivacyRecommendedSettings.Keys) {
                            foreach ($name in $PrivacyRecommendedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $PrivacyRecommendedSettings[$path][$name]
                            }
                        }

                        #Activity History and Clipboard
                        $HistoryRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Clipboard" = @{
                                "EnableClipboardHistory" = 0 #Disable storage of clipboard history
                            }
                        }

                        foreach ($path in $HistoryRecommendedSettings.Keys) {
                            foreach ($name in $HistoryRecommendedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $HistoryRecommendedSettings[$path][$name]
                            }
                        }

                        #App Privacy
                        $AppPrivacyRecommendedsettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" = "Deny" #Disable app access to user account information
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"         = "Deny" #Disable app access to diagnostics information
                        }

                        $AppPrivacyRecommendedsettings.GetEnumerator() | ForEach-Object {
                            Set-ItemProperty -Path $_.Key -Name "Value" -Value $_.Value -ErrorAction SilentlyContinue
                        }

                        $AppPrivacyRecommendedDwordsettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "Start_TrackProgs" = 0 #Disable Windows tracking of app starts
                            }
                        }

                        foreach ($settingType in $AppPrivacyRecommendedDwordsettings.Keys) {
                            foreach ($path in $AppPrivacyRecommendedDwordsettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $AppPrivacyRecommendedDwordsettings[$settingType][$path]
                            }
                        }

                        #Microsoft Edge (new version based on Chromium)
                        $EdgeRecommendedSettings = @{
                            "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                            "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                            "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                            "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                            "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                            "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                            "AutofillAddressEnabled"                         = 0 #Disable form suggestions
                            "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                            "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                            "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                            "WebWidgetAllowed"                               = 0 #Disable Edge bar
                            "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                        }

                        $EdgeRecommendedSettings.Keys | ForEach-Object {
                            $name = $_
                            $value = $EdgeRecommendedSettings[$name]
                            Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name $name -Type DWord -Value $value
                        }

                        #Microsoft Office
                        $OfficeRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry"          = @{
                                "DisableTelemetry" = 1 #Disable telemetry for Microsoft Office
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" = @{
                                "SendTelemetry" = 3 #Disable diagnostic data submission
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"            = @{
                                "QMEnable" = 0; #Disable participation in the Customer Experience Improvement Program
                                "LinkedIn" = 0 #Disable the display of LinkedIn information
                            }
                            "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings"        = @{
                                "InlineTextPrediction" = 0 #Disable inline text prediction in mails
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\osm"               = @{
                                "Enablelogging"         = 0; #Disable logging for Microsoft Office Telemetry Agent
                                "EnableUpload"          = 0; #Disable upload of data for Microsoft Office Telemetry Agent
                                "EnableFileObfuscation" = 1 #Obfuscate file names when uploading telemetry data
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback"   = @{
                                "SurveyEnabled" = 0; #Disable Microsoft Office surveys
                                "Enabled"       = 0; #Disable feedback to Microsoft
                                "IncludeEmail"  = 0 #Disable Microsoft's feedback tracking
                            }
                        }

                        foreach ($settingType in $OfficeRecommendedSettings.Keys) {
                            foreach ($path in $OfficeRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $OfficeRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Synchronization of Windows Settings
                        $SettingSyncRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"                        = @{
                                "SyncPolicy" = 5 #Disable synchronization of all settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" = @{
                                "Enabled" = 0 #Disable synchronization of design settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" = @{
                                "Enabled" = 0 #Disable synchronization of browser settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"     = @{
                                "Enabled" = 0 #Disable synchronization of credentials (passwords)
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"        = @{
                                "Enabled" = 0 #Disable synchronization of language settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"   = @{
                                "Enabled" = 0 #Disable synchronization of accessibility settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"         = @{
                                "Enabled" = 0 #Disable synchronization of advanced Windows settings
                            }
                        }

                        foreach ($settingType in $SettingSyncRecommendedSettings.Keys) {
                            foreach ($path in $SettingSyncRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SettingSyncRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Cortana (Personal Assistant)
                        $CortanaRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search" = @{
                                "CortanaConsent" = 0 #Disable and reset Cortana
                            }
                            "HKCU:\Software\Microsoft\InputPersonalization"                  = @{
                                "RestrictImplicitInkCollection"  = 1; #Disable Input Personalization
                                "RestrictImplicitTextCollection" = 1 #Disable Input Personalization
                            }
                            "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" = @{
                                "HarvestContacts" = 0 #Disable Input Personalization
                            }
                            "HKCU:\Software\Microsoft\Personalization\Settings"              = @{
                                "AcceptedPrivacyPolicy" = 0 #Disable Input Personalization
                            }
                        }

                        foreach ($settingType in $CortanaRecommendedSettings.Keys) {
                            foreach ($path in $CortanaRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $CortanaRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Windows Copilot
                        $CopilotRecommendedSettings = @{
                            "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"          = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "ShowCopilotButton" = 0 #Disable the Copilot button from the taskbar
                            }
                        }

                        foreach ($settingType in $CopilotRecommendedSettings.Keys) {
                            foreach ($path in $CopilotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $CopilotRecommendedSettings[$settingType][$path]
                            }
                        }

                        #User Behavior
                        $UserBehaviorRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" = @{
                                "TailoredExperiencesWithDiagnosticDataEnabled" = 0 #Disable the use of diagnostic data for a tailor-made user experience
                            }
                        }

                        foreach ($settingType in $UserBehaviorRecommendedSettings.Keys) {
                            foreach ($path in $UserBehaviorRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $UserBehaviorRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Windows Explorer
                        $WindowsContentDeliveryRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SystemPaneSuggestionsEnabled" = 0 #Disable occassionally showing app suggestions in Start menu
                            }
                        }

                        foreach ($settingType in $WindowsContentDeliveryRecommendedSettings.Keys) {
                            foreach ($path in $WindowsContentDeliveryRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $WindowsContentDeliveryRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Lockscreen
                        $LockScreenRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "RotatingLockScreenEnabled"        = 0; #Disable Windows Spotlight
                                "RotatingLockScreenOverlayEnabled" = 0; #Disable fun facts, tips, tricks, and more on your lock screen
                                "SubscribedContent-338387Enabled"  = 0 #Disable fun facts, tips, tricks, and more on your lock screen
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" = @{
                                "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" = 0 #Disable notifications on lock screen
                            }
                        }

                        foreach ($settingType in $LockScreenRecommendedSettings.Keys) {
                            foreach ($path in $LockScreenRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $LockScreenRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Search
                        $SearchRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" = @{
                                "IsDynamicSearchBoxEnabled" = 0 #Disable extension of Windows search with Bing
                            }
                        }

                        foreach ($settingType in $SearchRecommendedSettings.Keys) {
                            foreach ($path in $SearchRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SearchRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Miscellaneous
                        $MiscellaneousRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Siuf\Rules"                                    = @{
                                "NumberOfSIUFInPeriod" = 0 #Disable feedback reminders
                                "PeriodInNanoSeconds"  = 0 #Disable feedback reminders
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SilentInstalledAppsEnabled" = 0 #Disable automatic installation of recommended Windows Store Apps
                                "SoftLandingEnabled"         = 0 #Disable tips, tricks, and suggestions while using Windows
                            }
                            "HKCU:\Software\Microsoft\MediaPlayer\Preferences"                       = @{
                                "UsageTracking" = 0 #Disable Windows Media Player diagnostics
                            }
                        }

                        foreach ($settingType in $MiscellaneousRecommendedSettings.Keys) {
                            foreach ($path in $MiscellaneousRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $MiscellaneousRecommendedSettings[$settingType][$path]
                            }
                        }

                        Write-Host `n"The recommended settings for the current user have been applied." -BackgroundColor Black -ForegroundColor Green
                        Write-Host "For detailed information > " -NoNewline
                        Write-Host "https://github.com/caglaryalcin/StayPrivacy" -ForegroundColor DarkCyan

                    }
                    # Current User - Recommended and Somewhat recommended settings
                    "2" {
                        #Privacy
                        $PrivacyRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SubscribedContent-353698Enabled" = 0 #Disable suggestions in the timeline
                                "SubscribedContent-338388Enabled" = 0 #Disable suggestions in Start
                                "SubscribedContent-338389Enabled" = 0 #Disable tips, tricks, and suggestions when using Windows
                                "SubscribedContent-338393Enabled" = 0 #Disable showing suggested content in the Settings app
                                "SubscribedContent-353694Enabled" = 0 #Disable showing suggested content in the Settings app
                                "SubscribedContent-353696Enabled" = 0 #Disable showing suggested content in the Settings app
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"  = @{
                                "ScoobeSystemSettingEnabled" = 0 #Disable the possibility of suggesting to finish the setup of the device
                            }
                            "HKCU:\Software\Microsoft\input\TIPC"                                    = @{
                                "Enabled" = 0 #Disable transmission of typing information
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"        = @{
                                "Enabled" = 0 #Disable and reset Advertising ID and info
                            }
                        }

                        $PrivacyLimitedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" = @{
                                "ToastEnabled" = 0 #Disable app notifications
                            }
                            "HKCU:\Software\Microsoft\TabletTip\1.7"                            = @{
                                "EnableTextPrediction" = 0 #Disable text suggestions when typing on the software keyboard
                            }
                            "HKCU:\Control Panel\International\User Profile"                    = @{
                                "HttpAcceptLanguageOptOut" = 1 #Disable access to local language for browsers
                            }
                        }

                        foreach ($path in $PrivacyRecommendedSettings.Keys) {
                            foreach ($name in $PrivacyRecommendedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $PrivacyRecommendedSettings[$path][$name]
                            }
                        }

                        foreach ($path in $PrivacyLimitedSettings.Keys) {
                            foreach ($name in $PrivacyLimitedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $PrivacyLimitedSettings[$path][$name]
                            }
                        }

                        #Activity History and Clipboard
                        $HistoryRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Clipboard" = @{
                                "EnableClipboardHistory" = 0 #Disable storage of clipboard history
                            }
                        }

                        foreach ($path in $HistoryRecommendedSettings.Keys) {
                            foreach ($name in $HistoryRecommendedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $HistoryRecommendedSettings[$path][$name]
                            }
                        }

                        #App Privacy
                        $AppPrivacyRecommendedsettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" = "Deny" #Disable app access to user account information
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"         = "Deny" #Disable app access to diagnostics information
                        }

                        $AppPrivacyRecommendedsettings.GetEnumerator() | ForEach-Object {
                            Set-ItemProperty -Path $_.Key -Name "Value" -Value $_.Value -ErrorAction SilentlyContinue
                        }

                        $AppPrivacyRecommendedDwordsettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "Start_TrackProgs" = 0 #Disable Windows tracking of app starts
                            }
                        }

                        $AppPrivacyLimitedSettings = @{
                            "location"                                 = "Deny" #Disable app access to device location
                            "webcam"                                   = "Deny" #Disable app access to camera
                            "microphone"                               = "Deny" #Disable app access to microphone
                            "userNotificationListener"                 = "Deny" #Disable app access to notifications
                            "activity"                                 = "Deny" #Disable app access to motion
                            "contacts"                                 = "Deny" #Disable app access to contacts
                            "appointments"                             = "Deny" #Disable app access to calendar
                            "phoneCall"                                = "Deny" #Disable app access to phone calls
                            "phoneCallHistory"                         = "Deny" #Disable app access to call history
                            "email"                                    = "Deny" #Disable app access to email
                            "userDataTasks"                            = "Deny" #Disable app access to tasks
                            "chat"                                     = "Deny" #Disable app access to messages
                            "radios"                                   = "Deny" #Disable app access to radios
                            "bluetoothSync"                            = "Deny" #Disable app access to unpaired devices
                            "documentsLibrary"                         = "Deny" #Disable app access to documents
                            "picturesLibrary"                          = "Deny" #Disable app access to images
                            "videosLibrary"                            = "Deny" #Disable app access to videos
                            "broadFileSystemAccess"                    = "Deny" #Disable app access to the file system
                            "cellularData"                             = "Deny" #Disable app access to unpaired devices
                            "gazeInput"                                = "Deny" #Disable app access to eye tracking
                            "graphicsCaptureProgrammatic"              = "Deny" #Disable the ability for apps to take screenshots
                            "graphicsCaptureProgrammatic\NonPackaged"  = "Deny" #Disable the ability for desktop apps to take screenshots
                            "graphicsCaptureWithoutBorder"             = "Deny" #Disable the ability for apps to take screenshots without borders
                            "graphicsCaptureWithoutBorder\NonPackaged" = "Deny" #Disable the ability for desktop apps to take screenshots without margins
                            "musicLibrary"                             = "Deny" #Disable app access to music libraries
                            "downloadsFolder"                          = "Deny" #Disable app access to downloads folder
                        }

                        $AppPrivacyLimitedDwordSettings = @{
                            "AgentActivationEnabled"             = 0 #Disable app access to use voice activation
                            "AgentActivationOnLockScreenEnabled" = 0 #Disable app access to use voice activation when device is locked
                            "AgentActivationLastUsed"            = 0 #Disable the standard app for the headset button
                        }

                        foreach ($settingType in $AppPrivacyRecommendedDwordsettings.Keys) {
                            foreach ($path in $AppPrivacyRecommendedDwordsettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $AppPrivacyRecommendedDwordsettings[$settingType][$path]
                            }
                        }

                        $AppPrivacyLimitedSettings.GetEnumerator() | ForEach-Object {
                            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$($_.Key)" -Name "Value" -Value $_.Value
                        }

                        $AppPrivacyLimitedDwordSettings.GetEnumerator() | ForEach-Object {
                            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name $_.Key -Type DWord -Value $_.Value
                        }

                        #Microsoft Edge (new version based on Chromium)
                        $EdgeRecommendedSettings = @{
                            "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                            "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                            "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                            "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                            "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                            "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                            "AutofillAddressEnabled"                         = 0 #Disable form suggestions
                            "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                            "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                            "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                            "WebWidgetAllowed"                               = 0 #Disable Edge bar
                            "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                        }

                        $EdgeRecommendedSettings.Keys | ForEach-Object {
                            $name = $_
                            $value = $EdgeRecommendedSettings[$name]
                            Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name $name -Type DWord -Value $value
                        }

                        $EdgeLimitedSettings = @{
                            "ResolveNavigationErrorsUseWebService" = 0 #Disable use of web service to resolve navigation errors
                            "AlternateErrorPagesEnabled"           = 0 #Disable suggestion of similar sites when website cannot be found
                            "NetworkPredictionOptions"             = 2 #Disable preload of pages for faster browsing and searching
                            "PasswordManagerEnabled"               = 0 #Disable saving passwords for websites
                            "SiteSafetyServicesEnabled"            = 0 #Disable site safety services for more information about a visited website
                        }

                        $EdgeLimitedSettings.Keys | ForEach-Object {
                            $name = $_
                            $value = $EdgeLimitedSettings[$name]
                            Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name $name -Type DWord -Value $value
                        }
                        #Microsoft Office
                        $OfficeRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry"          = @{
                                "DisableTelemetry" = 1 #Disable telemetry for Microsoft Office
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" = @{
                                "SendTelemetry" = 3 #Disable diagnostic data submission
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"            = @{
                                "QMEnable" = 0; #Disable participation in the Customer Experience Improvement Program
                                "LinkedIn" = 0 #Disable the display of LinkedIn information
                            }
                            "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings"        = @{
                                "InlineTextPrediction" = 0 #Disable inline text prediction in mails
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\osm"               = @{
                                "Enablelogging"         = 0; #Disable logging for Microsoft Office Telemetry Agent
                                "EnableUpload"          = 0; #Disable upload of data for Microsoft Office Telemetry Agent
                                "EnableFileObfuscation" = 1 #Obfuscate file names when uploading telemetry data
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback"   = @{
                                "SurveyEnabled" = 0; #Disable Microsoft Office surveys
                                "Enabled"       = 0; #Disable feedback to Microsoft
                                "IncludeEmail"  = 0 #Disable Microsoft's feedback tracking
                            }
                        }

                        $OfficeLimitedSettings = @{
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"         = @{
                                "UpdateReliabilityData" = 0 #Disable automatic receipt of updates
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy" = @{
                                "DisconnectedState"                  = 2; #Disable connected experiences in Office
                                "UserContentDisabled"                = 2; #Disable connected experiences with content analytics
                                "DownloadContentDisabled"            = 2; #Disable online content downloading for connected experiences
                                "ControllerConnectedServicesEnabled" = 2 #Disable optional connected experiences in Office
                            }
                        }

                        foreach ($settingType in $OfficeRecommendedSettings.Keys) {
                            foreach ($path in $OfficeRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $OfficeRecommendedSettings[$settingType][$path]
                            }
                        }

                        foreach ($settingType in $OfficeLimitedSettings.Keys) {
                            foreach ($path in $OfficeLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $OfficeLimitedSettings[$settingType][$path]
                            }
                        }

                        #Synchronization of Windows Settings
                        $SettingSyncRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"                        = @{
                                "SyncPolicy" = 5 #Disable synchronization of all settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" = @{
                                "Enabled" = 0 #Disable synchronization of design settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" = @{
                                "Enabled" = 0 #Disable synchronization of browser settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"     = @{
                                "Enabled" = 0 #Disable synchronization of credentials (passwords)
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"        = @{
                                "Enabled" = 0 #Disable synchronization of language settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"   = @{
                                "Enabled" = 0 #Disable synchronization of accessibility settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"         = @{
                                "Enabled" = 0 #Disable synchronization of advanced Windows settings
                            }
                        }

                        foreach ($settingType in $SettingSyncRecommendedSettings.Keys) {
                            foreach ($path in $SettingSyncRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SettingSyncRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Cortana (Personal Assistant)
                        $CortanaRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search" = @{
                                "CortanaConsent" = 0 #Disable and reset Cortana
                            }
                            "HKCU:\Software\Microsoft\InputPersonalization"                  = @{
                                "RestrictImplicitInkCollection"  = 1; #Disable Input Personalization
                                "RestrictImplicitTextCollection" = 1 #Disable Input Personalization
                            }
                            "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" = @{
                                "HarvestContacts" = 0 #Disable Input Personalization
                            }
                            "HKCU:\Software\Microsoft\Personalization\Settings"              = @{
                                "AcceptedPrivacyPolicy" = 0 #Disable Input Personalization
                            }
                        }

                        foreach ($settingType in $CortanaRecommendedSettings.Keys) {
                            foreach ($path in $CortanaRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $CortanaRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Windows Copilot
                        $CopilotRecommendedSettings = @{
                            "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"          = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "ShowCopilotButton" = 0 #Disable the Copilot button from the taskbar
                            }
                        }

                        foreach ($settingType in $CopilotRecommendedSettings.Keys) {
                            foreach ($path in $CopilotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $CopilotRecommendedSettings[$settingType][$path]
                            }
                        }

                        #User Behavior
                        $UserBehaviorRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" = @{
                                "TailoredExperiencesWithDiagnosticDataEnabled" = 0 #Disable the use of diagnostic data for a tailor-made user experience
                            }
                        }

                        foreach ($settingType in $UserBehaviorRecommendedSettings.Keys) {
                            foreach ($path in $UserBehaviorRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $UserBehaviorRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Windows Explorer
                        $WindowsContentDeliveryRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SystemPaneSuggestionsEnabled" = 0 #Disable occassionally showing app suggestions in Start menu
                            }
                        }

                        $WindowsContentDeliveryLimitedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "Start_TrackDocs"               = 0; #Do not show recently opened items in Jump Lists on "Start" or taskbar
                                "ShowSyncProviderNotifications" = 0 #Disable ads in Windows Explorer/OneDrive
                            }
                        }

                        foreach ($settingType in $WindowsContentDeliveryRecommendedSettings.Keys) {
                            foreach ($path in $WindowsContentDeliveryRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $WindowsContentDeliveryRecommendedSettings[$settingType][$path]
                            }
                        }

                        foreach ($settingType in $WindowsContentDeliveryLimitedSettings.Keys) {
                            foreach ($path in $WindowsContentDeliveryLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $WindowsContentDeliveryLimitedSettings[$settingType][$path]
                            }
                        }

                        #Lockscreen
                        $LockScreenRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "RotatingLockScreenEnabled"        = 0; #Disable Windows Spotlight
                                "RotatingLockScreenOverlayEnabled" = 0; #Disable fun facts, tips, tricks, and more on your lock screen
                                "SubscribedContent-338387Enabled"  = 0 #Disable fun facts, tips, tricks, and more on your lock screen
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" = @{
                                "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" = 0 #Disable notifications on lock screen
                            }
                        }

                        foreach ($settingType in $LockScreenRecommendedSettings.Keys) {
                            foreach ($path in $LockScreenRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $LockScreenRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Search
                        $SearchLimitedSettings = @{
                            "HKCU:\Software\Policies\Microsoft\Windows\Explorer" = @{
                                "DisableSearchBoxSuggestions" = 1 #Disable search with AI in search box
                            }
                        }

                        $SearchRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" = @{
                                "IsDynamicSearchBoxEnabled" = 0 #Disable extension of Windows search with Bing
                            }
                        }

                        foreach ($settingType in $SearchRecommendedSettings.Keys) {
                            foreach ($path in $SearchRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SearchRecommendedSettings[$settingType][$path]
                            }
                        }

                        foreach ($settingType in $SearchLimitedSettings.Keys) {
                            foreach ($path in $SearchLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SearchLimitedSettings[$settingType][$path]
                            }
                        }

                        #Taskbar
                        $TaskbarLimitedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" = @{
                                "PeopleBand" = 0 #Disable people icon in the taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"                   = @{
                                "SearchboxTaskbarMode" = 0 #Disable search box in taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"        = @{
                                "HideSCAMeetNow" = 1 #Disable "meet now" in the taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"                    = @{
                                "ShellFeedsTaskbarViewMode" = 2 #Disable news and interests in the taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"        = @{
                                "TaskbarDa" = 0 #Disable Widgets in Windows Explorer
                            }
                        }

                        foreach ($settingType in $TaskbarLimitedSettings.Keys) {
                            foreach ($path in $TaskbarLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $TaskbarLimitedSettings[$settingType][$path]
                            }
                        }

                        foreach ($settingType in $SearchRecommendedSettings.Keys) {
                            foreach ($path in $SearchRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SearchRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Miscellaneous
                        $MiscellaneousRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Siuf\Rules"                                    = @{
                                "NumberOfSIUFInPeriod" = 0 #Disable feedback reminders
                                "PeriodInNanoSeconds"  = 0 #Disable feedback reminders
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SilentInstalledAppsEnabled" = 0 #Disable automatic installation of recommended Windows Store Apps
                                "SoftLandingEnabled"         = 0 #Disable tips, tricks, and suggestions while using Windows
                            }
                            "HKCU:\Software\Microsoft\MediaPlayer\Preferences"                       = @{
                                "UsageTracking" = 0 #Disable Windows Media Player diagnostics
                            }
                        }

                        foreach ($settingType in $MiscellaneousRecommendedSettings.Keys) {
                            foreach ($path in $MiscellaneousRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $MiscellaneousRecommendedSettings[$settingType][$path]
                            }
                        }

                        Write-Host `n"The recommended and somewhat recommended settings for the current user have been applied." -BackgroundColor Black -ForegroundColor Green
                        Write-Host "For detailed information > " -NoNewline
                        Write-Host "https://github.com/caglaryalcin/StayPrivacy" -ForegroundColor DarkCyan
                    }
                    # Current User - All settings
                    "3" {
                        $ErrorActionPreference = 'SilentlyContinue'
                        New-PSDrive -PSProvider Registry -Name HKCU -Root HKEY_CURRENT_USER | Out-Null

                        #Privacy
                        $PrivacyRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SubscribedContent-353698Enabled" = 0 #Disable suggestions in the timeline
                                "SubscribedContent-338388Enabled" = 0 #Disable suggestions in Start
                                "SubscribedContent-338389Enabled" = 0 #Disable tips, tricks, and suggestions when using Windows
                                "SubscribedContent-338393Enabled" = 0 #Disable showing suggested content in the Settings app
                                "SubscribedContent-353694Enabled" = 0 #Disable showing suggested content in the Settings app
                                "SubscribedContent-353696Enabled" = 0 #Disable showing suggested content in the Settings app
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"  = @{
                                "ScoobeSystemSettingEnabled" = 0 #Disable the possibility of suggesting to finish the setup of the device
                            }
                            "HKCU:\Software\Microsoft\input\TIPC"                                    = @{
                                "Enabled" = 0 #Disable transmission of typing information
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"        = @{
                                "Enabled" = 0 #Disable and reset Advertising ID and info
                            }
                        }

                        $PrivacyNotRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" = @{
                                "EnableWebContentEvaluation" = 0 #Disable sending URLs from apps to Windows Store
                            }
                        }

                        $PrivacyLimitedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" = @{
                                "ToastEnabled" = 0 #Disable app notifications
                            }
                            "HKCU:\Software\Microsoft\TabletTip\1.7"                            = @{
                                "EnableTextPrediction" = 0 #Disable text suggestions when typing on the software keyboard
                            }
                            "HKCU:\Control Panel\International\User Profile"                    = @{
                                "HttpAcceptLanguageOptOut" = 1 #Disable access to local language for browsers
                            }
                        }

                        foreach ($path in $PrivacyRecommendedSettings.Keys) {
                            foreach ($name in $PrivacyRecommendedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $PrivacyRecommendedSettings[$path][$name]
                            }
                        }

                        foreach ($path in $PrivacyNotRecommendedSettings.Keys) {
                            foreach ($name in $PrivacyNotRecommendedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $PrivacyNotRecommendedSettings[$path][$name]
                            }
                        }

                        foreach ($path in $PrivacyLimitedSettings.Keys) {
                            foreach ($name in $PrivacyLimitedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $PrivacyLimitedSettings[$path][$name]
                            }
                        }

                        #Activity History and Clipboard
                        $HistoryRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Clipboard" = @{
                                "EnableClipboardHistory" = 0 #Disable storage of clipboard history
                            }
                        }

                        foreach ($path in $HistoryRecommendedSettings.Keys) {
                            foreach ($name in $HistoryRecommendedSettings[$path].Keys) {
                                Set-ItemProperty -Path $path -Name $name -Type DWord -Value $HistoryRecommendedSettings[$path][$name]
                            }
                        }

                        #App Privacy
                        $AppPrivacyRecommendedsettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" = "Deny" #Disable app access to user account information
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"         = "Deny" #Disable app access to diagnostics information
                        }

                        $AppPrivacyRecommendedsettings.GetEnumerator() | ForEach-Object {
                            Set-ItemProperty -Path $_.Key -Name "Value" -Value $_.Value -ErrorAction SilentlyContinue
                        }

                        $AppPrivacyRecommendedDwordsettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "Start_TrackProgs" = 0 #Disable Windows tracking of app starts
                            }
                        }

                        $AppPrivacyLimitedSettings = @{
                            "location"                                 = "Deny" #Disable app access to device location
                            "webcam"                                   = "Deny" #Disable app access to camera
                            "microphone"                               = "Deny" #Disable app access to microphone
                            "userNotificationListener"                 = "Deny" #Disable app access to notifications
                            "activity"                                 = "Deny" #Disable app access to motion
                            "contacts"                                 = "Deny" #Disable app access to contacts
                            "appointments"                             = "Deny" #Disable app access to calendar
                            "phoneCall"                                = "Deny" #Disable app access to phone calls
                            "phoneCallHistory"                         = "Deny" #Disable app access to call history
                            "email"                                    = "Deny" #Disable app access to email
                            "userDataTasks"                            = "Deny" #Disable app access to tasks
                            "chat"                                     = "Deny" #Disable app access to messages
                            "radios"                                   = "Deny" #Disable app access to radios
                            "bluetoothSync"                            = "Deny" #Disable app access to unpaired devices
                            "documentsLibrary"                         = "Deny" #Disable app access to documents
                            "picturesLibrary"                          = "Deny" #Disable app access to images
                            "videosLibrary"                            = "Deny" #Disable app access to videos
                            "broadFileSystemAccess"                    = "Deny" #Disable app access to the file system
                            "cellularData"                             = "Deny" #Disable app access to unpaired devices
                            "gazeInput"                                = "Deny" #Disable app access to eye tracking
                            "graphicsCaptureProgrammatic"              = "Deny" #Disable the ability for apps to take screenshots
                            "graphicsCaptureProgrammatic\NonPackaged"  = "Deny" #Disable the ability for desktop apps to take screenshots
                            "graphicsCaptureWithoutBorder"             = "Deny" #Disable the ability for apps to take screenshots without borders
                            "graphicsCaptureWithoutBorder\NonPackaged" = "Deny" #Disable the ability for desktop apps to take screenshots without margins
                            "musicLibrary"                             = "Deny" #Disable app access to music libraries
                            "downloadsFolder"                          = "Deny" #Disable app access to downloads folder
                        }

                        $AppPrivacyLimitedDwordSettings = @{
                            "AgentActivationEnabled"             = 0 #Disable app access to use voice activation
                            "AgentActivationOnLockScreenEnabled" = 0 #Disable app access to use voice activation when device is locked
                            "AgentActivationLastUsed"            = 0 #Disable the standard app for the headset button
                        }

                        $AppPrivacyNotRecommendedsettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" = @{
                                "GlobalUserDisabled" = 1 #Prohibit apps from running in the background
                            }
                        }

                        foreach ($settingType in $AppPrivacyRecommendedDwordsettings.Keys) {
                            foreach ($path in $AppPrivacyRecommendedDwordsettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $AppPrivacyRecommendedDwordsettings[$settingType][$path]
                            }
                        }

                        $AppPrivacyLimitedSettings.GetEnumerator() | ForEach-Object {
                            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$($_.Key)" -Name "Value" -Value $_.Value
                        }

                        $AppPrivacyLimitedDwordSettings.GetEnumerator() | ForEach-Object {
                            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name $_.Key -Type DWord -Value $_.Value
                        }

                        foreach ($settingType in $AppPrivacyNotRecommendedsettings.Keys) {
                            foreach ($path in $AppPrivacyNotRecommendedsettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $AppPrivacyNotRecommendedsettings[$settingType][$path]
                            }
                        }

                        #Microsoft Edge (new version based on Chromium)
                        $EdgeRecommendedSettings = @{
                            "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                            "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                            "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                            "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                            "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                            "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                            "AutofillAddressEnabled"                         = 0 #Disable form suggestions
                            "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                            "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                            "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                            "WebWidgetAllowed"                               = 0 #Disable Edge bar
                            "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                        }

                        $EdgeNotRecommendedSettings = @{
                            "TyposquattingCheckerEnabled" = 0 #Disable typosquatting checker for site addresses
                            "SmartScreenEnabled"          = 0 #Disable SmartScreen Filter
                        }

                        $EdgeLimitedSettings = @{
                            "ResolveNavigationErrorsUseWebService" = 0 #Disable use of web service to resolve navigation errors
                            "AlternateErrorPagesEnabled"           = 0 #Disable suggestion of similar sites when website cannot be found
                            "NetworkPredictionOptions"             = 2 #Disable preload of pages for faster browsing and searching
                            "PasswordManagerEnabled"               = 0 #Disable saving passwords for websites
                            "SiteSafetyServicesEnabled"            = 0 #Disable site safety services for more information about a visited website
                        }

                        $EdgeRecommendedSettings.Keys | ForEach-Object {
                            $name = $_
                            $value = $EdgeRecommendedSettings[$name]
                            Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name $name -Type DWord -Value $value
                        }

                        $EdgeNotRecommendedSettings.Keys | ForEach-Object {
                            $name = $_
                            $value = $EdgeNotRecommendedSettings[$name]
                            Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name $name -Type DWord -Value $value
                        }

                        $EdgeLimitedSettings.Keys | ForEach-Object {
                            $name = $_
                            $value = $EdgeLimitedSettings[$name]
                            Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name $name -Type DWord -Value $value
                        }

                        #Microsoft Office
                        $OfficeRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry"          = @{
                                "DisableTelemetry" = 1 #Disable telemetry for Microsoft Office
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" = @{
                                "SendTelemetry" = 3 #Disable diagnostic data submission
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"            = @{
                                "QMEnable" = 0; #Disable participation in the Customer Experience Improvement Program
                                "LinkedIn" = 0 #Disable the display of LinkedIn information
                            }
                            "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings"        = @{
                                "InlineTextPrediction" = 0 #Disable inline text prediction in mails
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\osm"               = @{
                                "Enablelogging"         = 0; #Disable logging for Microsoft Office Telemetry Agent
                                "EnableUpload"          = 0; #Disable upload of data for Microsoft Office Telemetry Agent
                                "EnableFileObfuscation" = 1 #Obfuscate file names when uploading telemetry data
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback"   = @{
                                "SurveyEnabled" = 0; #Disable Microsoft Office surveys
                                "Enabled"       = 0; #Disable feedback to Microsoft
                                "IncludeEmail"  = 0 #Disable Microsoft's feedback tracking
                            }
                        }

                        $OfficeLimitedSettings = @{
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"         = @{
                                "UpdateReliabilityData" = 0 #Disable automatic receipt of updates
                            }
                            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy" = @{
                                "DisconnectedState"                  = 2; #Disable connected experiences in Office
                                "UserContentDisabled"                = 2; #Disable connected experiences with content analytics
                                "DownloadContentDisabled"            = 2; #Disable online content downloading for connected experiences
                                "ControllerConnectedServicesEnabled" = 2 #Disable optional connected experiences in Office
                            }
                        }

                        foreach ($settingType in $OfficeRecommendedSettings.Keys) {
                            foreach ($path in $OfficeRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $OfficeRecommendedSettings[$settingType][$path]
                            }
                        }

                        foreach ($settingType in $OfficeLimitedSettings.Keys) {
                            foreach ($path in $OfficeLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $OfficeLimitedSettings[$settingType][$path]
                            }
                        }

                        #Synchronization of Windows Settings
                        $SettingSyncRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"                        = @{
                                "SyncPolicy" = 5 #Disable synchronization of all settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" = @{
                                "Enabled" = 0 #Disable synchronization of design settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" = @{
                                "Enabled" = 0 #Disable synchronization of browser settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"     = @{
                                "Enabled" = 0 #Disable synchronization of credentials (passwords)
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"        = @{
                                "Enabled" = 0 #Disable synchronization of language settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"   = @{
                                "Enabled" = 0 #Disable synchronization of accessibility settings
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"         = @{
                                "Enabled" = 0 #Disable synchronization of advanced Windows settings
                            }
                        }

                        foreach ($settingType in $SettingSyncRecommendedSettings.Keys) {
                            foreach ($path in $SettingSyncRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SettingSyncRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Cortana (Personal Assistant)
                        $CortanaRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search" = @{
                                "CortanaConsent" = 0 #Disable and reset Cortana
                            }
                            "HKCU:\Software\Microsoft\InputPersonalization"                  = @{
                                "RestrictImplicitInkCollection"  = 1; #Disable Input Personalization
                                "RestrictImplicitTextCollection" = 1 #Disable Input Personalization
                            }
                            "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" = @{
                                "HarvestContacts" = 0 #Disable Input Personalization
                            }
                            "HKCU:\Software\Microsoft\Personalization\Settings"              = @{
                                "AcceptedPrivacyPolicy" = 0 #Disable Input Personalization
                            }
                        }

                        foreach ($settingType in $CortanaRecommendedSettings.Keys) {
                            foreach ($path in $CortanaRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $CortanaRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Windows Copilot
                        $CopilotRecommendedSettings = @{
                            "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"          = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "ShowCopilotButton" = 0 #Disable the Copilot button from the taskbar
                            }
                        }

                        foreach ($settingType in $CopilotRecommendedSettings.Keys) {
                            foreach ($path in $CopilotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $CopilotRecommendedSettings[$settingType][$path]
                            }
                        }

                        #User Behavior
                        $UserBehaviorRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" = @{
                                "TailoredExperiencesWithDiagnosticDataEnabled" = 0 #Disable the use of diagnostic data for a tailor-made user experience
                            }
                        }

                        foreach ($settingType in $UserBehaviorRecommendedSettings.Keys) {
                            foreach ($path in $UserBehaviorRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $UserBehaviorRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Windows Explorer
                        $WindowsContentDeliveryRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SystemPaneSuggestionsEnabled" = 0 #Disable occassionally showing app suggestions in Start menu
                            }
                        }

                        $WindowsContentDeliveryLimitedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
                                "Start_TrackDocs"               = 0; #Do not show recently opened items in Jump Lists on "Start" or taskbar
                                "ShowSyncProviderNotifications" = 0 #Disable ads in Windows Explorer/OneDrive
                            }
                        }

                        foreach ($settingType in $WindowsContentDeliveryRecommendedSettings.Keys) {
                            foreach ($path in $WindowsContentDeliveryRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $WindowsContentDeliveryRecommendedSettings[$settingType][$path]
                            }
                        }

                        foreach ($settingType in $WindowsContentDeliveryLimitedSettings.Keys) {
                            foreach ($path in $WindowsContentDeliveryLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $WindowsContentDeliveryLimitedSettings[$settingType][$path]
                            }
                        }

                        #Lockscreen
                        $LockScreenRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "RotatingLockScreenEnabled"        = 0; #Disable Windows Spotlight
                                "RotatingLockScreenOverlayEnabled" = 0; #Disable fun facts, tips, tricks, and more on your lock screen
                                "SubscribedContent-338387Enabled"  = 0 #Disable fun facts, tips, tricks, and more on your lock screen
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" = @{
                                "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" = 0 #Disable notifications on lock screen
                            }
                        }

                        foreach ($settingType in $LockScreenRecommendedSettings.Keys) {
                            foreach ($path in $LockScreenRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $LockScreenRecommendedSettings[$settingType][$path]
                            }
                        }

                        #Search
                        $SearchLimitedSettings = @{
                            "HKCU:\Software\Policies\Microsoft\Windows\Explorer" = @{
                                "DisableSearchBoxSuggestions" = 1 #Disable search with AI in search box
                            }
                        }

                        $SearchRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" = @{
                                "IsDynamicSearchBoxEnabled" = 0 #Disable extension of Windows search with Bing
                            }
                        }

                        foreach ($settingType in $SearchRecommendedSettings.Keys) {
                            foreach ($path in $SearchRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SearchRecommendedSettings[$settingType][$path]
                            }
                        }

                        foreach ($settingType in $SearchLimitedSettings.Keys) {
                            foreach ($path in $SearchLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $SearchLimitedSettings[$settingType][$path]
                            }
                        }

                        #Taskbar
                        $TaskbarLimitedSettings = @{
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" = @{
                                "PeopleBand" = 0 #Disable people icon in the taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"                   = @{
                                "SearchboxTaskbarMode" = 0 #Disable search box in taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"        = @{
                                "HideSCAMeetNow" = 1 #Disable "meet now" in the taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"                    = @{
                                "ShellFeedsTaskbarViewMode" = 2 #Disable news and interests in the taskbar
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"        = @{
                                "TaskbarDa" = 0 #Disable Widgets in Windows Explorer
                            }
                        }

                        foreach ($settingType in $TaskbarLimitedSettings.Keys) {
                            foreach ($path in $TaskbarLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $TaskbarLimitedSettings[$settingType][$path]
                            }
                        }

                        #Miscellaneous
                        $MiscellaneousRecommendedSettings = @{
                            "HKCU:\Software\Microsoft\Siuf\Rules"                                    = @{
                                "NumberOfSIUFInPeriod" = 0 #Disable feedback reminders
                                "PeriodInNanoSeconds"  = 0 #Disable feedback reminders
                            }
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
                                "SilentInstalledAppsEnabled" = 0 #Disable automatic installation of recommended Windows Store Apps
                                "SoftLandingEnabled"         = 0 #Disable tips, tricks, and suggestions while using Windows
                            }
                            "HKCU:\Software\Microsoft\MediaPlayer\Preferences"                       = @{
                                "UsageTracking" = 0 #Disable Windows Media Player diagnostics
                            }
                        }

                        foreach ($settingType in $MiscellaneousRecommendedSettings.Keys) {
                            foreach ($path in $MiscellaneousRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $path -Type DWord -Value $MiscellaneousRecommendedSettings[$settingType][$path]
                            }
                        }

                        Write-Host `n"All settings have been applied for the current user." -BackgroundColor Black -ForegroundColor Green
                        Write-Host "For detailed information > " -NoNewline
                        Write-Host "https://github.com/caglaryalcin/StayPrivacy" -ForegroundColor DarkCyan

                    }

                    default {
                        Write-Host "Invalid input. Please enter 1, 2 or 3."
                        $validChoice = $false
                    }
                }
            } while (-not $validChoice)
        }
        # All users
        "2" {
            function Test-HKLMRegistryPaths {
                $registryPaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder"
                    "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"
                    "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\InputPersonalization"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors"
                    "HKLM:\SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration"
                    "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
                    "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\MRT"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Spynet"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
                    "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
                    "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet"
                    "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth"
                    "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Messaging"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\TabletPC"
                    "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Biometrics"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI"
                    "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack"
                    "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice"
                    "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"
                    "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice"
                    "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack"
                    "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\WMDRM"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Feeds"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsCopilot"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive"
                    "HKLM:\SOFTWARE\Microsoft\OneDrive"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Speech"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeliveryOptimization"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate"
                    "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate"
                    "HKLM:\SYSTEM\ControlSet001\Services\wuauserv"
                    "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv"
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d"
                )
            
                $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $userKey = "HKU:\$currentSID"
                Set-ItemProperty -Path "$userKey\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0

                foreach ($path in $registryPaths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    else {
                        ##
                    }
                }
            }
            
            Test-HKLMRegistryPaths

            do {
                Write-Host `n"Which settings do you want to use?"
                Write-Host `n"[1]" -NoNewline
                Write-Host " - Recommended settings"
                Write-Host "[2]" -NoNewline
                Write-Host " - Recommended and " -NoNewline
                Write-Host "Somewhat recommended settings" -BackgroundColor Black -ForegroundColor Yellow
                Write-Host "[3]" -NoNewline
                Write-Host " - " -NoNewline
                Write-Host "All them" -BackgroundColor Black -ForegroundColor Red
                $choice = Read-Host -Prompt "`n[Choice]"
                    
                $validChoice = $true
                    
                switch ($choice) {
                    # All Users - Recommended settings
                    "1" {
                        #Activity History and Clipboard
                        $HistoryRecommendedSystemSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"             = @{
                                "EnableActivityFeed"        = 0 #Disable recordings of user activity
                                "PublishUserActivities"     = 0 #Disable storing users' activity history
                                "UploadUserActivities"      = 0 #Disable the submission of user activities to Microsoft
                                "AllowClipboardHistory"     = 0 #Disable storage of clipboard history for whole machine
                                "AllowCrossDeviceClipboard" = 0 #Disable the transfer of the clipboard to other devices via the cloud
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" = @{
                                "EnableActivityFeed"        = 0 #Disable recordings of user activity
                                "PublishUserActivities"     = 0 #Disable storing users' activity history
                                "UploadUserActivities"      = 0 #Disable the submission of user activities to Microsoft
                                "AllowClipboardHistory"     = 0 #Disable storage of clipboard history for whole machine
                                "AllowCrossDeviceClipboard" = 0 #Disable the transfer of the clipboard to other devices via the cloud
                            }
                        }

                        foreach ($settingType in $HistoryRecommendedSystemSettings.Keys) {
                            foreach ($key in $HistoryRecommendedSystemSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Type DWord -Value $HistoryRecommendedSystemSettings[$settingType][$key]
                            }
                        }

                        #App Privacy
                        $AppPrivacyRecommendedSettings = @{
                            "userAccountInformation" = "Deny" # Disable app access to user account information
                            "appDiagnostics"         = "Deny" # Disable app access to diagnostics information
                        }

                        foreach ($setting in $AppPrivacyRecommendedSettings.Keys) {
                            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$setting"
                            Set-ItemProperty -Path $path -Name "Value" -Value $AppPrivacyRecommendedSettings[$setting]
                        }

                        #Cortana (Personal Assistant)
                        $CortanaRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"                  = @{
                                "ModelDownloadAllowed" = 0 #Disable download and updates of speech recognition and speech synthesis models
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"               = @{
                                "AllowInputPersonalization" = 0 #Disable online speech recognition
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"             = @{
                                "AllowSearchToUseLocation"  = 0 #Cortana and search are disallowed to use location
                                "DisableWebSearch"          = 1 #Disable web search from Windows Desktop Search
                                "ConnectedSearchUseWeb"     = 0 #Disable display web results in Search
                                "AllowCloudSearch"          = 0 #Disable cloud search
                                "AllowCortanaAboveLock"     = 0 #Disable Cortana above lock screen
                                "EnableDynamicContentInWSB" = 0 #Disable the search highlights in the taskbar
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\InputPersonalization"   = @{
                                "AllowInputPersonalization" = 0 #Disable online speech recognition
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search" = @{
                                "AllowSearchToUseLocation"  = 0 #Cortana and search are disallowed to use location
                                "DisableWebSearch"          = 1 #Disable web search from Windows Desktop Search
                                "ConnectedSearchUseWeb"     = 0 #Disable display web results in Search
                                "AllowCloudSearch"          = 0 #Disable cloud search
                                "AllowCortanaAboveLock"     = 0 #Disable Cortana above lock screen
                                "EnableDynamicContentInWSB" = 0 #Disable the search highlights in the taskbar
                            }

                        }

                        foreach ($settingType in $CortanaRecommendedSettings.Keys) {
                            foreach ($key in $CortanaRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $CortanaRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Location Services
                        $LocationRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"             = @{
                                "DisableLocation"                = 1 #Disable functionality to locate the system
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors" = @{
                                "DisableLocation"                = 1 #Disable functionality to locate the system
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                        }

                        foreach ($settingType in $LocationRecommendedSettings.Keys) {
                            foreach ($key in $LocationRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $LocationRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Microsoft Edge (new version based on Chromium)
                        $EdgeRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Edge"             = @{
                                "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                                "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                                "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                                "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                                "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                                "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                                "AutofillAddressEnabled"                         = 0 #Disable fomr suggestions
                                "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                                "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                                "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                                "WebWidgetAllowed"                               = 0 #Disable Edge bar
                                "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" = @{
                                "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                                "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                                "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                                "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                                "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                                "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                                "AutofillAddressEnabled"                         = 0 #Disable fomr suggestions
                                "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                                "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                                "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                                "WebWidgetAllowed"                               = 0 #Disable Edge bar
                                "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                            }
                        }

                        foreach ($settingType in $EdgeRecommendedSettings.Keys) {
                            foreach ($key in $EdgeRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $EdgeRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Miscellaneous
                        $MiscellaneousRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"             = @{
                                "DoNotShowFeedbackNotifications" = 1 #Disable feedback reminders
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" = @{
                                "DoNotShowFeedbackNotifications" = 1 #Disable feedback reminders
                            }
                        }

                        foreach ($settingType in $MiscellaneousRecommendedSettings.Keys) {
                            foreach ($key in $MiscellaneousRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $MiscellaneousRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Privacy
                        $PrivacyRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth"               = @{
                                "AllowAdvertising"               = 0 #Disable advertiesements via Bluetooth
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"                      = @{
                                "Disabled" = 1 #Disable Windows Error Reporting
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                           = @{
                                "DisableInventory" = 1 #Disable Inventory Collector
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"             = @{
                                "PreventHandwritingErrorReports" = 1 #Disable sharing of handwriting error reports
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"                           = @{
                                "AllowMessageSync" = 0 #Disable backup of text messages into the cloud
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"                     = @{
                                "NoLockScreenCamera" = 1 #Disable camera in logon screen
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"                            = @{
                                "PreventHandwritingDataSharing" = 1 #Disable sharing of handwriting data
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"               = @{
                                "DisableInventory" = 1 #Disable Inventory Collector
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" = @{
                                "PreventHandwritingErrorReports" = 1 #Disable sharing of handwriting error reports
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Messaging"               = @{
                                "AllowMessageSync" = 0 #Disable backup of text messages into the cloud
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization"         = @{
                                "NoLockScreenCamera" = 1 #Disable camera in logon screen
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\TabletPC"                = @{
                                "PreventHandwritingDataSharing" = 1 #Disable sharing of handwriting data
                            }
                            "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows"                                    = @{
                                "CEIPEnable" = 0 #Disable advertisements via Bluetooth
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"               = @{
                                "Enabled" = 0 #Disable advertisements via Bluetooth
                            }
                        }

                        foreach ($settingType in $PrivacyRecommendedSettings.Keys) {
                            foreach ($key in $PrivacyRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $PrivacyRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Security
                        $SecurityRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                                 = @{
                                "DisableUAR" = 1 #Disable user steps recorder
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"                                    = @{
                                "DisablePasswordReveal" = 1 #Disable password reveal button
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"                     = @{
                                "DisableUAR" = 1 #Disable user steps recorder
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI"                        = @{
                                "DisablePasswordReveal" = 1 #Disable password reveal button
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack"                                   = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice"                            = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" = @{
                                "Start" = 0 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice"                                = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack"                                       = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"     = @{
                                "Start" = 0 #Disable temeletry
                            }
                        
                        }

                        foreach ($settingType in $SecurityRecommendedSettings.Keys) {
                            foreach ($key in $SecurityRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $SecurityRecommendedSettings[$settingType][$key]
                            }
                        }
	
                        #User Behavior
                        $UserBehaviorRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"                             = @{
                                "TailoredExperiencesWithDiagnosticDataEnabled" = 0 #Disable diagnostic data from customizing user experiences for whole machine
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                                 = @{
                                "AITEnable" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                            = @{
                                "AllowTelemetry"               = 0 #Disable application telemetry
                                "LimitDiagnosticLogCollection" = 1 #Disable diagnostic log collection
                                "DisableOneSettingsDownloads"  = 1 #Disable downloading of OneSettings configuration settings
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"                     = @{
                                "AITEnable" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"                = @{
                                "AllowTelemetry"               = 0 #Disable application telemetry
                                "LimitDiagnosticLogCollection" = 1 #Disable diagnostic log collection
                                "DisableOneSettingsDownloads"  = 1 #Disable downloading of OneSettings configuration settings
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
                                "AllowTelemetry" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"             = @{
                                "AllowTelemetry" = 0 #Disable application telemetry
                            }
                        }

                        foreach ($settingType in $UserBehaviorRecommendedSettings.Keys) {
                            foreach ($key in $UserBehaviorRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UserBehaviorRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Windows Copilot
                        $CopilotRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"             = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsCopilot" = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                        }

                        foreach ($settingType in $CopilotRecommendedSettings.Keys) {
                            foreach ($key in $CopilotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $CopilotRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Windows Update
                        $UpdateRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Speech"                                    = @{
                                "AllowSpeechModelUpdate" = 0 #Disable updates to the speech recognition and speech synthesis modules
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"              = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech"                        = @{
                                "AllowSpeechModelUpdate" = 0 #Disable updates to the speech recognition and speech synthesis modules
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeliveryOptimization"  = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                        }

                        $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                        $userKey = "HKU:\$currentSID"
                        Set-ItemProperty -Path "$userKey\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 #Disable Windows Update via peer-to-peer

                        foreach ($settingType in $UpdateRecommendedSettings.Keys) {
                            foreach ($key in $UpdateRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UpdateRecommendedSettings[$settingType][$key]
                            }
                        }

                        Write-Host `n"Recommended and somewhat recommended settings were applied for current user." -BackgroundColor Black -ForegroundColor Green
                        Write-Host "For detailed information > " -NoNewline
                        Write-Host "https://github.com/caglaryalcin/StayPrivacy" -ForegroundColor DarkCyan
                    }
                    # All Users - Recommended and Somewhat recommended settings
                    "2" {
                        #Activity History and Clipboard
                        $HistoryRecommendedSystemSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"             = @{
                                "EnableActivityFeed"        = 0 #Disable recordings of user activity
                                "PublishUserActivities"     = 0 #Disable storing users' activity history
                                "UploadUserActivities"      = 0 #Disable the submission of user activities to Microsoft
                                "AllowClipboardHistory"     = 0 #Disable storage of clipboard history for whole machine
                                "AllowCrossDeviceClipboard" = 0 #Disable the transfer of the clipboard to other devices via the cloud
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" = @{
                                "EnableActivityFeed"        = 0 #Disable recordings of user activity
                                "PublishUserActivities"     = 0 #Disable storing users' activity history
                                "UploadUserActivities"      = 0 #Disable the submission of user activities to Microsoft
                                "AllowClipboardHistory"     = 0 #Disable storage of clipboard history for whole machine
                                "AllowCrossDeviceClipboard" = 0 #Disable the transfer of the clipboard to other devices via the cloud
                            }
                        }

                        foreach ($settingType in $HistoryRecommendedSystemSettings.Keys) {
                            foreach ($key in $HistoryRecommendedSystemSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Type DWord -Value $HistoryRecommendedSystemSettings[$settingType][$key]
                            }
                        }

                        #App Privacy
                        $AppPrivacyRecommendedSettings = @{
                            "userAccountInformation" = "Deny" # Disable app access to user account information
                            "appDiagnostics"         = "Deny" # Disable app access to diagnostics information
                        }

                        $AppPrivacyLimitedSettings = @{
                            "location"                     = "Deny" # Disable app access to device location
                            "webcam"                       = "Deny" # Disable app access to camera
                            "microphone"                   = "Deny" # Disable app access to microphone
                            "userNotificationListener"     = "Deny" # Disable app access to notifications
                            "activity"                     = "Deny" # Disable app access to motion
                            "contacts"                     = "Deny" # Disable app access to contacts
                            "appointments"                 = "Deny" # Disable app access to calendar
                            "phoneCall"                    = "Deny" # Disable app access to phone calls
                            "phoneCallHistory"             = "Deny" # Disable app access to call history
                            "email"                        = "Deny" # Disable app access to email
                            "userDataTasks"                = "Deny" # Disable app access to tasks
                            "chat"                         = "Deny" # Disable app access to messages
                            "radios"                       = "Deny" # Disable app access to radios
                            "bluetoothSync"                = "Deny" # Disable app access to unpaired devices
                            "documentsLibrary"             = "Deny" # Disable app access to documents
                            "picturesLibrary"              = "Deny" # Disable app access to images
                            "videosLibrary"                = "Deny" # Disable app access to videos
                            "broadFileSystemAccess"        = "Deny" # Disable app access to the file system
                            "cellularData"                 = "Deny" # Disable app access to unpaired devices
                            "gazeInput"                    = "Deny" # Disable app access to eye tracking
                            "graphicsCaptureProgrammatic"  = "Deny" # Disable the ability for apps to take screenshots
                            "graphicsCaptureWithoutBorder" = "Deny" # Disable the ability for desktop apps to take screenshots without borders
                            "musicLibrary"                 = "Deny" # Disable app access to music libraries
                            "downloadsFolder"              = "Deny" # Disable app access to downloads folder
                        }

                        foreach ($setting in $AppPrivacyRecommendedSettings.Keys) {
                            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$setting"
                            Set-ItemProperty -Path $path -Name "Value" -Value $AppPrivacyRecommendedSettings[$setting]
                        }

                        foreach ($setting in $AppPrivacyLimitedSettings.Keys) {
                            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$setting"
                            Set-ItemProperty -Path $path -Name "Value" -Value $AppPrivacyLimitedSettings[$setting]
                        }

                        #Cortana (Personal Assistant)
                        $CortanaRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"                  = @{
                                "ModelDownloadAllowed" = 0 #Disable download and updates of speech recognition and speech synthesis models
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"               = @{
                                "AllowInputPersonalization" = 0 #Disable online speech recognition
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"             = @{
                                "AllowSearchToUseLocation"  = 0 #Cortana and search are disallowed to use location
                                "DisableWebSearch"          = 1 #Disable web search from Windows Desktop Search
                                "ConnectedSearchUseWeb"     = 0 #Disable display web results in Search
                                "AllowCloudSearch"          = 0 #Disable cloud search
                                "AllowCortanaAboveLock"     = 0 #Disable Cortana above lock screen
                                "EnableDynamicContentInWSB" = 0 #Disable the search highlights in the taskbar
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\InputPersonalization"   = @{
                                "AllowInputPersonalization" = 0 #Disable online speech recognition
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search" = @{
                                "AllowSearchToUseLocation"  = 0 #Cortana and search are disallowed to use location
                                "DisableWebSearch"          = 1 #Disable web search from Windows Desktop Search
                                "ConnectedSearchUseWeb"     = 0 #Disable display web results in Search
                                "AllowCloudSearch"          = 0 #Disable cloud search
                                "AllowCortanaAboveLock"     = 0 #Disable Cortana above lock screen
                                "EnableDynamicContentInWSB" = 0 #Disable the search highlights in the taskbar
                            }

                        }

                        foreach ($settingType in $CortanaRecommendedSettings.Keys) {
                            foreach ($key in $CortanaRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $CortanaRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Location Services
                        $LocationRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"             = @{
                                "DisableLocation"                = 1 #Disable functionality to locate the system
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors" = @{
                                "DisableLocation"                = 1 #Disable functionality to locate the system
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                        }

                        $LocationLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"                                               = @{
                                "DisableSensors" = 1 #Disable sensors for locating the system and its orientation
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors"                                   = @{
                                "DisableSensors" = 1 #Disable sensors for locating the system and its orientation
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration"                                            = @{
                                "Status" = 0 #Disable Windows Geolocation Service
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"                                        = @{
                                "Status" = 0 #Disable Windows Geolocation Service
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" = @{
                                "SensorPermissionState" = 0 #Disable Windows Geolocation Service
                            }
                        }	

                        foreach ($settingType in $LocationRecommendedSettings.Keys) {
                            foreach ($key in $LocationRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $LocationRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $LocationLimitedSettings.Keys) {
                            foreach ($key in $LocationLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $LocationLimitedSettings[$settingType][$key]
                            }
                        }

                        #Microsoft Defender and Microsoft Spynet
                        $DefenderSypnetLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\MRT"                                 = @{
                                "DontReportInfectionInformation" = 1 #Disable reporting of malware infection information
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"             = @{
                                "SpyNetReporting"      = 0 #Disable Microsoft SpyNet membership
                                "SubmitSamplesConsent" = 2 #Disable submitting data samples to Microsoft
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\MRT"                     = @{
                                "DontReportInfectionInformation" = 1 #Disable reporting of malware infection information
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Spynet" = @{
                                "SpyNetReporting"      = 0 #Disable Microsoft SpyNet membership
                                "SubmitSamplesConsent" = 2 #Disable submitting data samples to Microsoft
                            }
                        }

                        foreach ($settingType in $DefenderSypnetLimitedSettings.Keys) {
                            foreach ($key in $DefenderSypnetLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $DefenderSypnetLimitedSettings[$settingType][$key]
                            }
                        }

                        #Microsoft Edge (new version based on Chromium)
                        $EdgeRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Edge"             = @{
                                "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                                "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                                "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                                "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                                "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                                "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                                "AutofillAddressEnabled"                         = 0 #Disable fomr suggestions
                                "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                                "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                                "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                                "WebWidgetAllowed"                               = 0 #Disable Edge bar
                                "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" = @{
                                "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                                "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                                "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                                "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                                "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                                "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                                "AutofillAddressEnabled"                         = 0 #Disable fomr suggestions
                                "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                                "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                                "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                                "WebWidgetAllowed"                               = 0 #Disable Edge bar
                                "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                            }
                        }

                        $EdgeLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Edge"             = @{
                                "ResolveNavigationErrorsUseWebService" = 0 #Disable use of web service to resolve navigation errors
                                "AlternateErrorPagesEnabled"           = 0 #Disable suggestion of similar sites when website cannot be found
                                "NetworkPredictionOptions"             = 2 #Disable preload of pages for faster browsing and searching
                                "PasswordManagerEnabled"               = 0 #Disable saving passwords for websites
                                "SiteSafetyServicesEnabled"            = 0 #Disable site safety services for more information about a visited website
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" = @{
                                "ResolveNavigationErrorsUseWebService" = 0 #Disable use of web service to resolve navigation errors
                                "AlternateErrorPagesEnabled"           = 0 #Disable suggestion of similar sites when website cannot be found
                                "NetworkPredictionOptions"             = 2 #Disable preload of pages for faster browsing and searching
                                "PasswordManagerEnabled"               = 0 #Disable saving passwords for websites
                                "SiteSafetyServicesEnabled"            = 0 #Disable site safety services for more information about a visited website
                            }
                        }

                        foreach ($settingType in $EdgeRecommendedSettings.Keys) {
                            foreach ($key in $EdgeRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $EdgeRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $EdgeLimitedSettings.Keys) {
                            foreach ($key in $EdgeLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $EdgeLimitedSettings[$settingType][$key]
                            }
                        }

                        #Miscellaneous
                        $MiscellaneousRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"             = @{
                                "DoNotShowFeedbackNotifications" = 1 #Disable feedback reminders
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" = @{
                                "DoNotShowFeedbackNotifications" = 1 #Disable feedback reminders
                            }
                        }

                        $MiscellaneousLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps"                                                       = @{
                                "AutoDownloadAndUpdateMapData"                 = 0 #Disable automatic download and update of map data
                                "AllowUntriggeredNetworkTrafficOnSettingsPage" = 0 #Disable unsolicited network traffic on the offline maps settings page
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"             = @{
                                "NoGenTicket" = 1 #Disable Key Management Service Online Activation
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps"                                           = @{
                                "AutoDownloadAndUpdateMapData"                 = 0 #Disable automatic download and update of map data
                                "AllowUntriggeredNetworkTrafficOnSettingsPage" = 0 #Disable unsolicited network traffic on the offline maps settings page
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" = @{
                                "NoGenTicket" = 1 #Disable Key Management Service Online Activation
                            }
                        }

                        foreach ($settingType in $MiscellaneousRecommendedSettings.Keys) {
                            foreach ($key in $MiscellaneousRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $MiscellaneousRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $MiscellaneousLimitedSettings.Keys) {
                            foreach ($key in $MiscellaneousLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $MiscellaneousLimitedSettings[$settingType][$key]
                            }
                        }

                        #Privacy
                        $PrivacyRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth"               = @{
                                "AllowAdvertising"               = 0 #Disable advertiesements via Bluetooth
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"                      = @{
                                "Disabled" = 1 #Disable Windows Error Reporting
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                           = @{
                                "DisableInventory" = 1 #Disable Inventory Collector
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"             = @{
                                "PreventHandwritingErrorReports" = 1 #Disable sharing of handwriting error reports
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"                           = @{
                                "AllowMessageSync" = 0 #Disable backup of text messages into the cloud
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"                     = @{
                                "NoLockScreenCamera" = 1 #Disable camera in logon screen
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"                            = @{
                                "PreventHandwritingDataSharing" = 1 #Disable sharing of handwriting data
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"               = @{
                                "DisableInventory" = 1 #Disable Inventory Collector
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" = @{
                                "PreventHandwritingErrorReports" = 1 #Disable sharing of handwriting error reports
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Messaging"               = @{
                                "AllowMessageSync" = 0 #Disable backup of text messages into the cloud
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization"         = @{
                                "NoLockScreenCamera" = 1 #Disable camera in logon screen
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\TabletPC"                = @{
                                "PreventHandwritingDataSharing" = 1 #Disable sharing of handwriting data
                            }
                            "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows"                                    = @{
                                "CEIPEnable" = 0 #Disable advertisements via Bluetooth
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"               = @{
                                "Enabled" = 0 #Disable advertisements via Bluetooth
                            }
                        }

                        $PrivacyLimitedSettings = @{
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Biometrics" = @{
                                "Enabled" = 0 #Disable biometrical features
                            }
                        }

                        foreach ($settingType in $PrivacyRecommendedSettings.Keys) {
                            foreach ($key in $PrivacyRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $PrivacyRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $PrivacyLimitedSettings.Keys) {
                            foreach ($key in $PrivacyLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $PrivacyLimitedSettings[$settingType][$key]
                            }
                        }

                        #Security
                        $SecurityRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                                 = @{
                                "DisableUAR" = 1 #Disable user steps recorder
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"                                    = @{
                                "DisablePasswordReveal" = 1 #Disable password reveal button
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"                     = @{
                                "DisableUAR" = 1 #Disable user steps recorder
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI"                        = @{
                                "DisablePasswordReveal" = 1 #Disable password reveal button
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack"                                   = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice"                            = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" = @{
                                "Start" = 0 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice"                                = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack"                                       = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"     = @{
                                "Start" = 0 #Disable temeletry
                            }
                        
                        }

                        $SecurityLimitedSettings = @{
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\WMDRM" = @{
                                "DisableOnline" = 1 #Disable Internet access of Windows Media Digital Rights Management (DRM)
	
                            }
                        }

                        foreach ($settingType in $SecurityRecommendedSettings.Keys) {
                            foreach ($key in $SecurityRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $SecurityRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $SecurityLimitedSettings.Keys) {
                            foreach ($key in $SecurityLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $SecurityLimitedSettings[$settingType][$key]
                            }
                        }

                        #Taskbar
                        $TaskbarLimitedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"             = @{
                                "HideSCAMeetNow" = 1 #Disable "Meet now" in the taskbar
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"                       = @{
                                "EnableFeeds" = 0 #Disable news and interests in the taskbar
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
                                "HideSCAMeetNow" = 1 #Disable "Meet now" in the taskbar
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Feeds"           = @{
                                "EnableFeeds" = 0 #Disable news and interests in the taskbar
                            }
                        }

                        foreach ($settingType in $TaskbarLimitedSettings.Keys) {
                            foreach ($key in $TaskbarLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $TaskbarLimitedSettings[$settingType][$key]
                            }
                        }

                        #User Behavior
                        $UserBehaviorRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"                             = @{
                                "TailoredExperiencesWithDiagnosticDataEnabled" = 0 #Disable diagnostic data from customizing user experiences for whole machine
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                                 = @{
                                "AITEnable" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                            = @{
                                "AllowTelemetry"               = 0 #Disable application telemetry
                                "LimitDiagnosticLogCollection" = 1 #Disable diagnostic log collection
                                "DisableOneSettingsDownloads"  = 1 #Disable downloading of OneSettings configuration settings
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"                     = @{
                                "AITEnable" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"                = @{
                                "AllowTelemetry"               = 0 #Disable application telemetry
                                "LimitDiagnosticLogCollection" = 1 #Disable diagnostic log collection
                                "DisableOneSettingsDownloads"  = 1 #Disable downloading of OneSettings configuration settings
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
                                "AllowTelemetry" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"             = @{
                                "AllowTelemetry" = 0 #Disable application telemetry
                            }
                        }

                        foreach ($settingType in $UserBehaviorRecommendedSettings.Keys) {
                            foreach ($key in $UserBehaviorRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UserBehaviorRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Windows Copilot
                        $CopilotRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"             = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsCopilot" = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                        }

                        foreach ($settingType in $CopilotRecommendedSettings.Keys) {
                            foreach ($key in $CopilotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $CopilotRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Windows Explorer
                        $ExplorerLimitedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\OneDrive" = @{
                                "PreventNetworkTrafficPreUserSignIn" = 1 #Disable OneDrive access to network before login
                            }
                        }

                        foreach ($settingType in $ExplorerLimitedSettings.Keys) {
                            foreach ($key in $ExplorerLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $ExplorerLimitedSettings[$settingType][$key]
                            }
                        }

                        #Windows Update
                        $UpdateRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Speech"                                    = @{
                                "AllowSpeechModelUpdate" = 0 #Disable updates to the speech recognition and speech synthesis modules
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"              = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech"                        = @{
                                "AllowSpeechModelUpdate" = 0 #Disable updates to the speech recognition and speech synthesis modules
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeliveryOptimization"  = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                        }

                        $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                        $userKey = "HKU:\$currentSID"
                        Set-ItemProperty -Path "$userKey\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 #Disable Windows Update via peer-to-peer

                        $UpdateLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"                    = @{
                                "DeferUpgrade"                    = 1 #Activate deferring of upgrades
                                "DeferUpgradePeriod"              = 1 #Activate deferring of upgrades
                                "DeferUpdatePeriod"               = 0 #Activate deferring of upgrades
                                "ExcludeWUDriversInQualityUpdate" = 1 #Disable automatic driver updates through Windows Update
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate"        = @{
                                "DeferUpgrade"                    = 1 #Activate deferring of upgrades
                                "DeferUpgradePeriod"              = 1 #Activate deferring of upgrades
                                "DeferUpdatePeriod"               = 0 #Activate deferring of upgrades
                                "ExcludeWUDriversInQualityUpdate" = 1 #Disable automatic driver updates through Windows Update
                            }
                            "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"               = @{
                                "AllowExperimentation" = 0 #Disable Windows dynamic configuration and update rollouts
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"            = @{
                                "PreventDeviceMetadataFromNetwork" = 1 #Disable automatic downloading manufacturers' apps and icons for devices
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" = @{
                                "AutoDownload" = 2 #Disable automatic app updates through Windows Update
                            }
                        }

                        foreach ($settingType in $UpdateRecommendedSettings.Keys) {
                            foreach ($key in $UpdateRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UpdateRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $UpdateLimitedSettings.Keys) {
                            foreach ($key in $UpdateLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UpdateLimitedSettings[$settingType][$key]
                            }
                        }

                        Write-Host `n"Recommended and somewhat recommended settings were applied for all users." -BackgroundColor Black -ForegroundColor Green
                        Write-Host "For detailed information > " -NoNewline
                        Write-Host "https://github.com/caglaryalcin/StayPrivacy" -ForegroundColor DarkCyan

                    }
                    # All Users - All settings
                    "3" {
                        $ErrorActionPreference = 'SilentlyContinue'
                        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
                        New-PSDrive -PSProvider Registry -Name HKLM -Root HKEY_LOCAL_MACHINE | Out-Null

                        #Activity History and Clipboard
                        $HistoryRecommendedSystemSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"             = @{
                                "EnableActivityFeed"        = 0 #Disable recordings of user activity
                                "PublishUserActivities"     = 0 #Disable storing users' activity history
                                "UploadUserActivities"      = 0 #Disable the submission of user activities to Microsoft
                                "AllowClipboardHistory"     = 0 #Disable storage of clipboard history for whole machine
                                "AllowCrossDeviceClipboard" = 0 #Disable the transfer of the clipboard to other devices via the cloud
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" = @{
                                "EnableActivityFeed"        = 0 #Disable recordings of user activity
                                "PublishUserActivities"     = 0 #Disable storing users' activity history
                                "UploadUserActivities"      = 0 #Disable the submission of user activities to Microsoft
                                "AllowClipboardHistory"     = 0 #Disable storage of clipboard history for whole machine
                                "AllowCrossDeviceClipboard" = 0 #Disable the transfer of the clipboard to other devices via the cloud
                            }
                        }

                        foreach ($settingType in $HistoryRecommendedSystemSettings.Keys) {
                            foreach ($key in $HistoryRecommendedSystemSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Type DWord -Value $HistoryRecommendedSystemSettings[$settingType][$key]
                            }
                        }

                        #App Privacy
                        $AppPrivacyRecommendedSettings = @{
                            "userAccountInformation" = "Deny" # Disable app access to user account information
                            "appDiagnostics"         = "Deny" # Disable app access to diagnostics information
                        }

                        $AppPrivacyLimitedSettings = @{
                            "location"                     = "Deny" # Disable app access to device location
                            "webcam"                       = "Deny" # Disable app access to camera
                            "microphone"                   = "Deny" # Disable app access to microphone
                            "userNotificationListener"     = "Deny" # Disable app access to notifications
                            "activity"                     = "Deny" # Disable app access to motion
                            "contacts"                     = "Deny" # Disable app access to contacts
                            "appointments"                 = "Deny" # Disable app access to calendar
                            "phoneCall"                    = "Deny" # Disable app access to phone calls
                            "phoneCallHistory"             = "Deny" # Disable app access to call history
                            "email"                        = "Deny" # Disable app access to email
                            "userDataTasks"                = "Deny" # Disable app access to tasks
                            "chat"                         = "Deny" # Disable app access to messages
                            "radios"                       = "Deny" # Disable app access to radios
                            "bluetoothSync"                = "Deny" # Disable app access to unpaired devices
                            "documentsLibrary"             = "Deny" # Disable app access to documents
                            "picturesLibrary"              = "Deny" # Disable app access to images
                            "videosLibrary"                = "Deny" # Disable app access to videos
                            "broadFileSystemAccess"        = "Deny" # Disable app access to the file system
                            "cellularData"                 = "Deny" # Disable app access to unpaired devices
                            "gazeInput"                    = "Deny" # Disable app access to eye tracking
                            "graphicsCaptureProgrammatic"  = "Deny" # Disable the ability for apps to take screenshots
                            "graphicsCaptureWithoutBorder" = "Deny" # Disable the ability for desktop apps to take screenshots without borders
                            "musicLibrary"                 = "Deny" # Disable app access to music libraries
                            "downloadsFolder"              = "Deny" # Disable app access to downloads folder
                        }

                        foreach ($setting in $AppPrivacyRecommendedSettings.Keys) {
                            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$setting"
                            Set-ItemProperty -Path $path -Name "Value" -Value $AppPrivacyRecommendedSettings[$setting]
                        }

                        foreach ($setting in $AppPrivacyLimitedSettings.Keys) {
                            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$setting"
                            Set-ItemProperty -Path $path -Name "Value" -Value $AppPrivacyLimitedSettings[$setting]
                        }

                        #Cortana (Personal Assistant)
                        $CortanaRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences"                  = @{
                                "ModelDownloadAllowed" = 0 #Disable download and updates of speech recognition and speech synthesis models
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"               = @{
                                "AllowInputPersonalization" = 0 #Disable online speech recognition
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"             = @{
                                "AllowSearchToUseLocation"  = 0 #Cortana and search are disallowed to use location
                                "DisableWebSearch"          = 1 #Disable web search from Windows Desktop Search
                                "ConnectedSearchUseWeb"     = 0 #Disable display web results in Search
                                "AllowCloudSearch"          = 0 #Disable cloud search
                                "AllowCortanaAboveLock"     = 0 #Disable Cortana above lock screen
                                "EnableDynamicContentInWSB" = 0 #Disable the search highlights in the taskbar
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\InputPersonalization"   = @{
                                "AllowInputPersonalization" = 0 #Disable online speech recognition
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search" = @{
                                "AllowSearchToUseLocation"  = 0 #Cortana and search are disallowed to use location
                                "DisableWebSearch"          = 1 #Disable web search from Windows Desktop Search
                                "ConnectedSearchUseWeb"     = 0 #Disable display web results in Search
                                "AllowCloudSearch"          = 0 #Disable cloud search
                                "AllowCortanaAboveLock"     = 0 #Disable Cortana above lock screen
                                "EnableDynamicContentInWSB" = 0 #Disable the search highlights in the taskbar
                            }

                        }

                        foreach ($settingType in $CortanaRecommendedSettings.Keys) {
                            foreach ($key in $CortanaRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $CortanaRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Location Services
                        $LocationRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"             = @{
                                "DisableLocation"                = 1 #Disable functionality to locate the system
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors" = @{
                                "DisableLocation"                = 1 #Disable functionality to locate the system
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                        }

                        $LocationLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"                                               = @{
                                "DisableSensors" = 1 #Disable sensors for locating the system and its orientation
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors"                                   = @{
                                "DisableSensors" = 1 #Disable sensors for locating the system and its orientation
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration"                                            = @{
                                "Status" = 0 #Disable Windows Geolocation Service
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"                                        = @{
                                "Status" = 0 #Disable Windows Geolocation Service
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" = @{
                                "SensorPermissionState" = 0 #Disable Windows Geolocation Service
                            }
                        }	

                        foreach ($settingType in $LocationRecommendedSettings.Keys) {
                            foreach ($key in $LocationRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $LocationRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $LocationLimitedSettings.Keys) {
                            foreach ($key in $LocationLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $LocationLimitedSettings[$settingType][$key]
                            }
                        }

                        #Microsoft Defender and Microsoft Spynet
                        $DefenderSypnetLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\MRT"                                 = @{
                                "DontReportInfectionInformation" = 1 #Disable reporting of malware infection information
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"             = @{
                                "SpyNetReporting"      = 0 #Disable Microsoft SpyNet membership
                                "SubmitSamplesConsent" = 2 #Disable submitting data samples to Microsoft
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\MRT"                     = @{
                                "DontReportInfectionInformation" = 1 #Disable reporting of malware infection information
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Spynet" = @{
                                "SpyNetReporting"      = 0 #Disable Microsoft SpyNet membership
                                "SubmitSamplesConsent" = 2 #Disable submitting data samples to Microsoft
                            }
                        }

                        foreach ($settingType in $DefenderSypnetLimitedSettings.Keys) {
                            foreach ($key in $DefenderSypnetLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $DefenderSypnetLimitedSettings[$settingType][$key]
                            }
                        }

                        #Microsoft Edge (new version based on Chromium)
                        $EdgeRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Edge"             = @{
                                "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                                "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                                "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                                "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                                "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                                "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                                "AutofillAddressEnabled"                         = 0 #Disable fomr suggestions
                                "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                                "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                                "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                                "WebWidgetAllowed"                               = 0 #Disable Edge bar
                                "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" = @{
                                "ConfigureDoNotTrack"                            = 1 #Disable tracking in the web
                                "PaymentMethodQueryEnabled"                      = 0 #Disable check for saved payment methods by sites
                                "PersonalizationReportingEnabled"                = 0 #Disable personalizing advertising, search, news and other services
                                "AddressBarMicrosoftSearchInBingProviderEnabled" = 0 #Disable automatic completion of web addresses in address bar
                                "UserFeedbackAllowed"                            = 0 #Disable user feedback in toolbar
                                "AutofillCreditCardEnabled"                      = 0 #Disable storing and autocompleting of credit card data on websites
                                "AutofillAddressEnabled"                         = 0 #Disable fomr suggestions
                                "LocalProvidersEnabled"                          = 0 #Disable suggestions from local providers
                                "SearchSuggestEnabled"                           = 0 #Disable search and website suggestions
                                "EdgeShoppingAssistantEnabled"                   = 0 #Disable shopping assistant in Microsoft Edge
                                "WebWidgetAllowed"                               = 0 #Disable Edge bar
                                "HubsSidebarEnabled"                             = 0 #Disable Sidebar in Microsoft Edge
                            }
                        }

                        $EdgeNotRecommendedSettings = @{
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" = @{
                                "SmartScreenEnabled"          = 0 #Disable SmartScreen Filter
                                "TyposquattingCheckerEnabled" = 0 #Disable typosquatting checker for site addresses
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Edge"             = @{
                                "SmartScreenEnabled"          = 0 #Disable SmartScreen Filter
                                "TyposquattingCheckerEnabled" = 0 #Disable typosquatting checker for site addresses
                            }
                        }

                        $EdgeLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Edge"             = @{
                                "ResolveNavigationErrorsUseWebService" = 0 #Disable use of web service to resolve navigation errors
                                "AlternateErrorPagesEnabled"           = 0 #Disable suggestion of similar sites when website cannot be found
                                "NetworkPredictionOptions"             = 2 #Disable preload of pages for faster browsing and searching
                                "PasswordManagerEnabled"               = 0 #Disable saving passwords for websites
                                "SiteSafetyServicesEnabled"            = 0 #Disable site safety services for more information about a visited website
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" = @{
                                "ResolveNavigationErrorsUseWebService" = 0 #Disable use of web service to resolve navigation errors
                                "AlternateErrorPagesEnabled"           = 0 #Disable suggestion of similar sites when website cannot be found
                                "NetworkPredictionOptions"             = 2 #Disable preload of pages for faster browsing and searching
                                "PasswordManagerEnabled"               = 0 #Disable saving passwords for websites
                                "SiteSafetyServicesEnabled"            = 0 #Disable site safety services for more information about a visited website
                            }
                        }

                        foreach ($settingType in $EdgeRecommendedSettings.Keys) {
                            foreach ($key in $EdgeRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $EdgeRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $EdgeLimitedSettings.Keys) {
                            foreach ($key in $EdgeLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $EdgeLimitedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $EdgeNotRecommendedSettings.Keys) {
                            foreach ($key in $EdgeNotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $EdgeNotRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Miscellaneous
                        $MiscellaneousRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"             = @{
                                "DoNotShowFeedbackNotifications" = 1 #Disable feedback reminders
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" = @{
                                "DoNotShowFeedbackNotifications" = 1 #Disable feedback reminders
                            }
                        }

                        $MiscellaneousLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps"                                                       = @{
                                "AutoDownloadAndUpdateMapData"                 = 0 #Disable automatic download and update of map data
                                "AllowUntriggeredNetworkTrafficOnSettingsPage" = 0 #Disable unsolicited network traffic on the offline maps settings page
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"             = @{
                                "NoGenTicket" = 1 #Disable Key Management Service Online Activation
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps"                                           = @{
                                "AutoDownloadAndUpdateMapData"                 = 0 #Disable automatic download and update of map data
                                "AllowUntriggeredNetworkTrafficOnSettingsPage" = 0 #Disable unsolicited network traffic on the offline maps settings page
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" = @{
                                "NoGenTicket" = 1 #Disable Key Management Service Online Activation
                            }
                        }

                        $MiscellaneousNotRecommendedSettings = @{
                            "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" = @{
                                "EnableActiveProbing" = 0 #Disable Network Connectivity Status Indicator
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet"     = @{
                                "EnableActiveProbing" = 0 #Disable Network Connectivity Status Indicator
                            }
                        }

                        foreach ($settingType in $MiscellaneousRecommendedSettings.Keys) {
                            foreach ($key in $MiscellaneousRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $MiscellaneousRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $MiscellaneousLimitedSettings.Keys) {
                            foreach ($key in $MiscellaneousLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $MiscellaneousLimitedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $MiscellaneousNotRecommendedSettings.Keys) {
                            foreach ($key in $MiscellaneousNotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $MiscellaneousNotRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Privacy
                        $PrivacyRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth"               = @{
                                "AllowAdvertising"               = 0 #Disable advertiesements via Bluetooth
                                "DisableWindowsLocationProvider" = 1 #Disable functionality to locate the system
                                "DisableLocationScripting"       = 1 #Disable scripting functionality to locate the system
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"                      = @{
                                "Disabled" = 1 #Disable Windows Error Reporting
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                           = @{
                                "DisableInventory" = 1 #Disable Inventory Collector
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"             = @{
                                "PreventHandwritingErrorReports" = 1 #Disable sharing of handwriting error reports
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"                           = @{
                                "AllowMessageSync" = 0 #Disable backup of text messages into the cloud
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"                     = @{
                                "NoLockScreenCamera" = 1 #Disable camera in logon screen
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"                            = @{
                                "PreventHandwritingDataSharing" = 1 #Disable sharing of handwriting data
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"               = @{
                                "DisableInventory" = 1 #Disable Inventory Collector
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" = @{
                                "PreventHandwritingErrorReports" = 1 #Disable sharing of handwriting error reports
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Messaging"               = @{
                                "AllowMessageSync" = 0 #Disable backup of text messages into the cloud
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization"         = @{
                                "NoLockScreenCamera" = 1 #Disable camera in logon screen
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\TabletPC"                = @{
                                "PreventHandwritingDataSharing" = 1 #Disable sharing of handwriting data
                            }
                            "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows"                                    = @{
                                "CEIPEnable" = 0 #Disable advertisements via Bluetooth
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"               = @{
                                "Enabled" = 0 #Disable advertisements via Bluetooth
                            }
                        }

                        $PrivacyLimitedSettings = @{
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Biometrics" = @{
                                "Enabled" = 0 #Disable biometrical features
                            }
                        }

                        foreach ($settingType in $PrivacyRecommendedSettings.Keys) {
                            foreach ($key in $PrivacyRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $PrivacyRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $PrivacyLimitedSettings.Keys) {
                            foreach ($key in $PrivacyLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $PrivacyLimitedSettings[$settingType][$key]
                            }
                        }

                        #Security
                        $SecurityRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                                 = @{
                                "DisableUAR" = 1 #Disable user steps recorder
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"                                    = @{
                                "DisablePasswordReveal" = 1 #Disable password reveal button
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"                     = @{
                                "DisableUAR" = 1 #Disable user steps recorder
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI"                        = @{
                                "DisablePasswordReveal" = 1 #Disable password reveal button
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack"                                   = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice"                            = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" = @{
                                "Start" = 0 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice"                                = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack"                                       = @{
                                "Start" = 4 #Disable temeletry
                            }
                            "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"     = @{
                                "Start" = 0 #Disable temeletry
                            }
                        
                        }

                        $SecurityLimitedSettings = @{
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\WMDRM" = @{
                                "DisableOnline" = 1 #Disable Internet access of Windows Media Digital Rights Management (DRM)
	
                            }
                        }

                        foreach ($settingType in $SecurityRecommendedSettings.Keys) {
                            foreach ($key in $SecurityRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $SecurityRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $SecurityLimitedSettings.Keys) {
                            foreach ($key in $SecurityLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $SecurityLimitedSettings[$settingType][$key]
                            }
                        }

                        #Taskbar
                        $TaskbarLimitedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"             = @{
                                "HideSCAMeetNow" = 1 #Disable "Meet now" in the taskbar
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"                       = @{
                                "EnableFeeds" = 0 #Disable news and interests in the taskbar
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
                                "HideSCAMeetNow" = 1 #Disable "Meet now" in the taskbar
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Feeds"           = @{
                                "EnableFeeds" = 0 #Disable news and interests in the taskbar
                            }
                        }

                        foreach ($settingType in $TaskbarLimitedSettings.Keys) {
                            foreach ($key in $TaskbarLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $TaskbarLimitedSettings[$settingType][$key]
                            }
                        }

                        #User Behavior
                        $UserBehaviorRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"                             = @{
                                "TailoredExperiencesWithDiagnosticDataEnabled" = 0 #Disable diagnostic data from customizing user experiences for whole machine
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"                                 = @{
                                "AITEnable" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"                            = @{
                                "AllowTelemetry"               = 0 #Disable application telemetry
                                "LimitDiagnosticLogCollection" = 1 #Disable diagnostic log collection
                                "DisableOneSettingsDownloads"  = 1 #Disable downloading of OneSettings configuration settings
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat"                     = @{
                                "AITEnable" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection"                = @{
                                "AllowTelemetry"               = 0 #Disable application telemetry
                                "LimitDiagnosticLogCollection" = 1 #Disable diagnostic log collection
                                "DisableOneSettingsDownloads"  = 1 #Disable downloading of OneSettings configuration settings
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
                                "AllowTelemetry" = 0 #Disable application telemetry
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"             = @{
                                "AllowTelemetry" = 0 #Disable application telemetry
                            }
                        }

                        foreach ($settingType in $UserBehaviorRecommendedSettings.Keys) {
                            foreach ($key in $UserBehaviorRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UserBehaviorRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Windows Copilot
                        $CopilotRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"             = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsCopilot" = @{
                                "TurnOffWindowsCopilot" = 1 #Disable the Windows Copilot
                            }
                        }

                        foreach ($settingType in $CopilotRecommendedSettings.Keys) {
                            foreach ($key in $CopilotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $CopilotRecommendedSettings[$settingType][$key]
                            }
                        }

                        #Windows Explorer
                        $ExplorerNotRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"             = @{
                                "DisableFileSyncNGSC" = 1 #Disable Microsoft OneDrive
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" = @{
                                "DisableFileSyncNGSC" = 1 #Disable Microsoft OneDrive
                            }
                        }

                        $ExplorerLimitedSettings = @{
                            "HKLM:\SOFTWARE\Microsoft\OneDrive" = @{
                                "PreventNetworkTrafficPreUserSignIn" = 1 #Disable OneDrive access to network before login
                            }
                        }

                        foreach ($settingType in $ExplorerNotRecommendedSettings.Keys) {
                            foreach ($key in $ExplorerNotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $ExplorerNotRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $ExplorerLimitedSettings.Keys) {
                            foreach ($key in $ExplorerLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $ExplorerLimitedSettings[$settingType][$key]
                            }
                        }

                        #Windows Update
                        $UpdateRecommendedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Speech"                                    = @{
                                "AllowSpeechModelUpdate" = 0 #Disable updates to the speech recognition and speech synthesis modules
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"              = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Speech"                        = @{
                                "AllowSpeechModelUpdate" = 0 #Disable updates to the speech recognition and speech synthesis modules
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeliveryOptimization"  = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" = @{
                                "DODownloadMode" = 0 #Disable Windows Update via peer-to-peer
                            }
                        }

                        $UpdateLimitedSettings = @{
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"                    = @{
                                "DeferUpgrade"                    = 1 #Activate deferring of upgrades
                                "DeferUpgradePeriod"              = 1 #Activate deferring of upgrades
                                "DeferUpdatePeriod"               = 0 #Activate deferring of upgrades
                                "ExcludeWUDriversInQualityUpdate" = 1 #Disable automatic driver updates through Windows Update
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate"        = @{
                                "DeferUpgrade"                    = 1 #Activate deferring of upgrades
                                "DeferUpgradePeriod"              = 1 #Activate deferring of upgrades
                                "DeferUpdatePeriod"               = 0 #Activate deferring of upgrades
                                "ExcludeWUDriversInQualityUpdate" = 1 #Disable automatic driver updates through Windows Update
                            }
                            "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"               = @{
                                "AllowExperimentation" = 0 #Disable Windows dynamic configuration and update rollouts
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"            = @{
                                "PreventDeviceMetadataFromNetwork" = 1 #Disable automatic downloading manufacturers' apps and icons for devices
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" = @{
                                "AutoDownload" = 2 #Disable automatic app updates through Windows Update
                            }
                        }

                        $UpdateNotRecommendedSettings = @{
                            "HKLM:\SYSTEM\ControlSet001\Services\wuauserv"                                                                = @{
                                "Start" = 4 #Disable automatic Windows Updates
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv"                                                            = @{
                                "Start" = 4 #Disable automatic Windows Updates
                            }
                            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"                                                  = @{
                                "NoAutoUpdate" = 1 #Disable automatic Windows Updates
                            }
                            "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"                                      = @{
                                "NoAutoUpdate" = 1 #Disable automatic Windows Updates
                            }
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" = @{
                                "RegisteredWithAU" = 0 #Disable Windows Updates for other products (e.g. Microsoft Office)
                            }
                        }

                        $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                        $userKey = "HKU:\$currentSID"
                        Set-ItemProperty -Path "$userKey\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 #Disable Windows Update via peer-to-peer

                        foreach ($settingType in $UpdateRecommendedSettings.Keys) {
                            foreach ($key in $UpdateRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UpdateRecommendedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $UpdateLimitedSettings.Keys) {
                            foreach ($key in $UpdateLimitedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UpdateLimitedSettings[$settingType][$key]
                            }
                        }

                        foreach ($settingType in $UpdateNotRecommendedSettings.Keys) {
                            foreach ($key in $UpdateNotRecommendedSettings[$settingType].Keys) {
                                Set-ItemProperty -Path $settingType -Name $key -Value $UpdateNotRecommendedSettings[$settingType][$key]
                            }
                        }

                        Write-Host `n"All settings have been applied for the all user." -BackgroundColor Black -ForegroundColor Green
                        Write-Host "For detailed information > " -NoNewline
                        Write-Host "https://github.com/caglaryalcin/StayPrivacy" -ForegroundColor DarkCyan
                    }

                    default {
                        Write-Host "Invalid input. Please enter 1, 2 or 3."
                        $validChoice = $false
                    }
                }
            } while (-not $validChoice)
        }
        default {
            Write-Host "Invalid input. Please enter 1 or 2."
            $validChoice = $false
        }
    }
} while (-not $validChoice)