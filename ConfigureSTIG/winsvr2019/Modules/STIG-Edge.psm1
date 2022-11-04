Function Set-EdgeSTIG {
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\" -Name "Edge" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ExtensionInstallBlocklist" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ExtensionInstallWhitelist" -Force
    New-Item -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ExtensionInstallAllowlist" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "InPrivateModeAvailability" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "DefaultPopupsSetting" -PropertyType "DWORD" -Value 2 -Force
    # [string]$1val=[{"allow_search_engine_discovery": false},{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}]
    # New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ManagedSearchEngines" -PropertyType "String" -Value $1val -Force
    # reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ManagedSearchEngines" /t MULTI_SZ /d {"allow_search_engine_discovery": false}\0{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}] /f
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "NetworkPredictionOptions" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "SearchSuggestEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportAutofillFormData" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportBrowserSettings" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportCookies" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportExtensions" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportHistory" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportHomepage" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportOpenTabs" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportPaymentInfo" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportSavedPasswords" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportSearchEngine" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ImportShortcuts" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "AutoplayAllowed" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "DefaultWebUsbGuardSetting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "EnableMediaRouter" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "DefaultWebBluetoothGuardSetting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "AutofillAddressEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "EnableOnlineRevocationChecks" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "DefaultGeolocationSetting" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "AllowDeletingBrowserHistory" -PropertyType "DWORD" -Value 0 -Force
    #New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "DeveloperToolsAvailability" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "DownloadRestrictions" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist" -Name "1" -PropertyType "String" -Value "*" -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallWhitelist" -Name "1" -PropertyType "String" -Value "dnboadgmjeggdengfhphcmlclboenlco" -Force
    New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist" -Name "1" -PropertyType "String" -Value "dnboadgmjeggdengfhphcmlclboenlco" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "PasswordManagerEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "SSLVersionMin" -PropertyType "String" -Value "tls1.2" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "SitePerProcess" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "AuthSchemes" -PropertyType "String" -Value "ntlm,negotiate" -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "PromptForDownloadLocation" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "TrackingPrevention" -PropertyType "DWORD" -Value 3 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "PaymentMethodQueryEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "AlternateErrorPagesEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "UserFeedbackAllowed" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "EdgeCollectionsEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "ConfigureShare" -PropertyType "DWORD" -Value 1 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "BrowserGuestModeEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "RelaunchNotification" -PropertyType "DWORD" -Value 2 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "BuiltInDnsClientEnabled" -PropertyType "DWORD" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Edge" -Name "QuicAllowed" -PropertyType "DWORD" -Value 0 -Force   
}
